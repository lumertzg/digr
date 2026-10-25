use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::num::{NonZeroU16, NonZeroUsize};
use std::time::{Duration, Instant};

use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
};
use hickory_resolver::net::NetError;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::tcp::TcpClientStream;
use hickory_resolver::net::udp::UdpClientStream;
use hickory_resolver::net::xfer::{DnsHandle, FirstAnswer};
use hickory_resolver::proto::op::{
    DnsRequest, DnsRequestOptions, DnsResponse, Edns, OpCode, Query as DnsQuery, ResponseCode,
};
use hickory_resolver::proto::rr::rdata::opt::{ClientSubnet, EdnsOption};
use hickory_resolver::proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};

/// A single DNS lookup using an explicit server or the system nameservers.
pub struct Query {
    pub name: Name,
    pub record_type: RecordType,
    pub server: Option<String>,
    pub port: NonZeroU16,
    pub tcp: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub source: Option<IpAddr>,
    pub subnet: Option<ClientSubnet>,
    pub recursion: bool,
    pub timeout: Duration,
    /// Total attempts, including the initial request.
    pub tries: NonZeroUsize,
}

pub struct Response {
    pub server: SocketAddr,
    pub tcp: bool,
    pub elapsed: Duration,
    pub message: DnsResponse,
}

impl Query {
    /// Requires an empty response vector. Received responses remain available on failure.
    pub async fn lookup(mut self, responses: &mut Vec<Response>) -> Result<(), NetError> {
        let servers = match self.server.as_deref() {
            Some(server) => self.nameserver_addrs(server).await?,
            None => system_nameservers()?
                .into_iter()
                .map(|mut server| {
                    server.set_port(self.port.get());
                    server
                })
                .collect(),
        };
        self.name.set_fqdn(true);

        for _ in 0..16 {
            let response = self.send(&servers).await?;
            let next = self.cname_target(&response.message);
            responses.push(response);

            let Some(name) = next? else {
                return Ok(());
            };
            if responses
                .iter()
                .any(|response| response.message.queries[0].name() == &name)
            {
                return Err("CNAME loop detected".into());
            }

            self.name = name;
        }

        Err("CNAME query limit exceeded".into())
    }

    async fn send(&self, servers: &[SocketAddr]) -> Result<Response, NetError> {
        let mut last_error = NetError::from("no nameservers match the requested transport family");
        let mut failure = None;

        for &server in servers {
            if !self.supports_family(server.ip()) {
                continue;
            }

            match self.request(server).await {
                Ok(response) => {
                    if matches!(
                        response.message.metadata.response_code,
                        ResponseCode::ServFail | ResponseCode::Refused
                    ) {
                        failure = Some(response);
                        continue;
                    }

                    return Ok(response);
                }
                Err(error) => last_error = error,
            }
        }

        failure.ok_or(last_error)
    }

    /// None means the requested RRset was found. Some names the next CNAME target.
    pub(crate) fn cname_target(&self, message: &DnsResponse) -> Result<Option<Name>, NetError> {
        if message.metadata.response_code != ResponseCode::NoError {
            return Err(format!("query returned {}", message.metadata.response_code).into());
        }

        let mut name = &self.name;

        for _ in 0..=message.answers.len() {
            let mut target = None;

            for record in &message.answers {
                if record.dns_class != DNSClass::IN || record.name != *name {
                    continue;
                }
                if self.record_type.is_any() || record.record_type() == self.record_type {
                    return Ok(None);
                }
                if let RData::CNAME(cname) = &record.data {
                    target = Some(&cname.0);
                }
            }

            match target {
                Some(target) => name = target,
                None if name != &self.name => return Ok(Some(name.clone())),
                None => return Err("no records found for this query".into()),
            }
        }

        Err("CNAME loop detected".into())
    }

    pub(crate) async fn request(&self, server: SocketAddr) -> Result<Response, NetError> {
        let start = Instant::now();

        if !self.tcp {
            let message = self.retry(server, false).await?;
            if !message.metadata.truncation {
                return Ok(Response {
                    server,
                    tcp: false,
                    elapsed: start.elapsed(),
                    message,
                });
            }
        }

        let message = self.retry(server, true).await?;
        if message.metadata.truncation {
            return Err(NetError::Truncated);
        }

        Ok(Response {
            server,
            tcp: true,
            elapsed: start.elapsed(),
            message,
        })
    }

    async fn retry(&self, server: SocketAddr, tcp: bool) -> Result<DnsResponse, NetError> {
        let mut last_error = NetError::NoConnections;

        for _ in 0..self.tries.get() {
            match self.exchange(server, tcp).await {
                Ok(response) => return Ok(response),
                Err(error) => last_error = error,
            }
        }

        Err(format!("{server}: {last_error}").into())
    }

    async fn exchange(&self, server: SocketAddr, tcp: bool) -> Result<DnsResponse, NetError> {
        // Keep the provider alive while its TCP background task handles the response.
        let provider = TokioRuntimeProvider::default();
        let source = self.source.map(|ip| SocketAddr::new(ip, 0));
        let exchange = if tcp {
            TcpClientStream::exchange(server, source, self.timeout, None, provider.clone()).await?
        } else {
            UdpClientStream::builder(server, provider)
                .with_timeout(Some(self.timeout))
                .with_bind_addr(source)
                .with_max_retries(0)
                .exchange()
        };
        let question = DnsQuery::query(self.name.clone(), self.record_type);
        let mut options = DnsRequestOptions::default();
        options.recursion_desired = self.recursion;
        let mut request = DnsRequest::from_query(question.clone(), options);
        if let Some(subnet) = self.subnet {
            request
                .edns
                .get_or_insert_with(Edns::new)
                .options_mut()
                .insert(EdnsOption::Subnet(subnet));
        }

        let response = exchange.send(request).first_answer().await?;

        if response.metadata.op_code != OpCode::Query {
            return Err("response opcode does not match the query".into());
        }

        if response.queries.as_slice() != std::slice::from_ref(&question) {
            return Err("response question does not match the query".into());
        }

        Ok(response)
    }

    pub(crate) async fn nameserver_addrs(&self, server: &str) -> Result<Vec<SocketAddr>, NetError> {
        if let Some(addr) = parse_ip(server, self.port.get())? {
            return Ok(vec![addr]);
        }

        // Bootstrap through the system nameservers, not the unresolved server.
        let result: Result<Vec<SocketAddr>, NetError> = async {
            let resolver = self.resolver(system_nameservers()?)?;
            let mut name: Name = server.parse()?;
            name.set_fqdn(true);

            Ok(resolver
                .lookup_ip(name)
                .await?
                .iter()
                .map(|ip| SocketAddr::new(ip, self.port.get()))
                .collect())
        }
        .await;

        result.map_err(|error| format!("resolving nameserver {server}: {error}").into())
    }

    pub(crate) fn supports_family(&self, ip: IpAddr) -> bool {
        (!self.ipv4 || ip.is_ipv4())
            && (!self.ipv6 || ip.is_ipv6())
            && self
                .source
                .is_none_or(|source| source.is_ipv4() == ip.is_ipv4())
    }

    fn resolver(&self, servers: Vec<SocketAddr>) -> Result<TokioResolver, NetError> {
        let ipv4 = self.ipv4 || self.source.is_some_and(|ip| ip.is_ipv4());
        let ipv6 = self.ipv6 || self.source.is_some_and(|ip| ip.is_ipv6());
        // hickory's resolver takes bare IPs, which cannot carry an IPv6 scope.
        let name_servers = servers
            .into_iter()
            .filter(|server| !is_scoped(server) && self.supports_family(server.ip()))
            .map(|server| NameServerConfig::udp_and_tcp(server.ip()))
            .collect();
        let mut config = ResolverConfig::from_parts(None, vec![], name_servers);

        if config.name_servers.is_empty() {
            return Err("no nameservers match the requested transport family".into());
        }

        for server in &mut config.name_servers {
            if self.tcp {
                server.connections = vec![ConnectionConfig::tcp()];
            }

            for connection in &mut server.connections {
                connection.port = 53;
                connection.bind_addr = self.source.map(|ip| SocketAddr::new(ip, 0));
            }
        }

        let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
        let options = builder.options_mut();
        options.timeout = self.timeout;
        options.attempts = self.tries.get() - 1;
        options.recursion_desired = true;
        options.ip_strategy = match (ipv4, ipv6) {
            (true, _) => LookupIpStrategy::Ipv4Only,
            (_, true) => LookupIpStrategy::Ipv6Only,
            _ => LookupIpStrategy::Ipv4AndIpv6,
        };
        options.preserve_intermediates = false;
        options.use_hosts_file = ResolveHosts::Never;

        builder.build()
    }
}

/// Parses an IP address with an optional IPv6 zone, such as `fe80::1%en0`.
/// Returns None when the input is not an IP address.
pub(crate) fn parse_ip(server: &str, port: u16) -> Result<Option<SocketAddr>, NetError> {
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Ok(Some(SocketAddr::new(ip, port)));
    }

    let Some((ip, zone)) = server.split_once('%') else {
        return Ok(None);
    };
    let Ok(ip) = ip.parse::<Ipv6Addr>() else {
        return Ok(None);
    };

    Ok(Some(SocketAddrV6::new(ip, port, 0, scope_id(zone)?).into()))
}

fn scope_id(zone: &str) -> Result<u32, NetError> {
    if let Ok(index) = zone.parse() {
        return Ok(index);
    }

    #[cfg(unix)]
    if let Ok(name) = std::ffi::CString::new(zone) {
        // SAFETY: name is a NUL-terminated string that outlives the call.
        let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
        if index != 0 {
            return Ok(index);
        }
    }

    Err(format!("unknown network interface {zone}").into())
}

fn is_scoped(server: &SocketAddr) -> bool {
    matches!(server, SocketAddr::V6(server) if server.scope_id() != 0)
}

/// Reads resolv.conf directly because hickory's macOS reader rejects scoped IPv6
/// servers such as `fe80::1%en0`, and its unix reader drops their zone.
#[cfg(all(unix, not(target_os = "android")))]
fn system_nameservers() -> Result<Vec<SocketAddr>, NetError> {
    use resolv_conf::ScopedIp;

    const PATH: &str = "/etc/resolv.conf";
    let data = std::fs::read(PATH).map_err(|error| format!("reading {PATH}: {error}"))?;
    let (config, _) = resolv_conf::Config::parse_with_errors(&data);

    // Skip servers on unknown interfaces rather than failing the whole configuration.
    let servers: Vec<_> = config
        .nameservers
        .into_iter()
        .filter_map(|server| match server {
            ScopedIp::V6(ip, Some(zone)) => scope_id(&zone)
                .ok()
                .map(|scope| SocketAddrV6::new(ip, 53, 0, scope).into()),
            ip => Some(SocketAddr::new(IpAddr::from(ip), 53)),
        })
        .collect();

    if servers.is_empty() {
        return Err(format!("no usable nameservers found in {PATH}").into());
    }

    Ok(servers)
}

#[cfg(not(all(unix, not(target_os = "android"))))]
fn system_nameservers() -> Result<Vec<SocketAddr>, NetError> {
    Ok(hickory_resolver::system_conf::read_system_conf()?
        .0
        .name_servers
        .iter()
        .map(|server| SocketAddr::new(server.ip, 53))
        .collect())
}
