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

/// An absolute IN-class question with a queryable record type.
#[derive(Clone)]
pub struct Question {
    name: Name,
    record_type: RecordType,
}

#[derive(Clone, Copy)]
pub enum AddressFamily {
    Any,
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub fn supports(self, ip: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Ipv4 => ip.is_ipv4(),
            Self::Ipv6 => ip.is_ipv6(),
        }
    }
}

pub struct RequestSettings {
    pub port: NonZeroU16,
    pub tcp: bool,
    pub family: AddressFamily,
    pub source: Option<IpAddr>,
    pub subnet: Option<ClientSubnet>,
    pub recursion: bool,
    pub dnssec: bool,
    pub checking_disabled: bool,
    pub timeout: Duration,
    /// Total attempts, including the initial request.
    pub tries: NonZeroUsize,
}

/// A complete DNS exchange with exactly one question matching the request.
/// Only the DNS transport constructs responses. Consumers cannot mutate the validated message.
pub struct Response {
    pub server: SocketAddr,
    pub tcp: bool,
    pub elapsed: Duration,
    message: DnsResponse,
}

/// An untrusted, server-reported Extended DNS Error (RFC 8914).
pub struct ExtendedError<'a> {
    pub code: Option<u16>,
    pub name: Option<&'static str>,
    pub text: Option<&'a str>,
    pub wire: &'a [u8],
}

impl Response {
    pub fn message(&self) -> &DnsResponse {
        &self.message
    }

    pub fn question(&self) -> &DnsQuery {
        &self.message.queries[0]
    }

    pub fn extended_errors(&self) -> impl Iterator<Item = ExtendedError<'_>> {
        self.message
            .edns
            .iter()
            .flat_map(|edns| &edns.options().options)
            .filter_map(|(_, option)| {
                let EdnsOption::Unknown(15, wire) = option else {
                    return None;
                };
                let code = wire.first_chunk::<2>().copied().map(u16::from_be_bytes);
                let name = match code {
                    Some(0) => Some("Other"),
                    Some(1) => Some("Unsupported DNSKEY Algorithm"),
                    Some(2) => Some("Unsupported DS Digest Type"),
                    Some(3) => Some("Stale Answer"),
                    Some(4) => Some("Forged Answer"),
                    Some(5) => Some("DNSSEC Indeterminate"),
                    Some(6) => Some("DNSSEC Bogus"),
                    Some(7) => Some("Signature Expired"),
                    Some(8) => Some("Signature Not Yet Valid"),
                    Some(9) => Some("DNSKEY Missing"),
                    Some(10) => Some("RRSIGs Missing"),
                    Some(11) => Some("No Zone Key Bit Set"),
                    Some(12) => Some("NSEC Missing"),
                    Some(13) => Some("Cached Error"),
                    Some(14) => Some("Not Ready"),
                    Some(15) => Some("Blocked"),
                    Some(16) => Some("Censored"),
                    Some(17) => Some("Filtered"),
                    Some(18) => Some("Prohibited"),
                    Some(19) => Some("Stale NXDOMAIN Answer"),
                    Some(20) => Some("Not Authoritative"),
                    Some(21) => Some("Not Supported"),
                    Some(22) => Some("No Reachable Authority"),
                    Some(23) => Some("Network Error"),
                    Some(24) => Some("Invalid Data"),
                    _ => None,
                };

                Some(ExtendedError {
                    code,
                    name,
                    text: wire
                        .get(2..)
                        .and_then(|text| std::str::from_utf8(text).ok()),
                    wire,
                })
            })
    }
}

/// A nameserver address. A nonzero scope selects the interface of a link-local IPv6 server.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nameserver {
    ip: IpAddr,
    scope: u32,
}

impl Nameserver {
    /// Parses an IP address with an optional IPv6 zone, such as `fe80::1%en0`.
    /// Returns None when the input is not an IP address.
    pub fn parse(value: &str) -> Result<Option<Self>, NetError> {
        if let Ok(ip) = value.parse::<IpAddr>() {
            return Ok(Some(ip.into()));
        }

        let Some((ip, zone)) = value.split_once('%') else {
            return Ok(None);
        };
        let Ok(ip) = ip.parse::<Ipv6Addr>() else {
            return Ok(None);
        };

        Ok(Some(Self {
            ip: ip.into(),
            scope: scope_id(zone)?,
        }))
    }

    pub fn ip(self) -> IpAddr {
        self.ip
    }

    pub fn socket_addr(self, port: u16) -> SocketAddr {
        match self.ip {
            IpAddr::V6(ip) => SocketAddrV6::new(ip, port, 0, self.scope).into(),
            ip => SocketAddr::new(ip, port),
        }
    }
}

impl From<IpAddr> for Nameserver {
    fn from(ip: IpAddr) -> Self {
        Self { ip, scope: 0 }
    }
}

/// How a NOERROR response answers the query.
pub enum Answer {
    /// The requested RRset exists.
    Found,
    /// The name exists without records of the requested type.
    NoData,
    /// The response ends a CNAME chain at this name without its records.
    Cname(Name),
}

impl Question {
    pub fn new(mut name: Name, record_type: RecordType) -> Self {
        assert!(
            !matches!(record_type, RecordType::OPT | RecordType::ZERO),
            "question requires a queryable record type"
        );
        name.set_fqdn(true);

        Self { name, record_type }
    }

    pub fn name(&self) -> &Name {
        &self.name
    }

    pub fn record_type(&self) -> RecordType {
        self.record_type
    }

    pub(crate) fn answer(&self, message: &DnsResponse) -> Result<Answer, NetError> {
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
                    return Ok(Answer::Found);
                }
                if let RData::CNAME(cname) = &record.data {
                    target = Some(&cname.0);
                }
            }

            match target {
                Some(target) => name = target,
                None if name != &self.name => return Ok(Answer::Cname(name.clone())),
                None if is_referral(message) => {
                    return Err("response is a referral, not an answer".into());
                }
                None if message.answers.is_empty() => return Ok(Answer::NoData),
                None => return Err("response answers do not match the query".into()),
            }
        }

        Err("CNAME loop detected".into())
    }
}

/// Received responses remain available on failure. The output vector must start empty.
pub async fn lookup(
    mut question: Question,
    settings: &RequestSettings,
    server: Option<&str>,
    responses: &mut Vec<Response>,
) -> Result<(), NetError> {
    assert!(responses.is_empty(), "lookup responses must start empty");

    let servers = match server {
        Some(server) => settings.nameservers(server).await?,
        None => system_nameservers()?,
    };

    for _ in 0..16 {
        let response = settings.send(&question, &servers).await?;
        let answer = question.answer(&response.message);
        responses.push(response);

        let name = match answer? {
            Answer::Found | Answer::NoData => return Ok(()),
            Answer::Cname(name) => name,
        };
        if responses
            .iter()
            .any(|response| response.question().name() == &name)
        {
            return Err("CNAME loop detected".into());
        }

        question.name = name;
    }

    Err("CNAME query limit exceeded".into())
}

impl RequestSettings {
    async fn send(
        &self,
        question: &Question,
        servers: &[Nameserver],
    ) -> Result<Response, NetError> {
        let mut last_error = NetError::from("no nameservers match the requested transport family");
        let mut failure = None;

        for &server in servers {
            if !self.supports_family(server.ip) {
                continue;
            }

            match self
                .request(question, server.socket_addr(self.port.get()))
                .await
            {
                Ok(response) if is_server_failure(&response.message) => failure = Some(response),
                Ok(response) => return Ok(response),
                Err(error) => last_error = error,
            }
        }

        failure.ok_or(last_error)
    }

    pub(crate) async fn request(
        &self,
        question: &Question,
        server: SocketAddr,
    ) -> Result<Response, NetError> {
        if !self.tcp {
            let (message, elapsed) = self.retry(question, server, false).await?;
            if !message.metadata.truncation {
                return Ok(Response {
                    server,
                    tcp: false,
                    elapsed,
                    message,
                });
            }
        }

        let (message, elapsed) = self.retry(question, server, true).await?;
        if message.metadata.truncation {
            return Err(format!("{server}: truncated response over TCP").into());
        }

        Ok(Response {
            server,
            tcp: true,
            elapsed,
            message,
        })
    }

    /// The elapsed time covers only the exchange that succeeded.
    async fn retry(
        &self,
        question: &Question,
        server: SocketAddr,
        tcp: bool,
    ) -> Result<(DnsResponse, Duration), NetError> {
        let mut last_error = NetError::NoConnections;

        for _ in 0..self.tries.get() {
            let start = Instant::now();
            match self.exchange(question, server, tcp).await {
                Ok(response) => return Ok((response, start.elapsed())),
                Err(error) => last_error = error,
            }
        }

        Err(format!("{server}: {last_error}").into())
    }

    async fn exchange(
        &self,
        question: &Question,
        server: SocketAddr,
        tcp: bool,
    ) -> Result<DnsResponse, NetError> {
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
        let question = DnsQuery::query(question.name.clone(), question.record_type);
        let mut options = DnsRequestOptions::default();
        options.recursion_desired = self.recursion;
        options.edns_set_dnssec_ok = self.dnssec;
        let mut request = DnsRequest::from_query(question.clone(), options);
        request.metadata.checking_disabled = self.checking_disabled;
        if let Some(subnet) = self.subnet {
            request
                .edns
                .get_or_insert_with(Edns::new)
                .options_mut()
                .insert(EdnsOption::Subnet(subnet));
        }

        let mut response = exchange.send(request).first_answer().await?;

        if response.metadata.op_code != OpCode::Query {
            return Err("response opcode does not match the query".into());
        }

        if response.queries.as_slice() != std::slice::from_ref(&question) {
            return Err("response question does not match the query".into());
        }

        // Hickory separates TSIG when DNSSEC support is enabled. Keep it visible without verifying it.
        if let Some(signature) = response.signature.take() {
            response
                .additionals
                .push((*signature).into_record_of_rdata());
        }

        Ok(response)
    }

    async fn nameservers(&self, server: &str) -> Result<Vec<Nameserver>, NetError> {
        if let Some(server) = Nameserver::parse(server)? {
            return Ok(vec![server]);
        }

        self.resolve_host(&server.parse()?).await
    }

    /// Resolves a nameserver hostname through the system nameservers, not the unresolved server.
    pub(crate) async fn resolve_host(&self, host: &Name) -> Result<Vec<Nameserver>, NetError> {
        let result: Result<Vec<Nameserver>, NetError> = async {
            let resolver = self.resolver(system_nameservers()?)?;
            let mut name = host.clone();
            name.set_fqdn(true);

            Ok(resolver
                .lookup_ip(name)
                .await?
                .iter()
                .map(Nameserver::from)
                .collect())
        }
        .await;

        result.map_err(|error| format!("resolving nameserver {}: {error}", host.to_ascii()).into())
    }

    fn resolver(&self, servers: Vec<Nameserver>) -> Result<TokioResolver, NetError> {
        let family = match self.source {
            Some(IpAddr::V4(_)) => AddressFamily::Ipv4,
            Some(IpAddr::V6(_)) => AddressFamily::Ipv6,
            None => self.family,
        };
        let servers: Vec<_> = servers
            .into_iter()
            .filter(|server| self.supports_family(server.ip))
            .collect();

        if servers.is_empty() {
            return Err("no nameservers match the requested transport family".into());
        }

        // hickory's resolver takes bare IPs, which cannot carry an IPv6 scope.
        let mut name_servers: Vec<_> = servers
            .iter()
            .filter(|server| server.scope == 0)
            .map(|server| NameServerConfig::udp_and_tcp(server.ip))
            .collect();

        if name_servers.is_empty() {
            return Err("link-local system nameservers cannot resolve nameserver hostnames".into());
        }

        for server in &mut name_servers {
            if self.tcp {
                server.connections = vec![ConnectionConfig::tcp()];
            }

            for connection in &mut server.connections {
                connection.bind_addr = self.source.map(|ip| SocketAddr::new(ip, 0));
            }
        }

        let config = ResolverConfig::from_parts(None, vec![], name_servers);
        let mut builder = Resolver::builder_with_config(config, TokioRuntimeProvider::default());
        let options = builder.options_mut();
        options.timeout = self.timeout;
        options.attempts = self.tries.get() - 1;
        options.recursion_desired = true;
        options.ip_strategy = match family {
            AddressFamily::Ipv4 => LookupIpStrategy::Ipv4Only,
            AddressFamily::Ipv6 => LookupIpStrategy::Ipv6Only,
            AddressFamily::Any => LookupIpStrategy::Ipv4AndIpv6,
        };
        options.preserve_intermediates = false;
        options.use_hosts_file = ResolveHosts::Never;

        builder.build()
    }

    pub(crate) fn supports_family(&self, ip: IpAddr) -> bool {
        self.family.supports(ip)
            && self
                .source
                .is_none_or(|source| source.is_ipv4() == ip.is_ipv4())
    }
}

/// SERVFAIL and REFUSED come from one server's state, so another server may still answer.
pub(crate) fn is_server_failure(message: &DnsResponse) -> bool {
    matches!(
        message.metadata.response_code,
        ResponseCode::ServFail | ResponseCode::Refused
    )
}

/// An empty, non-authoritative response with NS records and no SOA delegates the name instead
/// of answering it. Other empty NOERROR responses are NODATA (RFC 2308 section 2.2).
fn is_referral(message: &DnsResponse) -> bool {
    let has = |matches: fn(&RData) -> bool| {
        message
            .authorities
            .iter()
            .any(|record| matches(&record.data))
    };

    message.answers.is_empty()
        && !message.metadata.authoritative
        && !has(|data| matches!(data, RData::SOA(_)))
        && has(|data| matches!(data, RData::NS(_)))
}

#[cfg(unix)]
fn scope_id(zone: &str) -> Result<u32, NetError> {
    let index = match zone.parse::<u32>() {
        Ok(index) => index,
        Err(_) => match std::ffi::CString::new(zone) {
            // SAFETY: name is a NUL-terminated string that outlives the call.
            Ok(name) => unsafe { libc::if_nametoindex(name.as_ptr()) },
            Err(_) => 0,
        },
    };

    if index == 0 {
        return Err(format!("unknown network interface {zone:?}").into());
    }

    Ok(index)
}

#[cfg(not(unix))]
fn scope_id(zone: &str) -> Result<u32, NetError> {
    zone.parse()
        .map_err(|_| format!("network interface {zone:?} must be a numeric index").into())
}

/// Reads resolv.conf directly because hickory's macOS reader rejects scoped IPv6
/// servers such as `fe80::1%en0`, and its unix reader drops their zone.
#[cfg(all(unix, not(target_os = "android")))]
fn system_nameservers() -> Result<Vec<Nameserver>, NetError> {
    use resolv_conf::ScopedIp;

    const PATH: &str = "/etc/resolv.conf";
    let data = std::fs::read(PATH).map_err(|error| format!("reading {PATH}: {error}"))?;
    let (config, _) = resolv_conf::Config::parse_with_errors(&data);

    // Skip servers on unknown interfaces rather than failing the whole configuration.
    let servers: Vec<_> = config
        .nameservers
        .into_iter()
        .filter_map(|server| match server {
            ScopedIp::V6(ip, Some(zone)) => scope_id(&zone).ok().map(|scope| Nameserver {
                ip: ip.into(),
                scope,
            }),
            ip => Some(IpAddr::from(ip).into()),
        })
        .collect();

    if servers.is_empty() {
        return Err(format!("no usable nameservers found in {PATH}").into());
    }

    Ok(servers)
}

#[cfg(not(all(unix, not(target_os = "android"))))]
fn system_nameservers() -> Result<Vec<Nameserver>, NetError> {
    Ok(hickory_resolver::system_conf::read_system_conf()?
        .0
        .name_servers
        .iter()
        .map(|server| server.ip.into())
        .collect())
}

#[cfg(test)]
mod tests {
    use hickory_resolver::proto::op::Message;
    use hickory_resolver::proto::rr::Record;
    use hickory_resolver::proto::rr::rdata::{A, CNAME, NS};

    use super::*;

    fn query(name: &str) -> Question {
        Question {
            name: Name::from_ascii(name).unwrap(),
            record_type: RecordType::A,
        }
    }

    fn response(answers: Vec<Record>, authorities: Vec<Record>) -> DnsResponse {
        let mut message = Message::response(0, OpCode::Query);
        message.add_answers(answers);
        message.add_authorities(authorities);
        DnsResponse::from_message(message).unwrap()
    }

    fn record(name: &str, data: RData) -> Record {
        Record::from_rdata(Name::from_ascii(name).unwrap(), 300, data)
    }

    #[test]
    fn empty_responses_without_delegation_are_nodata() {
        let answer = query("example.com.").answer(&response(vec![], vec![]));

        assert!(matches!(answer, Ok(Answer::NoData)));
    }

    #[test]
    fn referrals_are_not_nodata() {
        let nameserver = Name::from_ascii("a.iana-servers.net.").unwrap();
        let delegation = vec![record("example.com.", RData::NS(NS(nameserver)))];

        let answer = query("example.com.").answer(&response(vec![], delegation));

        assert!(answer.is_err());
    }

    #[test]
    fn unrelated_answers_are_rejected() {
        let answers = vec![record("other.example.", RData::A(A::new(192, 0, 2, 1)))];

        let answer = query("example.com.").answer(&response(answers, vec![]));

        assert!(answer.is_err());
    }

    #[test]
    fn cname_chains_are_followed_within_a_response() {
        let target = Name::from_ascii("target.example.").unwrap();
        let chain = vec![record("example.com.", RData::CNAME(CNAME(target.clone())))];
        let mut answers = chain.clone();
        answers.push(record("target.example.", RData::A(A::new(192, 0, 2, 1))));

        let found = query("example.com.").answer(&response(answers, vec![]));
        let partial = query("example.com.").answer(&response(chain, vec![]));

        assert!(matches!(found, Ok(Answer::Found)));
        assert!(matches!(partial, Ok(Answer::Cname(name)) if name == target));
    }

    #[test]
    fn nameserver_parse_distinguishes_addresses_from_hosts() {
        assert!(Nameserver::parse("192.0.2.1").unwrap().is_some());
        assert!(Nameserver::parse("dns.example").unwrap().is_none());
        assert!(Nameserver::parse("192.0.2.1:53").unwrap().is_none());
        assert!(Nameserver::parse("fe80::1%no-such-interface").is_err());
        assert!(Nameserver::parse("fe80::1%").is_err());
    }
}
