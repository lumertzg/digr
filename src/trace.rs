use std::net::{IpAddr, SocketAddr};

use hickory_resolver::net::NetError;
use hickory_resolver::proto::op::{DnsResponse, ResponseCode};
use hickory_resolver::proto::rr::{DNSClass, Name, RData};

use crate::dns::{Query, Response};

pub struct Hop {
    pub number: usize,
    pub response: Response,
}

pub struct Trace {
    query: Query,
    servers: Vec<String>,
    zone: Name,
    hop: Option<Hop>,
    work_left: usize,
}

impl Trace {
    pub fn new(mut query: Query) -> Self {
        query.name.set_fqdn(true);
        query.recursion = false;
        let servers = match &query.server {
            Some(server) => vec![server.clone()],
            None => ROOT_SERVERS
                .iter()
                .map(|server| (*server).to_owned())
                .collect(),
        };

        Self {
            query,
            servers,
            zone: Name::root(),
            hop: None,
            work_left: 64,
        }
    }

    /// Returns error-status responses before reporting their error on the next call.
    /// Stop iterating after an error.
    pub async fn next(&mut self) -> Result<Option<&Hop>, NetError> {
        if let Some(hop) = &self.hop {
            if hop.response.message.metadata.response_code != ResponseCode::NoError {
                return Err(format!(
                    "trace received {} from {}",
                    hop.response.message.metadata.response_code, hop.response.server
                )
                .into());
            }

            if hop.response.message.metadata.authoritative {
                return Ok(None);
            }

            let (zone, servers) = self.referral_servers(&hop.response.message)?;
            self.zone = zone;
            self.servers = servers;

            if hop.number >= 32 {
                return Err("trace hop limit exceeded".into());
            }
        }

        self.hop = Some(self.send().await?);

        Ok(self.hop.as_ref())
    }

    async fn send(&mut self) -> Result<Hop, NetError> {
        let mut last_error = NetError::from("no nameservers match the requested transport family");
        let mut failure = None;

        for index in 0..self.servers.len() {
            if self.servers[index]
                .parse::<IpAddr>()
                .is_ok_and(|ip| !self.query.supports_family(ip))
            {
                continue;
            }

            self.spend_work()?;
            let addresses = match self.query.nameserver_ips(&self.servers[index]).await {
                Ok(addresses) => addresses,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };

            for ip in addresses {
                if !self.query.supports_family(ip) {
                    continue;
                }

                self.spend_work()?;
                let server = SocketAddr::new(ip, self.query.port.get());
                let response = match self.query.request(server).await {
                    Ok(result) => result,
                    Err(error) => {
                        last_error = error;
                        continue;
                    }
                };
                let hop = Hop {
                    number: self.hop.as_ref().map_or(1, |hop| hop.number + 1),
                    response,
                };

                if matches!(
                    hop.response.message.metadata.response_code,
                    ResponseCode::ServFail | ResponseCode::Refused
                ) {
                    failure = Some(hop);
                    continue;
                }

                if hop.response.message.metadata.response_code == ResponseCode::NoError
                    && let Err(error) = self.validate_response(&hop.response.message)
                {
                    last_error = format!("{server}: {error}").into();
                    continue;
                }

                return Ok(hop);
            }
        }

        failure.ok_or(last_error)
    }

    fn validate_response(&self, response: &DnsResponse) -> Result<(), NetError> {
        if !response.metadata.authoritative {
            return self.referral_zone(response).map(|_| ());
        }

        // Authoritative NODATA ends the walk. A positive answer must concern this query.
        if !response.answers.is_empty() {
            self.query.cname_target(response)?;
        }

        Ok(())
    }

    fn spend_work(&mut self) -> Result<(), NetError> {
        // Bound both hostname bootstrap and server attempts across the entire walk.
        self.work_left = self
            .work_left
            .checked_sub(1)
            .ok_or("trace work limit exceeded")?;

        Ok(())
    }

    fn referral_zone<'a>(&self, response: &'a DnsResponse) -> Result<&'a Name, NetError> {
        if !response.answers.is_empty() {
            return Err("trace received a non-authoritative answer instead of a referral".into());
        }

        response
            .authorities
            .iter()
            .filter(|record| {
                record.dns_class == DNSClass::IN
                    && matches!(record.data, RData::NS(_))
                    && record.name.zone_of(&self.query.name)
                    && self.zone.zone_of(&record.name)
                    && record.name.num_labels() > self.zone.num_labels()
            })
            .max_by_key(|record| record.name.num_labels())
            .map(|record| &record.name)
            .ok_or_else(|| "trace received an invalid or non-progressing referral".into())
    }

    fn referral_servers(&self, response: &DnsResponse) -> Result<(Name, Vec<String>), NetError> {
        let zone = self.referral_zone(response)?;
        let mut servers = Vec::new();

        for record in &response.authorities {
            if record.dns_class != DNSClass::IN || record.name != *zone {
                continue;
            }

            let RData::NS(nameserver) = &record.data else {
                continue;
            };
            let mut has_glue = false;

            // Only trust glue for named servers inside the delegated zone.
            if zone.zone_of(&nameserver.0) {
                for glue in &response.additionals {
                    if glue.dns_class == DNSClass::IN
                        && glue.name == nameserver.0
                        && let Some(ip) = glue.data.ip_addr()
                        && self.query.supports_family(ip)
                    {
                        push_server(&mut servers, ip.to_string());
                        has_glue = true;
                    }
                }
            }

            if !has_glue {
                push_server(&mut servers, nameserver.0.to_string());
            }
        }

        Ok((zone.clone(), servers))
    }
}

fn push_server(servers: &mut Vec<String>, server: String) {
    if servers.len() < 64 && !servers.contains(&server) {
        servers.push(server);
    }
}

// InterNIC root hints, https://www.internic.net/domain/named.root (2026-10-23).
const ROOT_SERVERS: &[&str] = &[
    "198.41.0.4",
    "170.247.170.2",
    "192.33.4.12",
    "199.7.91.13",
    "192.203.230.10",
    "192.5.5.241",
    "192.112.36.4",
    "198.97.190.53",
    "192.36.148.17",
    "192.58.128.30",
    "193.0.14.129",
    "199.7.83.42",
    "202.12.27.33",
    "2001:503:ba3e::2:30",
    "2801:1b8:10::b",
    "2001:500:2::c",
    "2001:500:2d::d",
    "2001:500:a8::e",
    "2001:500:2f::f",
    "2001:500:12::d0d",
    "2001:500:1::53",
    "2001:7fe::53",
    "2001:503:c27::2:30",
    "2001:7fd::1",
    "2001:500:9f::42",
    "2001:dc3::35",
];
