use std::net::IpAddr;
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use std::time::Duration;

use hickory_resolver::proto::rr::rdata::opt::ClientSubnet;
use hickory_resolver::proto::rr::{Name, RecordType};
use ipnet::IpNet;
use usage_rs::{Cli, Subcommands, ValidationError};

use crate::dns::{Nameserver, Query};
use crate::location::Kind;

/// Query DNS records.
#[derive(Cli)]
#[usage(
    bin = "digr", version, unknown_flags = "error", try_into = Command,
    default_subcommand = "query", default_subcommand_flags,
    default_subcommand_on_empty, default_subcommand_help,
)]
pub struct Args {
    #[usage(subcommand)]
    command: Commands,
}

#[derive(Subcommands)]
enum Commands {
    /// Query DNS records (the default command).
    Query(Box<QueryArgs>),
    #[usage(hide)]
    UpdateDb(UpdateArgs),
}

#[derive(usage_rs::Args)]
struct UpdateArgs {
    #[usage(choices("city", "asn"))]
    kind: Kind,
}

#[derive(usage_rs::Args)]
struct QueryArgs {
    /// Domain name to query.
    #[usage(required_unless("--reverse"), conflicts("--reverse"))]
    name: Option<Name>,
    /// Record type name, decimal code, or TYPE<number>. Defaults to A, or PTR with --reverse.
    #[usage(short = 't', long = "type", value_name = "TYPE")]
    record_type: Option<String>,
    /// Look up PTR records for an IPv4 or IPv6 address instead of a name.
    #[usage(short = 'x', long, value_name = "IP")]
    reverse: Option<IpAddr>,
    /// Nameserver IP address or hostname. Defaults to the system nameservers.
    /// Link-local IPv6 addresses need a zone, such as fe80::1%en0.
    /// With --trace, overrides the root hints as the starting server.
    #[usage(short = 's', long, value_name = "HOST")]
    server: Option<String>,
    /// Nameserver port.
    #[usage(short = 'p', long, default = "53")]
    port: NonZeroU16,
    /// Use TCP only. Otherwise, use UDP with TCP fallback for truncated replies.
    #[usage(long)]
    tcp: bool,
    /// Use only IPv4 DNS transport, including nameserver hostname lookup.
    #[usage(short = '4', long, conflicts("--ipv6"))]
    ipv4: bool,
    /// Use only IPv6 DNS transport, including nameserver hostname lookup.
    #[usage(short = '6', long)]
    ipv6: bool,
    /// Bind queries to a local IP address. Implies its transport family.
    #[usage(long, value_name = "IP")]
    source: Option<IpAddr>,
    /// Send an IPv4 or IPv6 EDNS Client Subnet hint. Servers may ignore it.
    #[usage(long, value_name = "CIDR", conflicts("--subnet-from"))]
    subnet: Option<IpNet>,
    /// Use a representative AWS regional IPv4 /24 as the subnet hint.
    /// NA: Northern Virginia, SA: São Paulo, EU: Frankfurt, AS: Tokyo,
    /// AF: Cape Town, OC: Sydney. Does not change where queries originate.
    #[usage(long, value_name = "REGION")]
    subnet_from: Option<String>,
    /// Disable the recursion-desired flag on the query.
    #[usage(long)]
    no_recursion: bool,
    /// Per-request timeout in milliseconds, not a total lookup deadline.
    #[usage(long, default = "5000")]
    timeout_ms: NonZeroU64,
    /// Attempts per server and transport, including the initial request.
    #[usage(long, default = "3")]
    tries: NonZeroUsize,
    /// Follow delegations from the root to an authoritative response, without recursion.
    #[usage(long)]
    trace: bool,
    /// Show response flags and all answer, authority, and additional sections.
    /// AD reports the server's assertion, not local DNSSEC validation.
    #[usage(short = 'v', long)]
    verbose: bool,
    /// Print one JSON document with all DNS sections, including for trace.
    #[usage(long)]
    json: bool,
    /// Add approximate city and country information. Downloads DB-IP City Lite on first use.
    /// Fetches each new monthly release in the background.
    #[usage(long)]
    location: bool,
    /// Add autonomous system numbers and network names. Downloads DB-IP ASN Lite on first use.
    /// Fetches each new monthly release in the background.
    #[usage(long)]
    asn: bool,
}

pub enum Command {
    UpdateDb(Kind),
    Query(QueryOptions),
}

pub struct QueryOptions {
    pub query: Query,
    pub trace: bool,
    pub verbose: bool,
    pub json: bool,
    pub location: bool,
    pub asn: bool,
}

impl TryFrom<Args> for Command {
    type Error = ValidationError;

    fn try_from(args: Args) -> Result<Self, Self::Error> {
        match args.command {
            Commands::Query(args) => Self::try_from(*args),
            Commands::UpdateDb(args) => Ok(Command::UpdateDb(args.kind)),
        }
    }
}

impl TryFrom<QueryArgs> for Command {
    type Error = ValidationError;

    fn try_from(args: QueryArgs) -> Result<Self, Self::Error> {
        let family_matches =
            |ip: IpAddr| !(args.ipv4 && ip.is_ipv6()) && !(args.ipv6 && ip.is_ipv4());

        if let Some(source) = args.source
            && !family_matches(source)
        {
            return Err(ValidationError::field("--source")
                .value(source.to_string())
                .reason("must match the requested transport family"));
        }

        if let Some(server) = &args.server {
            validate_server(server, |ip| {
                family_matches(ip)
                    && args
                        .source
                        .is_none_or(|source| source.is_ipv4() == ip.is_ipv4())
            })?;
        }

        let subnet = args
            .subnet
            .or(args.subnet_from.as_deref().map(subnet_from).transpose()?);
        let record_type = args
            .record_type
            .as_deref()
            .map(parse_record_type)
            .transpose()?;
        let (name, record_type) = match args.reverse {
            Some(ip) => {
                if record_type.is_some_and(|kind| kind != RecordType::PTR) {
                    return Err(ValidationError::field("--type")
                        .value(args.record_type.unwrap_or_default())
                        .reason("--reverse queries PTR records"));
                }
                (Name::from(ip), RecordType::PTR)
            }
            None => (
                args.name
                    .expect("usage-rs requires a name without --reverse"),
                record_type.unwrap_or(RecordType::A),
            ),
        };

        Ok(Command::Query(QueryOptions {
            query: Query {
                name,
                record_type,
                server: args.server,
                port: args.port,
                tcp: args.tcp,
                ipv4: args.ipv4,
                ipv6: args.ipv6,
                source: args.source,
                subnet: subnet.map(|net| ClientSubnet::from(net.trunc())),
                recursion: !args.no_recursion,
                timeout: Duration::from_millis(args.timeout_ms.get()),
                tries: args.tries,
            },
            trace: args.trace,
            verbose: args.verbose,
            json: args.json,
            location: args.location,
            asn: args.asn,
        }))
    }
}

fn validate_server(server: &str, family: impl Fn(IpAddr) -> bool) -> Result<(), ValidationError> {
    let invalid = |reason: &str| {
        ValidationError::field("--server")
            .value(server)
            .reason(reason)
    };

    match Nameserver::parse(server).map_err(|error| invalid(&error.to_string()))? {
        Some(nameserver) if !family(nameserver.ip) => {
            Err(invalid("must match the requested transport family"))
        }
        Some(_) => Ok(()),
        None if server
            .rsplit_once(':')
            .is_some_and(|(_, port)| port.parse::<u16>().is_ok()) =>
        {
            Err(invalid("set the port with --port"))
        }
        None => server
            .parse::<Name>()
            .map(|_| ())
            .map_err(|error| invalid(&error.to_string())),
    }
}

fn subnet_from(value: &str) -> Result<IpNet, ValidationError> {
    // AWS regional ranges avoid geographically ambiguous anycast addresses.
    // Source: https://ip-ranges.amazonaws.com/ip-ranges.json
    let subnet = match value.to_ascii_uppercase().as_str() {
        "NA" => "3.80.0.0/24",
        "SA" => "18.228.0.0/24",
        "EU" => "3.120.0.0/24",
        "AS" => "13.112.0.0/24",
        "AF" => "13.244.0.0/24",
        "OC" => "13.54.0.0/24",
        _ => {
            return Err(ValidationError::field("--subnet-from")
                .value(value)
                .reason("expected NA, SA, EU, AS, AF, or OC"));
        }
    };

    Ok(subnet.parse().expect("regional prefixes are valid CIDRs"))
}

fn parse_record_type(value: &str) -> Result<RecordType, ValidationError> {
    let upper = value.to_ascii_uppercase();
    let code = upper.strip_prefix("TYPE").unwrap_or(&upper);

    let invalid = |reason: String| ValidationError::field("--type").value(value).reason(reason);
    let record_type = match code.parse::<u16>() {
        Ok(code) => RecordType::from(code),
        Err(_) => upper
            .parse::<RecordType>()
            .map_err(|error| invalid(error.to_string()))?,
    };

    // OPT carries EDNS options and type 0 is reserved, so neither can be queried.
    if matches!(record_type, RecordType::OPT | RecordType::ZERO) {
        return Err(invalid(format!("{record_type} is not a queryable type")));
    }

    Ok(record_type)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudo_record_types_are_rejected() {
        for value in ["OPT", "41", "TYPE0"] {
            assert!(parse_record_type(value).is_err(), "{value}");
        }
        assert_eq!(
            parse_record_type("type65000").unwrap(),
            RecordType::Unknown(65000)
        );
    }

    #[test]
    fn server_with_port_is_rejected() {
        for server in ["192.0.2.1:53", "dns.example:53", "[fe80::1%en0]:53"] {
            assert!(validate_server(server, |_| true).is_err(), "{server}");
        }
        assert!(validate_server("192.0.2.1", |ip| ip.is_ipv6()).is_err());
        assert!(validate_server("dns.example", |_| true).is_ok());
    }
}
