use std::error::Error;
use std::io::{self, Write};

use hickory_resolver::proto::rr::{RData, Record};
use hickory_resolver::proto::serialize::binary::BinEncodable;
use serde::Serialize;
use serde_json::{Value, json};

use super::{ip_information, record_class, record_type, response_status};
use crate::dns::{Query, Response};
use crate::location::{Database, Information, Kind};

#[derive(Serialize)]
pub struct Document {
    schema_version: u8,
    mode: Mode,
    query: QuerySummary,
    responses: Vec<ResponseSummary>,
    complete: bool,
    error: Option<Failure>,
    warnings: Vec<Warning>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enrichment: Option<Enrichment>,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum Mode {
    Lookup,
    Trace,
}

#[derive(Serialize)]
struct QuerySummary {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    subnet: Option<String>,
    dnssec: bool,
    checking_disabled: bool,
    local_validation: &'static str,
}

#[derive(Serialize)]
struct ResponseSummary {
    server: String,
    transport: &'static str,
    elapsed_ms: f64,
    status: String,
    flags: Flags,
    edns: Option<EdnsSummary>,
    question: Question,
    answers: Vec<RecordSummary>,
    authority: Vec<RecordSummary>,
    additional: Vec<RecordSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hop: Option<usize>,
}

#[derive(Serialize)]
struct EdnsSummary {
    version: u8,
    udp_payload: u16,
    dnssec_ok: bool,
    extended_errors: Vec<ExtendedErrorSummary>,
}

#[derive(Serialize)]
struct ExtendedErrorSummary {
    code: Option<u16>,
    name: Option<&'static str>,
    text: Option<String>,
    wire_hex: String,
}

#[derive(Serialize)]
struct Flags {
    authoritative: bool,
    truncated: bool,
    recursion_desired: bool,
    recursion_available: bool,
    authenticated_data: bool,
    checking_disabled: bool,
}

#[derive(Serialize)]
struct Question {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    class: String,
}

#[derive(Serialize)]
struct RecordSummary {
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    class: String,
    ttl: u32,
    data: Value,
    // Absent means no lookup. Null means a lookup produced no information.
    #[serde(skip_serializing_if = "Option::is_none")]
    location: Option<Option<Information>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    asn: Option<Option<Information>>,
}

#[derive(Serialize)]
struct Failure {
    code: &'static str,
    message: String,
}

#[derive(Serialize)]
struct Warning {
    code: WarningCode,
    message: String,
}

/// Warnings about IP information. The codes keep their schema v1 names.
#[derive(Serialize)]
pub enum WarningCode {
    #[serde(rename = "enrichment_unavailable")]
    Unavailable,
    #[serde(rename = "enrichment_lookup_failed")]
    LookupFailed,
    #[serde(rename = "enrichment_update_failed")]
    UpdateFailed,
}

#[derive(Serialize)]
struct Enrichment {
    provider: &'static str,
    url: &'static str,
    license: &'static str,
    approximate: bool,
    databases: Vec<DatabaseSource>,
}

#[derive(Serialize)]
struct DatabaseSource {
    kind: Kind,
    build_date: Option<String>,
}

impl Document {
    pub fn new(query: &Query, trace: bool, enrich: bool) -> Self {
        let mut name = query.name.clone();
        name.set_fqdn(true);

        Self {
            schema_version: 1,
            mode: if trace { Mode::Trace } else { Mode::Lookup },
            query: QuerySummary {
                name: name.to_ascii(),
                record_type: record_type(query.record_type),
                subnet: query
                    .subnet
                    .map(|subnet| format!("{}/{}", subnet.addr(), subnet.source_prefix())),
                dnssec: query.dnssec,
                checking_disabled: query.checking_disabled,
                local_validation: "not_performed",
            },
            responses: Vec::new(),
            complete: false,
            error: None,
            warnings: Vec::new(),
            enrichment: enrich.then(|| Enrichment {
                provider: "DB-IP Lite",
                url: "https://db-ip.com",
                license: "CC BY 4.0",
                approximate: true,
                databases: Vec::new(),
            }),
        }
    }

    pub fn warn(&mut self, code: WarningCode, message: String) {
        self.warnings.push(Warning { code, message });
    }

    pub fn push(
        &mut self,
        response: &Response,
        hop: Option<usize>,
        databases: &[Database],
    ) -> Result<(), Box<dyn Error>> {
        let message = &response.message;
        let metadata = &message.metadata;
        let question = &message.queries[0];
        let answers = self.records(&message.answers, databases)?;
        let authority = self.records(&message.authorities, databases)?;
        let additional = self.records(&message.additionals, databases)?;

        self.responses.push(ResponseSummary {
            server: response.server.to_string(),
            transport: if response.tcp { "tcp" } else { "udp" },
            elapsed_ms: response.elapsed.as_secs_f64() * 1000.0,
            status: response_status(metadata.response_code),
            flags: Flags {
                authoritative: metadata.authoritative,
                truncated: metadata.truncation,
                recursion_desired: metadata.recursion_desired,
                recursion_available: metadata.recursion_available,
                authenticated_data: metadata.authentic_data,
                checking_disabled: metadata.checking_disabled,
            },
            edns: message.edns.as_ref().map(|edns| EdnsSummary {
                version: edns.version(),
                udp_payload: edns.max_payload(),
                dnssec_ok: edns.flags().dnssec_ok,
                extended_errors: response
                    .extended_errors()
                    .map(|error| ExtendedErrorSummary {
                        code: error.code,
                        name: error.name,
                        text: error.text.map(str::to_owned),
                        wire_hex: hex(error.wire),
                    })
                    .collect(),
            }),
            question: Question {
                name: question.name().to_ascii(),
                record_type: record_type(question.query_type()),
                class: record_class(question.query_class()),
            },
            answers,
            authority,
            additional,
            hop,
        });

        Ok(())
    }

    fn records(
        &mut self,
        records: &[Record],
        databases: &[Database],
    ) -> Result<Vec<RecordSummary>, Box<dyn Error>> {
        let mut values = Vec::with_capacity(records.len());

        for record in records {
            let mut value = RecordSummary {
                name: record.name.to_ascii(),
                record_type: record_type(record.data.record_type()),
                class: record_class(record.dns_class),
                ttl: record.ttl,
                data: record_data(&record.data)?,
                location: None,
                asn: None,
            };

            if let Some(ip) = record.data.ip_addr() {
                let information = ip_information(databases, ip, |message| {
                    eprintln!("digr: {message}");
                    self.warn(WarningCode::LookupFailed, message);
                });
                for (kind, information) in information {
                    match kind {
                        Kind::City => value.location = Some(information),
                        Kind::Asn => value.asn = Some(information),
                    }
                }
            }

            values.push(value);
        }

        Ok(values)
    }

    pub fn finish(
        mut self,
        error: Option<&dyn Error>,
        databases: &[Database],
    ) -> Result<(), Box<dyn Error>> {
        self.complete = error.is_none();
        self.error = error.map(|error| Failure {
            code: "lookup_failed",
            message: error.to_string(),
        });
        if let Some(enrichment) = &mut self.enrichment {
            enrichment.databases = databases
                .iter()
                .map(|database| DatabaseSource {
                    kind: database.kind,
                    build_date: database.build_date(),
                })
                .collect();
        }

        let mut stdout = io::stdout().lock();
        serde_json::to_writer_pretty(&mut stdout, &self)?;
        writeln!(stdout)?;

        Ok(())
    }
}

fn record_data(data: &RData) -> Result<Value, Box<dyn Error>> {
    Ok(match data {
        RData::A(address) => json!({"address": address.to_string()}),
        RData::AAAA(address) => json!({"address": address.to_string()}),
        RData::ANAME(name) => json!({"target": name.0.to_ascii()}),
        RData::CNAME(name) => json!({"target": name.0.to_ascii()}),
        RData::NS(name) => json!({"target": name.0.to_ascii()}),
        RData::PTR(name) => json!({"target": name.0.to_ascii()}),
        RData::MX(mx) => json!({"preference": mx.preference, "exchange": mx.exchange.to_ascii()}),
        // RFC 1035 timers are unsigned, though hickory stores some as i32.
        RData::SOA(soa) => json!({
            "mname": soa.mname.to_ascii(), "rname": soa.rname.to_ascii(),
            "serial": soa.serial, "refresh": soa.refresh.cast_unsigned(),
            "retry": soa.retry.cast_unsigned(), "expire": soa.expire.cast_unsigned(),
            "minimum": soa.minimum,
        }),
        RData::SRV(srv) => json!({
            "priority": srv.priority, "weight": srv.weight,
            "port": srv.port, "target": srv.target.to_ascii(),
        }),
        RData::TXT(txt) => json!({"strings": txt.txt_data.iter().map(|bytes| json!({
            "text": std::str::from_utf8(bytes).ok(), "hex": hex(bytes),
        })).collect::<Vec<_>>()}),
        _ => json!({"text": super::record_value(data, true), "wire_hex": hex(&data.to_bytes()?)}),
    })
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
