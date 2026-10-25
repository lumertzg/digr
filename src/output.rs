use std::env;
use std::error::Error;
use std::io::{self, IsTerminal, Write};
use std::net::IpAddr;

use hickory_resolver::proto::dnssec::rdata::{DNSSECRData, SIG};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::rdata::HTTPS;
use hickory_resolver::proto::rr::{DNSClass, RData, Record, RecordType};
use indicatif::{ProgressBar, ProgressStyle};
use tabled::builder::Builder;
use tabled::grid::util::string::get_line_width;
use tabled::settings::{
    Alignment, Color, Padding, Style, Width,
    object::{Cell, Columns, Rows},
    style::BorderColor,
};

use crate::dns::{Query, Response};
use crate::location::{Database, Information, Kind, Progress};
use crate::trace::Hop;

pub mod json;

pub struct Output {
    verbose: bool,
    full_signatures: bool,
    dnssec_request: Option<String>,
    document: Option<json::Document>,
}

impl Output {
    pub fn new(query: &Query, trace: bool, verbose: bool, json: bool, enrich: bool) -> Self {
        Self {
            verbose: verbose || query.dnssec || query.checking_disabled,
            full_signatures: verbose,
            dnssec_request: (query.dnssec || query.checking_disabled).then(|| {
                format!(
                    "DNSSEC request: records {} (DO) · checking disabled: {} (CD)",
                    if query.dnssec {
                        "requested"
                    } else {
                        "not requested"
                    },
                    if query.checking_disabled { "yes" } else { "no" }
                )
            }),
            document: json.then(|| json::Document::new(query, trace, enrich)),
        }
    }

    pub fn warn(&mut self, code: json::WarningCode, message: String) {
        eprintln!("digr: {message}");
        if let Some(document) = &mut self.document {
            document.warn(code, message);
        }
    }

    pub fn lookup(
        &mut self,
        responses: &[Response],
        databases: &[Database],
    ) -> Result<(), Box<dyn Error>> {
        if let Some(document) = &mut self.document {
            for response in responses {
                document.push(response, None, databases)?;
            }
        } else {
            print_lookup(
                responses,
                self.verbose,
                self.full_signatures,
                self.dnssec_request.as_deref(),
                databases,
            )?;
        }

        Ok(())
    }

    pub fn hop(&mut self, hop: &Hop, databases: &[Database]) -> Result<(), Box<dyn Error>> {
        if let Some(document) = &mut self.document {
            document.push(&hop.response, Some(hop.number), databases)?;
        } else {
            print_hop(
                hop,
                self.verbose,
                self.full_signatures,
                self.dnssec_request.as_deref(),
                databases,
            )?;
        }

        Ok(())
    }

    pub fn finish(
        self,
        error: Option<&dyn Error>,
        databases: &[Database],
    ) -> Result<(), Box<dyn Error>> {
        if let Some(document) = self.document {
            document.finish(error, databases)?;
        } else if !databases.is_empty() {
            print_location_source(databases)?;
        }

        Ok(())
    }
}

fn print_lookup(
    responses: &[Response],
    verbose: bool,
    full_signatures: bool,
    dnssec_request: Option<&str>,
    databases: &[Database],
) -> io::Result<()> {
    for (index, response) in responses.iter().enumerate() {
        let question = &response.message.queries[0];

        if index > 0 {
            writeln!(io::stdout().lock())?;
        }

        let title = format!(
            "{} {}",
            question.name().to_ascii(),
            record_type(question.query_type())
        );
        print_response(
            response,
            &title,
            verbose,
            full_signatures,
            dnssec_request,
            databases,
        )?;
    }

    Ok(())
}

fn print_records(
    records: &[Record],
    databases: &[Database],
    full_signatures: bool,
) -> io::Result<()> {
    let enrich =
        !databases.is_empty() && records.iter().any(|record| record.data.ip_addr().is_some());
    let show_class = records
        .iter()
        .any(|record| record.dns_class != DNSClass::IN);
    let mut builder = Builder::default();

    let mut header = vec!["Name", "Type"];
    if show_class {
        header.push("Class");
    }
    header.extend(["TTL (s)", "Value"]);
    if enrich {
        for database in databases {
            header.push(match database.kind {
                Kind::City => "Location",
                Kind::Asn => "ASN / Network",
            });
        }
    }
    builder.push_record(header);

    for record in records {
        let mut row = vec![record.name.to_ascii(), record_type(record.record_type())];
        if show_class {
            row.push(record_class(record.dns_class));
        }
        row.extend([
            record.ttl.to_string(),
            record_value(&record.data, full_signatures),
        ]);

        if enrich {
            let information = record
                .data
                .ip_addr()
                .map(|ip| ip_information(databases, ip, |message| eprintln!("digr: {message}")));
            for index in 0..databases.len() {
                let value = information
                    .as_ref()
                    .and_then(|information| information[index].1.as_ref())
                    .map_or_else(|| "—".to_owned(), ToString::to_string);
                row.push(value);
            }
        }

        builder.push_record(row.iter().map(|cell| escape(cell)));
    }

    let ttl_column = if show_class { 3 } else { 2 };

    print_table(builder.build(), ttl_column)
}

fn print_table(mut table: tabled::Table, ttl_column: usize) -> io::Result<()> {
    table.with(Style::sharp());
    table.with(Alignment::left());
    table.modify(Columns::one(ttl_column), Alignment::right());

    if let Some((terminal_size::Width(width), _)) = terminal_size::terminal_size_of(io::stdout())
        && table.total_width() > usize::from(width)
    {
        let value_column = ttl_column + 1;
        let value_width = table
            .get_records()
            .iter()
            .map(|row| get_line_width(row[value_column].as_ref()))
            .max()
            .unwrap_or(0);
        let fixed_width = table.total_width() - value_width;
        let available = usize::from(width).saturating_sub(fixed_width);

        if available < "Value".len() {
            return print_stacked(Builder::from(table).into(), usize::from(width));
        }

        table.modify(
            Columns::one(value_column),
            Width::wrap(available).keep_words(true),
        );
    }

    if colors_enabled() {
        table.with(BorderColor::filled(Color::FG_BRIGHT_BLACK));
        table.modify(Columns::one(0), Color::FG_BRIGHT_BLACK);
        table.modify(Columns::one(1), Color::FG_CYAN);
        table.modify(Columns::one(ttl_column), Color::FG_BRIGHT_BLACK);
        table.modify(Rows::first(), Color::FG_GREEN | Color::BOLD);
    }

    writeln!(io::stdout().lock(), "{table}")
}

fn print_stacked(rows: Vec<Vec<String>>, width: usize) -> io::Result<()> {
    let headers = &rows[0];
    let label_width = headers
        .iter()
        .map(|label| get_line_width(label))
        .max()
        .unwrap_or(0);
    let value_width = width.saturating_sub(label_width + 4);

    for (index, record) in rows[1..].iter().enumerate() {
        if index > 0 {
            writeln!(io::stdout().lock())?;
        }

        // Match tabled's ASCII-space word boundaries, not Unicode whitespace.
        let longest_word = record
            .iter()
            .flat_map(|value| value.split(' '))
            .map(get_line_width)
            .max()
            .unwrap_or(0);

        // Put labels above values when even an intact address cannot fit beside them.
        let inline = longest_word <= value_width;
        let mut builder = Builder::default();
        for (header, value) in headers.iter().zip(record) {
            if inline {
                builder.push_record([header.clone(), value.clone()]);
            } else {
                builder.push_record([header.clone()]);
                builder.push_record([value.clone()]);
            }
        }

        let mut table = builder.build();
        table.with(Style::empty());
        if inline {
            table.with(Padding::new(0, 2, 0, 0));
            table.modify(Columns::one(1), Width::wrap(value_width).keep_words(true));
        } else {
            table.with(Padding::zero());
            table.with(Width::wrap(width.max(longest_word)).keep_words(true));
        }

        if colors_enabled() {
            for field in 0..headers.len() {
                let row = if inline { field } else { field * 2 };
                table.modify(Cell::new(row, 0), Color::FG_BRIGHT_BLACK);
            }
            let type_cell = if inline {
                Cell::new(1, 1)
            } else {
                Cell::new(3, 0)
            };
            table.modify(type_cell, Color::FG_CYAN);
        }
        writeln!(io::stdout().lock(), "{table}")?;
    }

    Ok(())
}

fn print_hop(
    hop: &Hop,
    verbose: bool,
    full_signatures: bool,
    dnssec_request: Option<&str>,
    databases: &[Database],
) -> io::Result<()> {
    let role = if hop.response.message.metadata.response_code != ResponseCode::NoError {
        "Response"
    } else if hop.response.message.metadata.authoritative {
        "Authoritative"
    } else {
        "Referral"
    };

    if hop.number > 1 {
        writeln!(io::stdout().lock())?;
    }

    print_response(
        &hop.response,
        &format!("Hop {} · {role}", hop.number),
        verbose,
        full_signatures,
        dnssec_request,
        databases,
    )
}

fn print_response(
    response: &Response,
    title: &str,
    verbose: bool,
    full_signatures: bool,
    dnssec_request: Option<&str>,
    databases: &[Database],
) -> io::Result<()> {
    let message = &response.message;
    let status = message.metadata.response_code;
    let color = if status != ResponseCode::NoError {
        Color::FG_YELLOW
    } else if message.metadata.authoritative || message.authorities.is_empty() {
        Color::FG_GREEN
    } else {
        Color::FG_CYAN
    };
    let status = response_status(status);
    print_line(&escape(&format!("{title} · {status}")), color | Color::BOLD)?;
    print_metadata(response, verbose, dnssec_request)?;
    writeln!(io::stdout().lock())?;

    if verbose {
        for (name, records) in [
            ("Answer", &message.answers),
            ("Authority", &message.authorities),
            ("Additional", &message.additionals),
        ] {
            if !records.is_empty() {
                print_section(name, records, databases, full_signatures)?;
            }
        }
    } else if !message.answers.is_empty() {
        print_records(&message.answers, databases, full_signatures)?;
    } else if !message.authorities.is_empty() {
        print_section(
            "Authority",
            &message.authorities,
            databases,
            full_signatures,
        )?;
    }

    if message.answers.is_empty()
        && message.authorities.is_empty()
        && (!verbose || message.additionals.is_empty())
    {
        print_line("No answer records.", Color::FG_BRIGHT_BLACK)?;
    }

    Ok(())
}

fn print_metadata(
    response: &Response,
    verbose: bool,
    dnssec_request: Option<&str>,
) -> io::Result<()> {
    print_line(
        &format!(
            "Server {} · {} · {:.1} ms",
            response.server,
            if response.tcp { "TCP" } else { "UDP" },
            response.elapsed.as_secs_f64() * 1000.0
        ),
        Color::FG_BRIGHT_BLACK,
    )?;
    if let Some(request) = dnssec_request {
        print_line(request, Color::FG_BRIGHT_BLACK)?;
        print_line(
            "DNSSEC validation: not performed locally",
            Color::FG_BRIGHT_BLACK,
        )?;
    }

    if verbose {
        print_flags(response)?;
    }

    print_edns(response, verbose)
}

fn print_edns(response: &Response, verbose: bool) -> io::Result<()> {
    if verbose && let Some(edns) = &response.message.edns {
        print_line(
            &format!(
                "EDNS: version {} · UDP payload {} bytes · DNSSEC OK (DO): {}",
                edns.version(),
                edns.max_payload(),
                if edns.flags().dnssec_ok { "yes" } else { "no" }
            ),
            Color::FG_BRIGHT_BLACK,
        )?;
    }

    for error in response.extended_errors() {
        let description = match error.code {
            Some(code) => format!("{code} ({})", error.name.unwrap_or("Unknown")),
            None => "malformed".to_owned(),
        };
        let detail = match error.text {
            Some(text) => escape(text),
            None => format!("raw hex: {}", json::hex(error.wire)),
        };
        print_line(
            &format!("EDE (server-reported): {description} · {detail}"),
            Color::FG_YELLOW,
        )?;
    }

    Ok(())
}

fn print_flags(response: &Response) -> io::Result<()> {
    let metadata = &response.message.metadata;
    let flags = [
        (metadata.authoritative, "authoritative (AA)"),
        (metadata.truncation, "truncated (TC)"),
        (metadata.recursion_desired, "recursion requested (RD)"),
        (metadata.recursion_available, "recursion available (RA)"),
        (
            metadata.authentic_data,
            "authenticated data (AD, server-asserted)",
        ),
        (metadata.checking_disabled, "checking disabled (CD)"),
    ]
    .into_iter()
    .filter_map(|(enabled, name)| enabled.then_some(name))
    .collect::<Vec<_>>();

    print_line(
        &format!(
            "Flags: {}",
            if flags.is_empty() {
                "none".to_owned()
            } else {
                flags.join(" · ")
            }
        ),
        Color::FG_BRIGHT_BLACK,
    )
}

fn print_section(
    name: &str,
    records: &[Record],
    databases: &[Database],
    full_signatures: bool,
) -> io::Result<()> {
    print_line(
        &format!("{name} · {}", records.len()),
        Color::FG_GREEN | Color::BOLD,
    )?;
    print_records(records, databases, full_signatures)
}

fn print_location_source(databases: &[Database]) -> io::Result<()> {
    writeln!(io::stdout().lock())?;
    for database in databases {
        print_line(&database.description(), Color::FG_BRIGHT_BLACK)?;
    }
    print_line(
        "DB-IP Lite · https://db-ip.com · CC BY 4.0",
        Color::FG_BRIGHT_BLACK,
    )
}

pub struct DownloadProgress {
    kind: Kind,
    bar: Option<ProgressBar>,
}

impl DownloadProgress {
    pub fn new(kind: Kind) -> Self {
        Self { kind, bar: None }
    }

    pub fn update(&mut self, progress: Progress) {
        match progress {
            Progress::Waiting => eprintln!(
                "digr: waiting for another digr process to install DB-IP {} Lite…",
                self.kind
            ),
            Progress::Download { length, received } => {
                let bar = self
                    .bar
                    .get_or_insert_with(|| download_progress(self.kind, length));
                bar.set_position(received);
            }
        }
    }
}

impl Drop for DownloadProgress {
    fn drop(&mut self) {
        if let Some(bar) = &self.bar {
            bar.finish_and_clear();
        }
    }
}

fn download_progress(kind: Kind, length: Option<u64>) -> ProgressBar {
    eprintln!("digr: downloading DB-IP {kind} Lite into the user cache…");
    let progress = ProgressBar::new(length.unwrap_or(0));
    let template = if length.is_some() {
        "{spinner:.cyan} {msg} [{bar:25.cyan/blue}] {bytes}/{total_bytes}"
    } else {
        "{spinner:.cyan} {msg} {bytes}"
    };
    progress.set_style(ProgressStyle::with_template(template).expect("valid progress template"));
    progress.set_message(format!("DB-IP {kind}"));
    progress.enable_steady_tick(std::time::Duration::from_millis(100));

    progress
}

fn response_status(code: ResponseCode) -> String {
    match code {
        ResponseCode::NoError => "NOERROR",
        ResponseCode::FormErr => "FORMERR",
        ResponseCode::ServFail => "SERVFAIL",
        ResponseCode::NXDomain => "NXDOMAIN",
        ResponseCode::NotImp => "NOTIMP",
        ResponseCode::Refused => "REFUSED",
        ResponseCode::YXDomain => "YXDOMAIN",
        ResponseCode::YXRRSet => "YXRRSET",
        ResponseCode::NXRRSet => "NXRRSET",
        ResponseCode::NotAuth => "NOTAUTH",
        ResponseCode::NotZone => "NOTZONE",
        ResponseCode::BADVERS => "BADVERS",
        ResponseCode::BADSIG => "BADSIG",
        ResponseCode::BADKEY => "BADKEY",
        ResponseCode::BADTIME => "BADTIME",
        ResponseCode::BADMODE => "BADMODE",
        ResponseCode::BADNAME => "BADNAME",
        ResponseCode::BADALG => "BADALG",
        ResponseCode::BADTRUNC => "BADTRUNC",
        ResponseCode::BADCOOKIE => "BADCOOKIE",
        ResponseCode::Unknown(code) => return format!("UNKNOWN({code})"),
    }
    .to_owned()
}

fn print_line(text: &str, color: Color) -> io::Result<()> {
    let mut stdout = io::stdout().lock();

    if colors_enabled() {
        writeln!(stdout, "{}", color.colorize(text))
    } else {
        writeln!(stdout, "{text}")
    }
}

fn colors_enabled() -> bool {
    io::stdout().is_terminal()
        && env::var_os("NO_COLOR").is_none()
        && env::var_os("TERM").is_none_or(|term| term != "dumb")
}

/// Looks up an address in each database, in order. A failed lookup is reported and yields
/// no information.
fn ip_information(
    databases: &[Database],
    ip: IpAddr,
    mut warn: impl FnMut(String),
) -> Vec<(Kind, Option<Information>)> {
    databases
        .iter()
        .map(|database| {
            let information = database.lookup(ip).unwrap_or_else(|error| {
                warn(format!("{} lookup for {ip} failed: {error}", database.kind));
                None
            });
            (database.kind, information)
        })
        .collect()
}

fn record_type(kind: RecordType) -> String {
    match kind {
        RecordType::Unknown(code) => format!("TYPE{code}"),
        _ => kind.to_string(),
    }
}

fn record_class(class: DNSClass) -> String {
    match class {
        DNSClass::Unknown(code) => format!("CLASS{code}"),
        _ => class.to_string(),
    }
}

/// Renders names in ASCII so lookalike Unicode domains stay distinguishable.
fn record_value(data: &RData, full_signatures: bool) -> String {
    match data {
        RData::DNSSEC(DNSSECRData::RRSIG(signature)) => signature_value(signature, full_signatures),
        RData::DNSSEC(DNSSECRData::SIG(signature)) => signature_value(signature, true),
        RData::DNSSEC(DNSSECRData::NSEC(nsec)) => {
            let mut text = nsec.next_domain_name().to_ascii();
            for kind in nsec.type_bit_maps() {
                text.push_str(&format!(" {}", record_type(kind)));
            }
            text
        }
        RData::ANAME(name) => name.0.to_ascii(),
        RData::CNAME(name) => name.0.to_ascii(),
        RData::NS(name) => name.0.to_ascii(),
        RData::PTR(name) => name.0.to_ascii(),
        RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange.to_ascii()),
        RData::HTTPS(HTTPS(svcb)) | RData::SVCB(svcb) => {
            let mut text = format!("{} {}", svcb.svc_priority, svcb.target_name.to_ascii());
            for (key, value) in &svcb.svc_params {
                text.push_str(&format!(" {key}={value}"));
            }
            text
        }
        RData::NAPTR(naptr) => format!(
            "{} {} {} {} {} {}",
            naptr.order,
            naptr.preference,
            txt_string(&naptr.flags),
            txt_string(&naptr.services),
            txt_string(&naptr.regexp),
            naptr.replacement.to_ascii()
        ),
        RData::SRV(srv) => format!(
            "{} {} {} {}",
            srv.priority,
            srv.weight,
            srv.port,
            srv.target.to_ascii()
        ),
        // RFC 1035 timers are unsigned, though hickory stores some as i32.
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname.to_ascii(),
            soa.rname.to_ascii(),
            soa.serial,
            soa.refresh.cast_unsigned(),
            soa.retry.cast_unsigned(),
            soa.expire.cast_unsigned(),
            soa.minimum
        ),
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|bytes| txt_string(bytes))
            .collect::<Vec<_>>()
            .join(" "),
        _ => data.to_string(),
    }
}

fn signature_value(signature: &SIG, full_signature: bool) -> String {
    let input = signature.input();
    let mut text = format!(
        "{} · {} ({}) · key {} · signer {} · from {} · until {}",
        record_type(input.type_covered),
        input.algorithm,
        u8::from(input.algorithm),
        input.key_tag,
        input.signer_name.to_ascii(),
        signature_date(input.sig_inception.get()),
        signature_date(input.sig_expiration.get())
    );

    if full_signature {
        text.push_str(&format!(
            " · labels {} · original TTL {}s · signature {}",
            input.num_labels,
            input.original_ttl,
            data_encoding::BASE64.encode(signature.sig())
        ));
    }

    text
}

fn signature_date(seconds: u32) -> String {
    chrono::DateTime::from_timestamp(i64::from(seconds), 0)
        .expect("u32 timestamps fit chrono")
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Quotes a TXT character-string like zone files do, escaping bytes that are not safe text.
fn txt_string(bytes: &[u8]) -> String {
    let mut text = String::from('"');

    for chunk in bytes.utf8_chunks() {
        for character in chunk.valid().chars() {
            match character {
                '"' | '\\' => {
                    text.push('\\');
                    text.push(character);
                }
                _ if is_unsafe(character) => {
                    for byte in character.encode_utf8(&mut [0; 4]).bytes() {
                        text.push_str(&format!("\\{byte:03}"));
                    }
                }
                _ => text.push(character),
            }
        }
        for byte in chunk.invalid() {
            text.push_str(&format!("\\{byte:03}"));
        }
    }

    text.push('"');
    text
}

/// DNS data is untrusted. Control characters could move the cursor or inject terminal
/// escape sequences. Bidirectional overrides and invisible format characters could reorder
/// or hide what is displayed.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());

    for character in text.chars() {
        if is_unsafe(character) {
            escaped.push_str(&format!("\\u{{{:x}}}", u32::from(character)));
        } else {
            escaped.push(character);
        }
    }

    escaped
}

fn is_unsafe(character: char) -> bool {
    character.is_control()
        || matches!(
            character,
            '\u{00ad}'
                | '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{2064}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{e0000}'..='\u{e007f}'
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escape_neutralizes_terminal_control() {
        assert_eq!(
            escape("a\nb\u{1b}[2J\u{9b}\u{7f}\u{202e}"),
            "a\\u{a}b\\u{1b}[2J\\u{9b}\\u{7f}\\u{202e}"
        );
    }

    #[test]
    fn txt_strings_are_quoted_and_escaped() {
        assert_eq!(txt_string(b"say \"hi\"\n"), r#""say \"hi\"\010""#);
        assert_eq!(txt_string(b"\xff caf\xc3\xa9"), r#""\255 café""#);
    }
}
