use std::env;
use std::error::Error;
use std::io::{self, IsTerminal, Write};

use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::Record;
use indicatif::{ProgressBar, ProgressStyle};
use tabled::builder::Builder;
use tabled::grid::util::string::get_line_width;
use tabled::settings::{
    Alignment, Color, Padding, Style, Width,
    formatting::Charset,
    object::{Cell, Columns, Rows},
    style::BorderColor,
};

use crate::dns::{Query, Response};
use crate::location::{Database, Kind};
use crate::trace::Hop;

pub mod json;

pub struct Output {
    verbose: bool,
    document: Option<json::Document>,
}

impl Output {
    pub fn new(query: &Query, trace: bool, verbose: bool, json: bool, enrich: bool) -> Self {
        Self {
            verbose,
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
            print_lookup(responses, self.verbose, databases)?;
        }

        Ok(())
    }

    pub fn hop(&mut self, hop: &Hop, databases: &[Database]) -> Result<(), Box<dyn Error>> {
        if let Some(document) = &mut self.document {
            document.push(&hop.response, Some(hop.number), databases)?;
        } else {
            print_hop(hop, self.verbose, databases)?;
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

fn print_lookup(responses: &[Response], verbose: bool, databases: &[Database]) -> io::Result<()> {
    for (index, response) in responses.iter().enumerate() {
        let question = &response.message.queries[0];

        if index > 0 {
            writeln!(io::stdout().lock())?;
        }

        let title = format!("{} {}", question.name(), question.query_type());
        print_response(response, &title, verbose, databases)?;
    }

    Ok(())
}

fn print_records(records: &[Record], databases: &[Database]) -> io::Result<()> {
    let mut builder = Builder::default();
    let enrich =
        !databases.is_empty() && records.iter().any(|record| record.data.ip_addr().is_some());
    let mut header = vec!["Name", "Type", "TTL (s)", "Value"];
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
        let mut row = vec![
            record.name.to_string(),
            record.data.record_type().to_string(),
            record.ttl.to_string(),
            record.data.to_string(),
        ];
        if enrich {
            for database in databases {
                let value = record.data.ip_addr().map(|ip| {
                    database
                        .lookup(ip)
                        .unwrap_or_else(|error| {
                            eprintln!("digr: {} lookup for {ip} failed: {error}", database.kind);
                            None
                        })
                        .map(|information| information.to_string())
                        .unwrap_or_else(|| "—".to_owned())
                });
                row.push(value.unwrap_or_else(|| "—".to_owned()));
            }
        }
        builder.push_record(row);
    }

    let mut table = builder.build();
    table.with((Style::sharp(), Charset::new().clean()));
    table.with(Alignment::left());
    table.modify(Columns::one(2), Alignment::right());

    if let Some((terminal_size::Width(width), _)) = terminal_size::terminal_size_of(io::stdout())
        && table.total_width() > usize::from(width)
    {
        return print_stacked(Builder::from(table).into(), usize::from(width));
    }

    if colors_enabled() {
        table.with(BorderColor::filled(Color::FG_BRIGHT_BLACK));
        table.modify(Columns::one(0), Color::FG_BRIGHT_BLACK);
        table.modify(Columns::one(1), Color::FG_CYAN);
        table.modify(Columns::one(2), Color::FG_BRIGHT_BLACK);
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
        table.with((Style::empty(), Charset::new().clean()));
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

fn print_hop(hop: &Hop, verbose: bool, databases: &[Database]) -> io::Result<()> {
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
        databases,
    )
}

fn print_response(
    response: &Response,
    title: &str,
    verbose: bool,
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
    print_line(&format!("{title} · {status}"), color | Color::BOLD)?;
    print_line(
        &format!(
            "Server {} · {} · {:.1} ms",
            response.server,
            if response.tcp { "TCP" } else { "UDP" },
            response.elapsed.as_secs_f64() * 1000.0
        ),
        Color::FG_BRIGHT_BLACK,
    )?;

    if verbose {
        print_flags(response)?;
    }
    writeln!(io::stdout().lock())?;

    if verbose {
        for (name, records) in [
            ("Answer", &message.answers),
            ("Authority", &message.authorities),
            ("Additional", &message.additionals),
        ] {
            if !records.is_empty() {
                print_section(name, records, databases)?;
            }
        }
    } else if !message.answers.is_empty() {
        print_records(&message.answers, databases)?;
    } else if !message.authorities.is_empty() {
        print_section("Authority", &message.authorities, databases)?;
    }

    if message.answers.is_empty()
        && message.authorities.is_empty()
        && (!verbose || message.additionals.is_empty())
    {
        print_line("No answer records.", Color::FG_BRIGHT_BLACK)?;
    }

    Ok(())
}

fn print_flags(response: &Response) -> io::Result<()> {
    let metadata = &response.message.metadata;
    let flags = [
        (metadata.authoritative, "AA"),
        (metadata.truncation, "TC"),
        (metadata.recursion_desired, "RD"),
        (metadata.recursion_available, "RA"),
        (metadata.authentic_data, "AD (server-asserted)"),
        (metadata.checking_disabled, "CD"),
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
                flags.join(" ")
            }
        ),
        Color::FG_BRIGHT_BLACK,
    )
}

fn print_section(name: &str, records: &[Record], databases: &[Database]) -> io::Result<()> {
    print_line(
        &format!("{name} · {}", records.len()),
        Color::FG_GREEN | Color::BOLD,
    )?;
    print_records(records, databases)
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

    pub fn update(&mut self, length: Option<u64>, received: u64) {
        let bar = self
            .bar
            .get_or_insert_with(|| download_progress(self.kind, length));
        bar.set_position(received);
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
