mod cli;
mod dns;
mod location;
mod output;
mod trace;

use std::error::Error;
use std::process::ExitCode;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let result = match cli::Args::parse_into() {
        cli::Command::UpdateDb(kind) => location::update(kind).await,
        cli::Command::Query(options) => run(options).await,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("digr: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(options: cli::QueryOptions) -> Result<(), Box<dyn Error>> {
    let mut output = output::Output::new(
        &options.query,
        options.trace,
        options.verbose,
        options.json,
        options.location || options.asn,
    );
    let databases = load_databases(options.location, options.asn, &mut output).await;

    let result = if options.trace {
        run_trace(options.query, &databases, &mut output).await
    } else {
        run_lookup(options.query, &databases, &mut output).await
    };
    output.finish(
        result.as_ref().err().map(|error| error.as_ref()),
        &databases,
    )?;

    result
}

async fn load_databases(
    location: bool,
    asn: bool,
    output: &mut output::Output,
) -> Vec<location::Database> {
    let mut databases = Vec::new();
    for (enabled, kind) in [(location, location::Kind::City), (asn, location::Kind::Asn)] {
        if !enabled {
            continue;
        }

        let mut progress = output::DownloadProgress::new(kind);
        let result =
            location::Database::load(kind, |length, received| progress.update(length, received))
                .await;
        drop(progress);

        match result {
            Ok(database) => {
                if let Err(error) = database.refresh_if_stale() {
                    eprintln!("digr: unable to start DB-IP {kind} update: {error}");
                }
                databases.push(database);
            }
            Err(error) => output.warn(
                output::json::WarningCode::EnrichmentUnavailable,
                format!("{kind} information unavailable: {error}. Continuing without it."),
            ),
        }
    }

    databases
}

async fn run_trace(
    query: dns::Query,
    databases: &[location::Database],
    output: &mut output::Output,
) -> Result<(), Box<dyn Error>> {
    let mut trace = trace::Trace::new(query);

    while let Some(hop) = trace.next().await? {
        output.hop(hop, databases)?;
    }

    Ok(())
}

async fn run_lookup(
    query: dns::Query,
    databases: &[location::Database],
    output: &mut output::Output,
) -> Result<(), Box<dyn Error>> {
    let mut responses = Vec::new();
    let result = query.lookup(&mut responses).await;

    output.lookup(&responses, databases)?;

    result.map_err(Into::into)
}
