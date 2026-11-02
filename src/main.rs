mod cli;
mod dns;
mod enrichment;
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
        &options.question,
        &options.settings,
        options.trace,
        options.verbose,
        options.json,
        options.location || options.asn,
    );
    let databases = load_databases(options.location, options.asn, &mut output).await;

    let result = if options.trace {
        run_trace(&options, &databases, &mut output).await
    } else {
        run_lookup(&options, &databases, &mut output).await
    };

    let finished = output.finish(
        result.as_ref().err().map(|error| error.as_ref()),
        &databases,
    );

    // The DNS failure matters more than a failure to print it.
    result?;
    finished
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
        let result = location::Database::load(kind, |event| progress.update(event)).await;
        drop(progress);

        match result {
            Ok(database) => {
                if let Err(error) = database.refresh_if_stale() {
                    output.warn(
                        output::json::WarningCode::UpdateFailed,
                        format!("unable to start DB-IP {kind} update: {error}"),
                    );
                }
                databases.push(database);
            }
            Err(error) => output.warn(
                output::json::WarningCode::Unavailable,
                format!("{kind} information unavailable: {error}. Continuing without it."),
            ),
        }
    }

    databases
}

async fn run_trace(
    options: &cli::QueryOptions,
    databases: &[location::Database],
    output: &mut output::Output,
) -> Result<(), Box<dyn Error>> {
    let mut trace = trace::Trace::new(
        &options.question,
        &options.settings,
        options.server.as_deref(),
    )?;

    while let Some(hop) = trace.next().await? {
        let enriched = enrichment::EnrichedResponse::new(
            &hop.response,
            databases,
            options.json || options.verbose,
            |message| output.warn(output::json::WarningCode::LookupFailed, message),
        );
        output.hop(enriched, hop.number)?;
    }

    Ok(())
}

async fn run_lookup(
    options: &cli::QueryOptions,
    databases: &[location::Database],
    output: &mut output::Output,
) -> Result<(), Box<dyn Error>> {
    let mut responses = Vec::new();
    let result = dns::lookup(
        options.question.clone(),
        &options.settings,
        options.server.as_deref(),
        &mut responses,
    )
    .await;

    let printed = responses
        .iter()
        .enumerate()
        .try_for_each(|(index, response)| {
            let enriched = enrichment::EnrichedResponse::new(
                response,
                databases,
                options.json || options.verbose,
                |message| output.warn(output::json::WarningCode::LookupFailed, message),
            );

            output.lookup(enriched, index)
        });

    // The DNS failure matters more than a failure to print it.
    result?;
    printed
}
