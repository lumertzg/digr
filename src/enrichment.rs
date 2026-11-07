use hickory_resolver::proto::rr::Record;

use crate::dns::Response;
use crate::location::{Database, Information, Kind};

pub struct EnrichedRecord<'a> {
    pub record: &'a Record,
    /// Empty when not applicable or not requested. None means an attempted lookup had no result.
    pub information: Vec<(Kind, Option<Information>)>,
}

pub struct EnrichedResponse<'a> {
    pub response: &'a Response,
    pub kinds: Vec<Kind>,
    pub answers: Vec<EnrichedRecord<'a>>,
    pub authority: Vec<EnrichedRecord<'a>>,
    pub additional: Vec<EnrichedRecord<'a>>,
}

impl<'a> EnrichedResponse<'a> {
    pub fn new(
        response: &'a Response,
        databases: &[Database],
        all_sections: bool,
        mut warn: impl FnMut(String),
    ) -> Self {
        let message = response.message();
        let mut prepare = |records: &'a [Record], visible: bool| {
            records
                .iter()
                .map(|record| {
                    let information = record
                        .data
                        .ip_addr()
                        .filter(|_| visible)
                        .into_iter()
                        .flat_map(|ip| databases.iter().map(move |database| (ip, database)))
                        .map(|(ip, database)| {
                            let information = database.lookup(ip).unwrap_or_else(|error| {
                                warn(format!(
                                    "{} lookup for {ip} failed: {error}",
                                    database.kind()
                                ));
                                None
                            });
                            (database.kind(), information)
                        })
                        .collect();

                    EnrichedRecord {
                        record,
                        information,
                    }
                })
                .collect()
        };

        Self {
            response,
            kinds: databases.iter().map(Database::kind).collect(),
            answers: prepare(&message.answers, true),
            authority: prepare(
                &message.authorities,
                all_sections || message.answers.is_empty(),
            ),
            additional: prepare(&message.additionals, all_sections),
        }
    }
}
