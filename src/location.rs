use std::error::Error;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use chrono::{DateTime, Months, Utc};
use directories::ProjectDirs;
use flate2::read::GzDecoder;
use maxminddb::{Reader, geoip2};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use tempfile::NamedTempFile;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const RETRY_INTERVAL: i64 = 24 * 60 * 60;

pub enum Progress {
    /// Another process holds the install lock.
    Waiting,
    Download {
        length: Option<u64>,
        received: u64,
    },
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    City,
    Asn,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::City => "city",
            Self::Asn => "asn",
        }
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for Kind {
    type Err = &'static str;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "city" => Ok(Self::City),
            "asn" => Ok(Self::Asn),
            _ => Err("expected city or asn"),
        }
    }
}

pub struct Database {
    pub kind: Kind,
    reader: Reader<Vec<u8>>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum Information {
    Location {
        city: Option<String>,
        country_code: Option<String>,
    },
    Asn {
        number: Option<u32>,
        organization: Option<String>,
    },
}

impl std::fmt::Display for Information {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let parts: Vec<String> = match self {
            Self::Location { city, country_code } => {
                city.iter().chain(country_code).cloned().collect()
            }
            Self::Asn {
                number,
                organization,
            } => number
                .map(|number| format!("AS{number}"))
                .into_iter()
                .chain(organization.iter().cloned())
                .collect(),
        };

        formatter.write_str(&if parts.is_empty() {
            "—".to_owned()
        } else {
            parts.join(" · ")
        })
    }
}

impl Database {
    pub async fn load(kind: Kind, mut progress: impl FnMut(Progress)) -> Result<Self> {
        let (path, state_path) = paths(kind)?;
        if let Ok(reader) = open(&path, kind) {
            return Ok(Self { kind, reader });
        }

        let lock = state_file(&state_path)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                progress(Progress::Waiting);
                lock.lock()?;
            }
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }

        // Another first-use process may have installed the database while we waited.
        // A first install is user-requested, so unlike background refreshes it is not rate-limited.
        let reader = match open(&path, kind) {
            Ok(reader) => reader,
            Err(_) => install(&path, kind, &release_months(None, Utc::now()), progress).await?,
        };

        Ok(Self { kind, reader })
    }

    pub fn refresh_if_stale(&self) -> Result<()> {
        let (_, state_path) = paths(self.kind)?;

        if stale(&self.reader)
            && !fs::read_to_string(&state_path).is_ok_and(|value| recent_attempt(&value))
        {
            start_updater(self.kind)?;
        }

        Ok(())
    }

    pub fn description(&self) -> String {
        let date = self.build_date().unwrap_or_else(|| "unknown".to_owned());

        match self.kind {
            Kind::City => format!("Approximate IP locations · City {date}"),
            Kind::Asn => format!("IP network information · ASN {date}"),
        }
    }

    pub fn build_date(&self) -> Option<String> {
        build_time(&self.reader).map(|date| date.format("%Y-%m-%d").to_string())
    }

    pub fn lookup(&self, ip: IpAddr) -> Result<Option<Information>> {
        let result = self.reader.lookup(ip)?;

        match self.kind {
            Kind::City => Ok(result
                .decode::<geoip2::City>()?
                .map(|city| Information::Location {
                    city: city.city.names.english.map(str::to_owned),
                    country_code: city
                        .country
                        .iso_code
                        .filter(|code| *code != "ZZ")
                        .map(str::to_owned),
                })),
            Kind::Asn => Ok(result.decode::<geoip2::Asn>()?.map(|asn| Information::Asn {
                number: asn.autonomous_system_number,
                organization: asn.autonomous_system_organization.map(str::to_owned),
            })),
        }
    }
}

pub async fn update(kind: Kind) -> Result<()> {
    let (path, state_path) = paths(kind)?;
    let mut lock = state_file(&state_path)?;

    match lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(()),
        Err(TryLockError::Error(error)) => return Err(error.into()),
    }

    let installed = open(&path, kind).ok();
    if installed.as_ref().is_some_and(|reader| !stale(reader)) || !begin_attempt(&mut lock)? {
        return Ok(());
    }

    let installed = installed.as_ref().map(release_month);
    let months = release_months(installed.as_deref(), Utc::now());
    install(&path, kind, &months, |_| {}).await?;

    Ok(())
}

/// Returns the database and its lock and state file.
fn paths(kind: Kind) -> Result<(PathBuf, PathBuf)> {
    let path = cache_directory()?.join(format!("dbip-{kind}-lite.mmdb"));
    let state_path = path.with_extension("state");

    Ok((path, state_path))
}

fn cache_directory() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("", "", "digr").ok_or("cannot determine user cache directory")?;
    let directory = dirs.cache_dir().join("geoip");
    fs::create_dir_all(&directory)?;

    Ok(directory)
}

fn state_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn build_time(reader: &Reader<Vec<u8>>) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(reader.metadata().build_epoch as i64, 0)
}

/// DB-IP builds each monthly release on its first day, so the build month names the release.
fn release_month(reader: &Reader<Vec<u8>>) -> String {
    build_time(reader)
        .map(|date| date.format("%Y-%m").to_string())
        .unwrap_or_default()
}

/// A newer monthly release may exist once the calendar passes the installed release's month.
fn stale(reader: &Reader<Vec<u8>>) -> bool {
    release_month(reader) < Utc::now().format("%Y-%m").to_string()
}

/// Release months newer than the installed one, newest first. Publication may lag the
/// calendar, so the previous month is a fallback.
fn release_months(installed: Option<&str>, now: DateTime<Utc>) -> Vec<String> {
    [now, now - Months::new(1)]
        .iter()
        .map(|date| date.format("%Y-%m").to_string())
        .filter(|month| installed.is_none_or(|installed| month.as_str() > installed))
        .collect()
}

fn recent_attempt(value: &str) -> bool {
    value
        .parse::<i64>()
        .ok()
        .and_then(|timestamp| Utc::now().timestamp().checked_sub(timestamp))
        .is_some_and(|elapsed| (0..RETRY_INTERVAL).contains(&elapsed))
}

fn begin_attempt(state: &mut File) -> io::Result<bool> {
    let mut value = String::new();
    state.read_to_string(&mut value)?;
    if recent_attempt(&value) {
        return Ok(false);
    }

    // Keep all access on the locked handle, and record failed attempts too.
    state.set_len(0)?;
    state.rewind()?;
    write!(state, "{}", Utc::now().timestamp())?;
    state.flush()?;

    Ok(true)
}

fn start_updater(kind: Kind) -> io::Result<()> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["update-db", kind.as_str()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;

        const DETACHED_PROCESS: u32 = 0x0000_0008;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }

    let mut child = command.spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });

    Ok(())
}

fn open(path: &Path, kind: Kind) -> Result<Reader<Vec<u8>>> {
    let reader = Reader::open_readfile(path)
        .map_err(|error| format!("opening {}: {error}", path.display()))?;
    if !reader
        .metadata()
        .database_type
        .to_ascii_lowercase()
        .contains(kind.as_str())
    {
        return Err(format!(
            "unexpected database type: {}",
            reader.metadata().database_type
        )
        .into());
    }

    Ok(reader)
}

async fn install(
    path: &Path,
    kind: Kind,
    months: &[String],
    mut progress: impl FnMut(Progress),
) -> Result<Reader<Vec<u8>>> {
    let client = Client::builder()
        .user_agent(concat!("digr/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(300))
        .https_only(true)
        .build()?;
    let mut response = None;

    // Try older releases on 404 only.
    for month in months {
        let url = format!("https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz");
        let candidate = client.get(url).send().await?;
        if candidate.status() != StatusCode::NOT_FOUND {
            response = Some(candidate.error_for_status()?);
            break;
        }
    }

    let mut response = response.ok_or("no new monthly release is available yet")?;
    let length = response.content_length();
    let mut compressed = Vec::new();
    progress(Progress::Download {
        length,
        received: 0,
    });

    while let Some(chunk) = response.chunk().await? {
        if compressed.len() + chunk.len() > 256 * 1024 * 1024 {
            return Err("database download exceeds 256 MiB".into());
        }
        compressed.extend_from_slice(&chunk);
        progress(Progress::Download {
            length,
            received: compressed.len() as u64,
        });
    }

    let mut file = NamedTempFile::new_in(path.parent().ok_or("missing cache directory")?)?;
    let mut decoder = GzDecoder::new(compressed.as_slice()).take(512 * 1024 * 1024 + 1);
    if io::copy(&mut decoder, &mut file)? > 512 * 1024 * 1024 {
        return Err("expanded database exceeds 512 MiB".into());
    }
    file.as_file().sync_all()?;

    let reader = open(file.path(), kind)?;
    reader.verify()?;

    file.persist(path)?;

    Ok(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn date(value: &str) -> DateTime<Utc> {
        value.parse().unwrap()
    }

    #[test]
    fn release_months_skip_the_installed_release() {
        let now = date("2026-10-31T00:00:00Z");

        assert_eq!(release_months(None, now), ["2026-10", "2026-09"]);
        assert_eq!(release_months(Some("2026-09"), now), ["2026-10"]);
        assert!(release_months(Some("2026-10"), now).is_empty());
    }
}
