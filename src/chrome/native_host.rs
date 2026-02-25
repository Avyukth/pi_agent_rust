use std::collections::HashMap;
use std::fs;
use std::io::{Read as IoRead, Write as IoWrite};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use asupersync::io::AsyncReadExt;
use asupersync::net::unix::UnixListener;
use thiserror::Error;
use uuid::Uuid;

use super::{DiscoveryRecord, protocol};

const DEFAULT_NATIVE_HOST_DIR: &str = "/tmp";
const DEFAULT_LEASE_TTL_MS: u64 = 30_000;
const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;
const SOCKET_PREFIX: &str = "pi-chrome-";
const SOCKET_SUFFIX: &str = ".sock";
const DISCOVERY_PREFIX: &str = "pi-chrome-host-";
const DISCOVERY_SUFFIX: &str = ".discovery.json";
const DEFAULT_REQUEST_JOURNAL_TTL_MS: i64 = 60_000;
const MAX_JOURNAL_ENTRIES: usize = 256;
const MAX_JOURNAL_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_AGENT_MAX_RECONNECT_ATTEMPTS: i64 = 3;
const DEFAULT_AGENT_SOCKET_TIMEOUT_MS: i64 = 5_000;
const JOURNAL_TTL_COUPLING_SAFETY_MARGIN_MS: i64 = 10_000;

#[derive(Debug, Clone)]
pub struct NativeHostConfig {
    pub discovery_dir: PathBuf,
    pub socket_dir: PathBuf,
    pub host_id: Option<String>,
    pub host_epoch: Option<String>,
    pub token: Option<String>,
    pub lease_ttl_ms: u64,
    pub idle_timeout_ms: u64,
    pub capabilities: Vec<String>,
}

impl NativeHostConfig {
    #[must_use]
    pub fn new() -> Self {
        Self {
            discovery_dir: PathBuf::from(DEFAULT_NATIVE_HOST_DIR),
            socket_dir: PathBuf::from(DEFAULT_NATIVE_HOST_DIR),
            host_id: None,
            host_epoch: None,
            token: None,
            lease_ttl_ms: DEFAULT_LEASE_TTL_MS,
            idle_timeout_ms: DEFAULT_IDLE_TIMEOUT_MS,
            capabilities: vec!["browser_tools".to_string(), "observations".to_string()],
        }
    }
}

impl Default for NativeHostConfig {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeHostRunOutcome {
    IdleTimeout,
    AgentConnected,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct EslJournalKey {
    pi_session_id: String,
    request_id: String,
    host_epoch: String,
}

#[derive(Debug, Clone)]
struct EslJournalEntry {
    fingerprint: protocol::RequestFingerprint,
    state: EslJournalState,
    created_at_ms: i64,
    last_access_ms: i64,
    approx_bytes: usize,
}

#[derive(Debug, Clone)]
enum EslJournalState {
    InProgress,
    Terminal(protocol::ResponseEnvelope),
}

#[derive(Debug, Clone)]
struct EslJournal {
    ttl_ms: i64,
    max_entries: usize,
    max_bytes: usize,
    current_bytes: usize,
    entries: HashMap<EslJournalKey, EslJournalEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EslBeginOutcome {
    Dispatch,
    Replay(protocol::ResponseEnvelope),
    Reject(protocol::ResponseEnvelope),
}

impl EslJournal {
    fn new(lease_ttl_ms: u64) -> Result<Self, NativeHostError> {
        let min_ttl_ms = i64::try_from(lease_ttl_ms)
            .unwrap_or(i64::MAX)
            .saturating_add(
                (DEFAULT_AGENT_MAX_RECONNECT_ATTEMPTS + 1)
                    .saturating_mul(DEFAULT_AGENT_SOCKET_TIMEOUT_MS)
                    .saturating_add(JOURNAL_TTL_COUPLING_SAFETY_MARGIN_MS),
            );
        if DEFAULT_REQUEST_JOURNAL_TTL_MS < min_ttl_ms {
            return Err(NativeHostError::EslInvariant(format!(
                "request journal ttl {DEFAULT_REQUEST_JOURNAL_TTL_MS}ms violates coupling invariant (min {min_ttl_ms}ms)"
            )));
        }
        Ok(Self {
            ttl_ms: DEFAULT_REQUEST_JOURNAL_TTL_MS,
            max_entries: MAX_JOURNAL_ENTRIES,
            max_bytes: MAX_JOURNAL_BYTES,
            current_bytes: 0,
            entries: HashMap::new(),
        })
    }

    #[cfg(test)]
    fn with_limits_for_test(ttl_ms: i64, max_entries: usize, max_bytes: usize) -> Self {
        Self {
            ttl_ms,
            max_entries,
            max_bytes,
            current_bytes: 0,
            entries: HashMap::new(),
        }
    }

    fn begin_request(
        &mut self,
        pi_session_id: &str,
        host_epoch: &str,
        request: &protocol::Request,
        now_ms: i64,
    ) -> Result<EslBeginOutcome, NativeHostError> {
        self.prune_expired_terminal_entries(now_ms);

        let key = EslJournalKey {
            pi_session_id: pi_session_id.to_string(),
            request_id: request.id.clone(),
            host_epoch: host_epoch.to_string(),
        };
        let fingerprint = protocol::RequestFingerprint::new(&request.op, &request.payload)
            .map_err(NativeHostError::Fingerprint)?;

        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_access_ms = now_ms;
            if entry.fingerprint != fingerprint {
                return Ok(EslBeginOutcome::Reject(invalid_request_envelope(
                    &request.id,
                    "request_id reused with different op/payload",
                )));
            }
            return Ok(match &entry.state {
                EslJournalState::InProgress => EslBeginOutcome::Reject(in_progress_envelope(
                    &request.id,
                    "in_progress: request still executing",
                )),
                EslJournalState::Terminal(envelope) => EslBeginOutcome::Replay(envelope.clone()),
            });
        }

        let new_entry_bytes = approx_in_progress_entry_bytes(&key, &fingerprint);
        if !self.ensure_capacity_for_new_entry(new_entry_bytes, now_ms) {
            tracing::warn!(
                event = "pi.chrome.esl.reject_indeterminate_capacity",
                pi_session_id,
                request_id = %request.id,
                host_epoch,
                max_entries = self.max_entries,
                max_bytes = self.max_bytes,
                current_entries = self.entries.len(),
                current_bytes = self.current_bytes,
                "Rejecting request because ESL caps can only be satisfied by evicting in_progress entries"
            );
            return Ok(EslBeginOutcome::Reject(execution_indeterminate_envelope(
                &request.id,
                "esl journal capacity reached with only in_progress entries",
            )));
        }

        let entry = EslJournalEntry {
            fingerprint,
            state: EslJournalState::InProgress,
            created_at_ms: now_ms,
            last_access_ms: now_ms,
            approx_bytes: new_entry_bytes,
        };
        self.current_bytes = self.current_bytes.saturating_add(new_entry_bytes);
        self.entries.insert(key, entry);
        Ok(EslBeginOutcome::Dispatch)
    }

    fn record_terminal_response(
        &mut self,
        pi_session_id: &str,
        host_epoch: &str,
        request: &protocol::Request,
        response: &protocol::ResponseEnvelope,
        now_ms: i64,
    ) -> Result<(), NativeHostError> {
        let key = EslJournalKey {
            pi_session_id: pi_session_id.to_string(),
            request_id: request.id.clone(),
            host_epoch: host_epoch.to_string(),
        };
        let Some(entry) = self.entries.get_mut(&key) else {
            return Ok(());
        };

        let fingerprint = protocol::RequestFingerprint::new(&request.op, &request.payload)
            .map_err(NativeHostError::Fingerprint)?;
        if entry.fingerprint != fingerprint {
            tracing::warn!(
                event = "pi.chrome.esl.record_terminal_fingerprint_mismatch",
                pi_session_id,
                request_id = %request.id,
                host_epoch,
                "Skipping terminal ESL update because request fingerprint mismatched existing entry"
            );
            return Ok(());
        }

        self.current_bytes = self.current_bytes.saturating_sub(entry.approx_bytes);
        entry.state = EslJournalState::Terminal(response.clone());
        entry.last_access_ms = now_ms;
        entry.approx_bytes = approx_terminal_entry_bytes(&key, &entry.fingerprint, response);
        self.current_bytes = self.current_bytes.saturating_add(entry.approx_bytes);

        let _ = self.ensure_capacity_for_new_entry(0, now_ms);
        Ok(())
    }

    #[cfg(test)]
    fn contains_key(&self, pi_session_id: &str, request_id: &str, host_epoch: &str) -> bool {
        self.entries.contains_key(&EslJournalKey {
            pi_session_id: pi_session_id.to_string(),
            request_id: request_id.to_string(),
            host_epoch: host_epoch.to_string(),
        })
    }

    #[cfg(test)]
    fn terminal_count(&self) -> usize {
        self.entries
            .values()
            .filter(|entry| matches!(entry.state, EslJournalState::Terminal(_)))
            .count()
    }

    fn prune_expired_terminal_entries(&mut self, now_ms: i64) {
        if self.ttl_ms <= 0 {
            return;
        }
        let mut expired = Vec::new();
        for (key, entry) in &self.entries {
            let is_terminal = matches!(entry.state, EslJournalState::Terminal(_));
            if is_terminal && now_ms.saturating_sub(entry.last_access_ms) >= self.ttl_ms {
                expired.push(key.clone());
            }
        }
        for key in expired {
            self.remove_entry(&key);
        }
    }

    fn ensure_capacity_for_new_entry(&mut self, additional_bytes: usize, now_ms: i64) -> bool {
        self.prune_expired_terminal_entries(now_ms);
        while self
            .entries
            .len()
            .saturating_add(usize::from(additional_bytes > 0))
            > self.max_entries
            || self.current_bytes.saturating_add(additional_bytes) > self.max_bytes
        {
            let Some(evict_key) = self.oldest_terminal_key() else {
                return false;
            };
            tracing::debug!(
                event = "pi.chrome.esl.evict_terminal",
                request_id = %evict_key.request_id,
                host_epoch = %evict_key.host_epoch,
                "Evicting terminal ESL entry to satisfy caps"
            );
            self.remove_entry(&evict_key);
        }
        true
    }

    fn oldest_terminal_key(&self) -> Option<EslJournalKey> {
        self.entries
            .iter()
            .filter_map(|(key, entry)| {
                if matches!(entry.state, EslJournalState::Terminal(_)) {
                    Some((key, entry.last_access_ms))
                } else {
                    None
                }
            })
            .min_by(|(a_key, a_ts), (b_key, b_ts)| {
                a_ts.cmp(b_ts)
                    .then_with(|| a_key.request_id.cmp(&b_key.request_id))
            })
            .map(|(key, _)| key.clone())
    }

    fn remove_entry(&mut self, key: &EslJournalKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.current_bytes = self.current_bytes.saturating_sub(entry.approx_bytes);
        }
    }
}

#[derive(Debug)]
pub struct NativeHost {
    config: NativeHostConfig,
    host_id: String,
    host_epoch: String,
    token: String,
    socket_path: PathBuf,
    discovery_path: PathBuf,
    claimed_by: Option<protocol::ClaimedBy>,
    listener: Option<UnixListener>,
    journal: EslJournal,
}

impl NativeHost {
    pub fn new(config: NativeHostConfig) -> Result<Self, NativeHostError> {
        let host_id = config.host_id.clone().unwrap_or_else(random_id);
        let host_epoch = config.host_epoch.clone().unwrap_or_else(random_id);
        let token = config.token.clone().unwrap_or_else(random_token);
        let journal = EslJournal::new(config.lease_ttl_ms)?;
        let socket_path = config
            .socket_dir
            .join(format!("{SOCKET_PREFIX}{host_id}{SOCKET_SUFFIX}"));
        let discovery_path = config
            .discovery_dir
            .join(format!("{DISCOVERY_PREFIX}{host_id}{DISCOVERY_SUFFIX}"));

        Ok(Self {
            config,
            host_id,
            host_epoch,
            token,
            socket_path,
            discovery_path,
            claimed_by: None,
            listener: None,
            journal,
        })
    }

    #[must_use]
    pub fn host_id(&self) -> &str {
        &self.host_id
    }

    #[must_use]
    pub fn host_epoch(&self) -> &str {
        &self.host_epoch
    }

    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub fn discovery_path(&self) -> &Path {
        &self.discovery_path
    }

    #[must_use]
    pub const fn claimed_by(&self) -> Option<&protocol::ClaimedBy> {
        self.claimed_by.as_ref()
    }

    pub async fn startup(&mut self) -> Result<(), NativeHostError> {
        if self.listener.is_some() {
            return Ok(());
        }

        fs::create_dir_all(&self.config.socket_dir).map_err(|source| NativeHostError::Io {
            path: self.config.socket_dir.clone(),
            source,
        })?;
        fs::create_dir_all(&self.config.discovery_dir).map_err(|source| NativeHostError::Io {
            path: self.config.discovery_dir.clone(),
            source,
        })?;

        let listener = UnixListener::bind(&self.socket_path)
            .await
            .map_err(|source| NativeHostError::Io {
                path: self.socket_path.clone(),
                source,
            })?;
        set_owner_only_permissions(&self.socket_path)?;

        self.listener = Some(listener);
        self.write_discovery_record()?;
        Ok(())
    }

    pub async fn run_until_idle_for_test(
        &mut self,
    ) -> Result<NativeHostRunOutcome, NativeHostError> {
        self.startup().await?;
        let listener = self
            .listener
            .as_ref()
            .expect("listener initialized by startup");
        let timeout = Duration::from_millis(self.config.idle_timeout_ms.max(1));
        let accept_result = asupersync::time::timeout(
            asupersync::time::wall_now(),
            timeout,
            Box::pin(listener.accept()),
        )
        .await;

        match accept_result {
            Ok(Ok((_stream, _addr))) => Ok(NativeHostRunOutcome::AgentConnected),
            Ok(Err(source)) => Err(NativeHostError::Io {
                path: self.socket_path.clone(),
                source,
            }),
            Err(_timeout) => Ok(NativeHostRunOutcome::IdleTimeout),
        }
    }

    pub async fn run(&mut self) -> Result<NativeHostRunOutcome, NativeHostError> {
        let mut stdin = std::io::stdin();
        let mut stdout = std::io::stdout();
        self.run_with_io(&mut stdin, &mut stdout).await
    }

    pub async fn run_with_io<R: IoRead, W: IoWrite>(
        &mut self,
        chrome_reader: &mut R,
        chrome_writer: &mut W,
    ) -> Result<NativeHostRunOutcome, NativeHostError> {
        self.startup().await?;
        let listener = self
            .listener
            .as_ref()
            .expect("listener initialized by startup");
        let timeout = Duration::from_millis(self.config.idle_timeout_ms.max(1));
        let accept_result = asupersync::time::timeout(
            asupersync::time::wall_now(),
            timeout,
            Box::pin(listener.accept()),
        )
        .await;

        let (mut stream, _addr) = match accept_result {
            Ok(Ok(pair)) => pair,
            Ok(Err(source)) => {
                return Err(NativeHostError::Io {
                    path: self.socket_path.clone(),
                    source,
                });
            }
            Err(_timeout) => return Ok(NativeHostRunOutcome::IdleTimeout),
        };

        let inbound = read_socket_message(&mut stream).await?;
        let response = match inbound {
            protocol::MessageType::AuthClaim(claim) => self.handle_auth_claim(claim)?,
            _ => handshake_error_response(
                protocol::ProtocolErrorCode::ChromeBridgeAuthFailed,
                "first socket message must be auth_claim",
                false,
            ),
        };
        write_socket_message(&mut stream, &response).await?;
        if !matches!(response, protocol::MessageType::AuthOk(_)) {
            return Ok(NativeHostRunOutcome::AgentConnected);
        }
        let claimed_by = self
            .claimed_by
            .clone()
            .expect("auth_ok handshake must set claimed_by");

        let mut agent_stream =
            stream
                .as_std()
                .try_clone()
                .map_err(|source| NativeHostError::Io {
                    path: self.socket_path.clone(),
                    source,
                })?;
        agent_stream
            .set_nonblocking(false)
            .map_err(|source| NativeHostError::Io {
                path: self.socket_path.clone(),
                source,
            })?;
        drop(stream);

        let host_epoch = self.host_epoch.clone();
        let relay_result = relay_until_disconnect(
            &mut agent_stream,
            chrome_reader,
            chrome_writer,
            &claimed_by.pi_session_id,
            &host_epoch,
            &mut self.journal,
        );
        let clear_claim_result = self.clear_claim();
        relay_result?;
        clear_claim_result?;
        Ok(NativeHostRunOutcome::AgentConnected)
    }

    pub async fn accept_and_handle_claim_for_test(
        &mut self,
    ) -> Result<protocol::MessageType, NativeHostError> {
        self.startup().await?;
        let listener = self
            .listener
            .as_ref()
            .expect("listener initialized by startup");
        let (mut stream, _addr) =
            listener
                .accept()
                .await
                .map_err(|source| NativeHostError::Io {
                    path: self.socket_path.clone(),
                    source,
                })?;

        let inbound = read_socket_message(&mut stream).await?;
        let response = match inbound {
            protocol::MessageType::AuthClaim(claim) => self.handle_auth_claim(claim)?,
            _ => handshake_error_response(
                protocol::ProtocolErrorCode::ChromeBridgeAuthFailed,
                "first socket message must be auth_claim",
                false,
            ),
        };

        write_socket_message(&mut stream, &response).await?;
        Ok(response)
    }

    pub async fn accept_claim_and_relay_single_exchange_for_test<R: IoRead, W: IoWrite>(
        &mut self,
        chrome_reader: &mut R,
        chrome_writer: &mut W,
    ) -> Result<
        (
            protocol::MessageType,
            protocol::MessageType,
            protocol::MessageType,
        ),
        NativeHostError,
    > {
        self.startup().await?;
        let listener = self
            .listener
            .as_ref()
            .expect("listener initialized by startup");
        let (stream, _addr) = listener
            .accept()
            .await
            .map_err(|source| NativeHostError::Io {
                path: self.socket_path.clone(),
                source,
            })?;

        let mut agent_stream =
            stream
                .as_std()
                .try_clone()
                .map_err(|source| NativeHostError::Io {
                    path: self.socket_path.clone(),
                    source,
                })?;
        agent_stream
            .set_nonblocking(false)
            .map_err(|source| NativeHostError::Io {
                path: self.socket_path.clone(),
                source,
            })?;

        let inbound = read_agent_socket_message_blocking(&mut agent_stream)?;
        let handshake = match inbound {
            protocol::MessageType::AuthClaim(claim) => self.handle_auth_claim(claim)?,
            _ => handshake_error_response(
                protocol::ProtocolErrorCode::ChromeBridgeAuthFailed,
                "first socket message must be auth_claim",
                false,
            ),
        };
        write_agent_socket_message_blocking(&mut agent_stream, &handshake)?;
        if !matches!(handshake, protocol::MessageType::AuthOk(_)) {
            return Ok((
                handshake,
                handshake_error_response(
                    protocol::ProtocolErrorCode::ChromeBridgeAuthFailed,
                    "relay skipped because auth failed",
                    false,
                ),
                handshake_error_response(
                    protocol::ProtocolErrorCode::ChromeBridgeAuthFailed,
                    "relay skipped because auth failed",
                    false,
                ),
            ));
        }

        let agent_message = relay_one_agent_message_to_chrome(&mut agent_stream, chrome_writer)?;
        let chrome_message = relay_one_chrome_message_to_agent(chrome_reader, &mut agent_stream)?;
        Ok((handshake, agent_message, chrome_message))
    }

    pub fn handle_auth_claim(
        &mut self,
        claim: protocol::AuthClaim,
    ) -> Result<protocol::MessageType, NativeHostError> {
        if claim.host_id != self.host_id {
            return Ok(handshake_error_response(
                protocol::ProtocolErrorCode::ChromeBridgeAuthFailed,
                format!(
                    "host_id mismatch: claim={}, host={}",
                    claim.host_id, self.host_id
                ),
                false,
            ));
        }
        if claim.token != self.token {
            return Ok(handshake_error_response(
                protocol::ProtocolErrorCode::ChromeBridgeAuthFailed,
                "auth token mismatch",
                false,
            ));
        }

        if !protocol_ranges_overlap(
            claim.protocol_min,
            claim.protocol_max,
            protocol::PROTOCOL_MIN_SUPPORTED,
            protocol::PROTOCOL_MAX_SUPPORTED,
        ) {
            return Ok(handshake_error_response(
                protocol::ProtocolErrorCode::ChromeBridgeProtocolMismatch,
                "no overlapping protocol version",
                false,
            ));
        }

        let missing_capability = claim
            .want_capabilities
            .iter()
            .find(|wanted| !self.config.capabilities.iter().any(|have| have == *wanted));
        if let Some(capability) = missing_capability {
            return Ok(handshake_error_response(
                protocol::ProtocolErrorCode::ChromeBridgeProtocolMismatch,
                format!("required capability not supported: {capability}"),
                false,
            ));
        }

        let requester = protocol::ClaimedBy {
            pi_session_id: claim.pi_session_id,
            client_instance_id: claim.client_instance_id,
        };

        if let Some(current_claim) = &self.claimed_by {
            if current_claim != &requester {
                return Ok(protocol::MessageType::AuthBusy(protocol::AuthBusy {
                    version: protocol::PROTOCOL_VERSION_V1,
                    host_id: self.host_id.clone(),
                    claimed_by: current_claim.clone(),
                }));
            }
        }

        self.claimed_by = Some(requester.clone());
        self.write_discovery_record()?;

        Ok(protocol::MessageType::AuthOk(protocol::AuthOk {
            version: protocol::PROTOCOL_VERSION_V1,
            host_id: self.host_id.clone(),
            claimed_by: requester,
            host_epoch: self.host_epoch.clone(),
            protocol: protocol::PROTOCOL_VERSION_V1,
            capabilities: self.config.capabilities.clone(),
            lease_ttl_ms: self.config.lease_ttl_ms,
        }))
    }

    fn clear_claim(&mut self) -> Result<(), NativeHostError> {
        if self.claimed_by.take().is_some() {
            self.write_discovery_record()?;
        }
        Ok(())
    }

    fn write_discovery_record(&self) -> Result<(), NativeHostError> {
        let now_ms = unix_time_ms();
        let lease_expiry =
            now_ms.saturating_add(i64::try_from(self.config.lease_ttl_ms).unwrap_or(i64::MAX));
        let discovery_expiry = now_ms.saturating_add(
            i64::try_from(self.config.idle_timeout_ms.max(self.config.lease_ttl_ms))
                .unwrap_or(i64::MAX),
        );

        let record = DiscoveryRecord {
            host_id: self.host_id.clone(),
            host_epoch: self.host_epoch.clone(),
            socket_path: self.socket_path.clone(),
            token: self.token.clone(),
            protocol_min: protocol::PROTOCOL_MIN_SUPPORTED,
            protocol_max: protocol::PROTOCOL_MAX_SUPPORTED,
            capabilities: self.config.capabilities.clone(),
            claimed_by: self.claimed_by.clone(),
            lease_expires_at_ms: Some(lease_expiry),
            expires_at_ms: Some(discovery_expiry),
        };
        let bytes =
            serde_json::to_vec(&record).map_err(|source| NativeHostError::DiscoverySerialize {
                path: self.discovery_path.clone(),
                source,
            })?;
        fs::write(&self.discovery_path, bytes).map_err(|source| NativeHostError::Io {
            path: self.discovery_path.clone(),
            source,
        })?;
        set_owner_only_permissions(&self.discovery_path)?;
        Ok(())
    }
}

impl Drop for NativeHost {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_file(&self.discovery_path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                tracing::debug!(
                    "failed to remove native host discovery record {:?}: {err}",
                    self.discovery_path
                );
            }
        }
    }
}

#[derive(Debug, Error)]
pub enum NativeHostError {
    #[error("ESL invariant violation: {0}")]
    EslInvariant(String),
    #[error("failed to fingerprint ESL request: {0}")]
    Fingerprint(serde_json::Error),
    #[error("native host I/O error for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to serialize discovery record {path}: {source}")]
    DiscoverySerialize {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("native host frame codec error: {0}")]
    Frame(#[from] protocol::FrameCodecError),
    #[error("invalid native messaging JSON payload: {0}")]
    NativeMessageJson(serde_json::Error),
    #[error("chrome native messaging frame exceeds {max_bytes} bytes (got {frame_bytes})")]
    NativeMessageFrameTooLarge {
        frame_bytes: usize,
        max_bytes: usize,
    },
}

fn random_id() -> String {
    Uuid::new_v4().to_string()
}

fn random_token() -> String {
    Uuid::new_v4().simple().to_string()
}

fn set_owner_only_permissions(path: &Path) -> Result<(), NativeHostError> {
    let mut perms = fs::metadata(path)
        .map_err(|source| NativeHostError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms).map_err(|source| NativeHostError::Io {
        path: path.to_path_buf(),
        source,
    })
}

const fn protocol_ranges_overlap(a_min: u16, a_max: u16, b_min: u16, b_max: u16) -> bool {
    if a_min > a_max || b_min > b_max {
        return false;
    }
    a_min <= b_max && b_min <= a_max
}

fn handshake_error_response(
    code: protocol::ProtocolErrorCode,
    message: impl Into<String>,
    retryable: bool,
) -> protocol::MessageType {
    protocol::MessageType::Response(protocol::ResponseEnvelope::Error(protocol::ErrorResponse {
        version: protocol::PROTOCOL_VERSION_V1,
        id: "handshake".to_string(),
        ok: false,
        error: protocol::ProtocolErrorDetail {
            code,
            message: message.into(),
            retryable,
        },
    }))
}

fn invalid_request_envelope(
    request_id: &str,
    message: impl Into<String>,
) -> protocol::ResponseEnvelope {
    protocol::ResponseEnvelope::Error(protocol::ErrorResponse {
        version: protocol::PROTOCOL_VERSION_V1,
        id: request_id.to_string(),
        ok: false,
        error: protocol::ProtocolErrorDetail {
            code: protocol::ProtocolErrorCode::ChromeBridgeProtocolMismatch,
            message: format!("invalid_request: {}", message.into()),
            retryable: false,
        },
    })
}

fn in_progress_envelope(
    request_id: &str,
    message: impl Into<String>,
) -> protocol::ResponseEnvelope {
    protocol::ResponseEnvelope::Error(protocol::ErrorResponse {
        version: protocol::PROTOCOL_VERSION_V1,
        id: request_id.to_string(),
        ok: false,
        error: protocol::ProtocolErrorDetail {
            code: protocol::ProtocolErrorCode::ChromeBridgeBusy,
            message: message.into(),
            retryable: true,
        },
    })
}

fn execution_indeterminate_envelope(
    request_id: &str,
    message: impl Into<String>,
) -> protocol::ResponseEnvelope {
    protocol::ResponseEnvelope::Error(protocol::ErrorResponse {
        version: protocol::PROTOCOL_VERSION_V1,
        id: request_id.to_string(),
        ok: false,
        error: protocol::ProtocolErrorDetail {
            code: protocol::ProtocolErrorCode::ChromeBridgeExecutionIndeterminate,
            message: message.into(),
            retryable: false,
        },
    })
}

fn approx_in_progress_entry_bytes(
    key: &EslJournalKey,
    fingerprint: &protocol::RequestFingerprint,
) -> usize {
    key.pi_session_id
        .len()
        .saturating_add(key.request_id.len())
        .saturating_add(key.host_epoch.len())
        .saturating_add(fingerprint.as_str().len())
        .saturating_add(128)
}

fn approx_terminal_entry_bytes(
    key: &EslJournalKey,
    fingerprint: &protocol::RequestFingerprint,
    response: &protocol::ResponseEnvelope,
) -> usize {
    let response_bytes = serde_json::to_vec(response).map_or(0, |bytes| bytes.len());
    key.pi_session_id
        .len()
        .saturating_add(key.request_id.len())
        .saturating_add(key.host_epoch.len())
        .saturating_add(fingerprint.as_str().len())
        .saturating_add(response_bytes)
        .saturating_add(160)
}

async fn write_socket_message(
    stream: &mut asupersync::net::unix::UnixStream,
    message: &protocol::MessageType,
) -> Result<(), NativeHostError> {
    let frame = protocol::encode_frame(message)?;
    asupersync::io::AsyncWriteExt::write_all(stream, &frame)
        .await
        .map_err(|source| NativeHostError::Io {
            path: PathBuf::from("<agent-socket>"),
            source,
        })
}

fn write_native_messaging_frame<W: IoWrite>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), NativeHostError> {
    if payload.len() > protocol::MAX_SOCKET_FRAME_BYTES {
        return Err(NativeHostError::NativeMessageFrameTooLarge {
            frame_bytes: payload.len(),
            max_bytes: protocol::MAX_SOCKET_FRAME_BYTES,
        });
    }

    let len =
        u32::try_from(payload.len()).map_err(|_| NativeHostError::NativeMessageFrameTooLarge {
            frame_bytes: payload.len(),
            max_bytes: protocol::MAX_SOCKET_FRAME_BYTES,
        })?;
    writer
        .write_all(&len.to_le_bytes())
        .map_err(|source| NativeHostError::Io {
            path: PathBuf::from("<chrome-stdio>"),
            source,
        })?;
    writer
        .write_all(payload)
        .map_err(|source| NativeHostError::Io {
            path: PathBuf::from("<chrome-stdio>"),
            source,
        })?;
    writer.flush().map_err(|source| NativeHostError::Io {
        path: PathBuf::from("<chrome-stdio>"),
        source,
    })?;
    Ok(())
}

fn read_native_messaging_frame<R: IoRead>(reader: &mut R) -> Result<Vec<u8>, NativeHostError> {
    let mut header = [0_u8; 4];
    reader
        .read_exact(&mut header)
        .map_err(|source| NativeHostError::Io {
            path: PathBuf::from("<chrome-stdio>"),
            source,
        })?;
    let frame_len = u32::from_le_bytes(header) as usize;
    if frame_len > protocol::MAX_SOCKET_FRAME_BYTES {
        return Err(NativeHostError::NativeMessageFrameTooLarge {
            frame_bytes: frame_len,
            max_bytes: protocol::MAX_SOCKET_FRAME_BYTES,
        });
    }

    let mut payload = vec![0_u8; frame_len];
    reader
        .read_exact(&mut payload)
        .map_err(|source| NativeHostError::Io {
            path: PathBuf::from("<chrome-stdio>"),
            source,
        })?;
    Ok(payload)
}

fn write_native_messaging_message<W: IoWrite>(
    writer: &mut W,
    message: &protocol::MessageType,
) -> Result<(), NativeHostError> {
    let payload = serde_json::to_vec(message).map_err(NativeHostError::NativeMessageJson)?;
    write_native_messaging_frame(writer, &payload)
}

fn read_native_messaging_message<R: IoRead>(
    reader: &mut R,
) -> Result<protocol::MessageType, NativeHostError> {
    let payload = read_native_messaging_frame(reader)?;
    serde_json::from_slice(&payload).map_err(NativeHostError::NativeMessageJson)
}

fn read_agent_socket_message_blocking<R: IoRead>(
    reader: &mut R,
) -> Result<protocol::MessageType, NativeHostError> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let mut byte = [0_u8; 1];
        reader
            .read_exact(&mut byte)
            .map_err(|source| NativeHostError::Io {
                path: PathBuf::from("<agent-socket>"),
                source,
            })?;
        buf.push(byte[0]);
        if let Some((message, consumed)) = protocol::decode_frame::<protocol::MessageType>(&buf)? {
            if consumed != buf.len() {
                return Err(NativeHostError::Io {
                    path: PathBuf::from("<agent-socket>"),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "multiple agent frames in one blocking read are not supported",
                    ),
                });
            }
            return Ok(message);
        }
    }
}

fn write_agent_socket_message_blocking<W: IoWrite>(
    writer: &mut W,
    message: &protocol::MessageType,
) -> Result<(), NativeHostError> {
    let frame = protocol::encode_frame(message)?;
    writer
        .write_all(&frame)
        .map_err(|source| NativeHostError::Io {
            path: PathBuf::from("<agent-socket>"),
            source,
        })?;
    writer.flush().map_err(|source| NativeHostError::Io {
        path: PathBuf::from("<agent-socket>"),
        source,
    })?;
    Ok(())
}

fn relay_one_agent_message_to_chrome<R: IoRead, W: IoWrite>(
    agent_reader: &mut R,
    chrome_writer: &mut W,
) -> Result<protocol::MessageType, NativeHostError> {
    let message = read_agent_socket_message_blocking(agent_reader)?;
    write_native_messaging_message(chrome_writer, &message)?;
    Ok(message)
}

fn relay_one_chrome_message_to_agent<R: IoRead, W: IoWrite>(
    chrome_reader: &mut R,
    agent_writer: &mut W,
) -> Result<protocol::MessageType, NativeHostError> {
    let message = read_native_messaging_message(chrome_reader)?;
    write_agent_socket_message_blocking(agent_writer, &message)?;
    Ok(message)
}

fn relay_until_disconnect<R: IoRead, W: IoWrite>(
    agent_stream: &mut std::os::unix::net::UnixStream,
    chrome_reader: &mut R,
    chrome_writer: &mut W,
    pi_session_id: &str,
    host_epoch: &str,
    journal: &mut EslJournal,
) -> Result<(), NativeHostError> {
    loop {
        let agent_message = match read_agent_socket_message_blocking(agent_stream) {
            Ok(message) => message,
            Err(err) if is_clean_disconnect_error(&err) => return Ok(()),
            Err(err) => return Err(err),
        };

        let request = match &agent_message {
            protocol::MessageType::Request(request) => Some(request.clone()),
            _ => None,
        };

        if let Some(request) = request {
            match journal.begin_request(pi_session_id, host_epoch, &request, unix_time_ms())? {
                EslBeginOutcome::Dispatch => {
                    tracing::debug!(
                        event = "pi.chrome.esl.dispatch",
                        pi_session_id,
                        request_id = %request.id,
                        host_epoch,
                        op = %request.op,
                        "Dispatching request after ESL miss"
                    );
                    write_native_messaging_message(
                        chrome_writer,
                        &protocol::MessageType::Request(request.clone()),
                    )?;
                    match relay_chrome_messages_until_response(chrome_reader, agent_stream) {
                        Ok((_forwarded, terminal_response)) => {
                            journal.record_terminal_response(
                                pi_session_id,
                                host_epoch,
                                &request,
                                &terminal_response,
                                unix_time_ms(),
                            )?;
                        }
                        Err(err) if is_clean_disconnect_error(&err) => return Ok(()),
                        Err(err) => return Err(err),
                    }
                }
                EslBeginOutcome::Replay(envelope) => {
                    tracing::debug!(
                        event = "pi.chrome.esl.replay",
                        pi_session_id,
                        request_id = %request.id,
                        host_epoch,
                        op = %request.op,
                        "Replaying terminal ESL response without duplicate execution"
                    );
                    let message = protocol::MessageType::Response(envelope);
                    if let Err(err) = write_agent_socket_message_blocking(agent_stream, &message) {
                        if is_clean_disconnect_error(&err) {
                            return Ok(());
                        }
                        return Err(err);
                    }
                }
                EslBeginOutcome::Reject(envelope) => {
                    tracing::warn!(
                        event = "pi.chrome.esl.reject",
                        pi_session_id,
                        request_id = %request.id,
                        host_epoch,
                        op = %request.op,
                        "Rejecting request due to ESL state/fingerprint/capacity rules"
                    );
                    let message = protocol::MessageType::Response(envelope);
                    if let Err(err) = write_agent_socket_message_blocking(agent_stream, &message) {
                        if is_clean_disconnect_error(&err) {
                            return Ok(());
                        }
                        return Err(err);
                    }
                }
            }
            continue;
        }

        write_native_messaging_message(chrome_writer, &agent_message)?;
        match relay_chrome_messages_until_response(chrome_reader, agent_stream) {
            Ok((_forwarded, _terminal)) => {}
            Err(err) if is_clean_disconnect_error(&err) => return Ok(()),
            Err(err) => return Err(err),
        }
    }
}

fn relay_chrome_messages_until_response<R: IoRead, W: IoWrite>(
    chrome_reader: &mut R,
    agent_writer: &mut W,
) -> Result<(usize, protocol::ResponseEnvelope), NativeHostError> {
    let mut forwarded = 0_usize;
    loop {
        let message = relay_one_chrome_message_to_agent(chrome_reader, agent_writer)?;
        forwarded = forwarded.saturating_add(1);
        if let protocol::MessageType::Response(envelope) = message {
            return Ok((forwarded, envelope));
        }
    }
}

async fn read_socket_message(
    stream: &mut asupersync::net::unix::UnixStream,
) -> Result<protocol::MessageType, NativeHostError> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let byte = stream
            .read_u8()
            .await
            .map_err(|source| NativeHostError::Io {
                path: PathBuf::from("<agent-socket>"),
                source,
            })?;
        buf.push(byte);
        if let Some((message, consumed)) = protocol::decode_frame::<protocol::MessageType>(&buf)? {
            if consumed != buf.len() {
                return Err(NativeHostError::Io {
                    path: PathBuf::from("<agent-socket>"),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "multiple frames in handshake read are not supported",
                    ),
                });
            }
            return Ok(message);
        }
    }
}

fn is_clean_disconnect_error(err: &NativeHostError) -> bool {
    match err {
        NativeHostError::Io { source, .. } => matches!(
            source.kind(),
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
        ),
        _ => false,
    }
}

fn unix_time_ms() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    i64::try_from(now.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    use asupersync::runtime::RuntimeBuilder;
    use proptest::prelude::*;
    use std::io::{BufRead, Write};

    fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        runtime.block_on(future)
    }

    fn test_config(base: &Path) -> NativeHostConfig {
        NativeHostConfig {
            discovery_dir: base.to_path_buf(),
            socket_dir: base.to_path_buf(),
            host_id: Some("host-test".to_string()),
            host_epoch: Some("epoch-test".to_string()),
            token: Some("secret-test-token".to_string()),
            lease_ttl_ms: 30_000,
            idle_timeout_ms: 25,
            capabilities: vec!["browser_tools".to_string(), "observations".to_string()],
        }
    }

    #[test]
    fn test_native_host_startup_writes_discovery_record_and_socket() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");

            host.startup()
                .await
                .expect("startup should bind and publish");

            assert!(
                host.socket_path().exists(),
                "native host startup must create the unix socket path"
            );
            assert!(
                host.discovery_path().exists(),
                "native host startup must write discovery record"
            );

            let raw = fs::read(host.discovery_path()).expect("read discovery record");
            let record: DiscoveryRecord =
                serde_json::from_slice(&raw).expect("parse discovery record json");
            let now_ms = unix_time_ms();
            assert_eq!(record.host_id, "host-test", "host_id should be preserved");
            assert_eq!(
                record.host_epoch, "epoch-test",
                "host_epoch should be written to discovery"
            );
            assert_eq!(
                record.token, "secret-test-token",
                "auth token should be published for rendezvous"
            );
            assert_eq!(
                record.socket_path,
                host.socket_path().to_path_buf(),
                "discovery record must point at the bound socket path"
            );
            assert!(
                record.claimed_by.is_none(),
                "host starts unclaimed before auth_claim succeeds"
            );
            assert!(
                record.lease_expires_at_ms.is_some_and(|ts| ts > now_ms),
                "lease expiry must be present and in the future"
            );
            assert!(
                record.expires_at_ms.is_some_and(|ts| ts > now_ms),
                "discovery expiry must be present and in the future"
            );

            let discovery_mode = fs::metadata(host.discovery_path())
                .expect("stat discovery file")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                discovery_mode, 0o600,
                "discovery file must be owner-only because it embeds the auth token"
            );
            let socket_mode = fs::metadata(host.socket_path())
                .expect("stat socket path")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(
                socket_mode, 0o600,
                "unix socket path must be owner-only to reduce local cross-session exposure"
            );
        });
    }

    #[test]
    fn test_native_host_idle_timeout_exits_without_connection() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut config = test_config(tempdir.path());
            config.idle_timeout_ms = 10;
            let mut host = NativeHost::new(config).expect("host init");

            let outcome = host
                .run_until_idle_for_test()
                .await
                .expect("idle wait should complete cleanly");
            assert_eq!(
                outcome,
                NativeHostRunOutcome::IdleTimeout,
                "host must exit cleanly on idle timeout when no agent claims it"
            );
        });
    }

    #[test]
    fn test_native_host_socket_accepts_connection_before_idle_timeout() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut config = test_config(tempdir.path());
            config.idle_timeout_ms = 200;
            let mut host = NativeHost::new(config).expect("host init");

            host.startup().await.expect("startup should succeed");
            let connect_path = host.socket_path().to_path_buf();
            let connector = std::thread::spawn(move || {
                std::os::unix::net::UnixStream::connect(connect_path)
                    .expect("client should connect to host socket")
            });

            let outcome = host
                .run_until_idle_for_test()
                .await
                .expect("accept loop should complete");
            assert_eq!(
                outcome,
                NativeHostRunOutcome::AgentConnected,
                "incoming agent connection should end the idle wait path"
            );

            let _stream = connector.join().expect("connector join");
        });
    }

    #[test]
    fn test_native_host_drop_cleans_up_discovery_record_and_socket() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.startup().await.expect("startup should succeed");
            let discovery_path = host.discovery_path().to_path_buf();
            let socket_path = host.socket_path().to_path_buf();

            assert!(discovery_path.exists(), "sanity: discovery file exists");
            assert!(socket_path.exists(), "sanity: socket path exists");
            drop(host);

            assert!(
                !discovery_path.exists(),
                "dropping native host must remove discovery record"
            );
            assert!(
                !socket_path.exists(),
                "dropping native host should drop listener and remove socket path"
            );
        });
    }

    fn sample_auth_claim(token: &str) -> protocol::AuthClaim {
        protocol::AuthClaim {
            version: protocol::PROTOCOL_VERSION_V1,
            host_id: "host-test".to_string(),
            pi_session_id: "session-1".to_string(),
            client_instance_id: "client-1".to_string(),
            token: token.to_string(),
            protocol_min: protocol::PROTOCOL_MIN_SUPPORTED,
            protocol_max: protocol::PROTOCOL_MAX_SUPPORTED,
            want_capabilities: vec!["browser_tools".to_string()],
        }
    }

    fn sample_request_struct(id: &str, payload: serde_json::Value) -> protocol::Request {
        protocol::Request {
            version: protocol::PROTOCOL_VERSION_V1,
            id: id.to_string(),
            op: "tabs_context".to_string(),
            payload,
        }
    }

    fn sample_request() -> protocol::MessageType {
        protocol::MessageType::Request(sample_request_struct(
            "req-e2e-1",
            serde_json::json!({"tabId": 123}),
        ))
    }

    fn sample_response_for(id: &str) -> protocol::MessageType {
        protocol::MessageType::Response(protocol::ResponseEnvelope::Ok(protocol::Response {
            version: protocol::PROTOCOL_VERSION_V1,
            id: id.to_string(),
            ok: true,
            result: serde_json::json!({"tabs": [{"id": 123, "url": "https://example.test"}]}),
        }))
    }

    fn sample_response_envelope_for(id: &str) -> protocol::ResponseEnvelope {
        let protocol::MessageType::Response(envelope) = sample_response_for(id) else {
            unreachable!("sample_response_for must return response");
        };
        envelope
    }

    fn esl_json_value_strategy() -> impl Strategy<Value = serde_json::Value> {
        let leaf = prop_oneof![
            Just(serde_json::Value::Null),
            any::<bool>().prop_map(serde_json::Value::Bool),
            any::<i64>().prop_map(|n| serde_json::Value::Number(n.into())),
            "[a-zA-Z0-9 _./:-]{0,64}".prop_map(serde_json::Value::String),
        ];

        leaf.prop_recursive(4, 128, 8, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(serde_json::Value::Array),
                prop::collection::btree_map("[a-zA-Z0-9_]{1,16}", inner, 0..6).prop_map(|map| {
                    let mut obj = serde_json::Map::with_capacity(map.len());
                    for (key, value) in map {
                        obj.insert(key, value);
                    }
                    serde_json::Value::Object(obj)
                }),
            ]
        })
    }

    fn trace_request_for_slot(slot: u8, payload_variant: u8) -> protocol::Request {
        sample_request_struct(
            &format!("req-trace-{}", slot % 4),
            serde_json::json!({
                "slot": slot % 4,
                "variant": payload_variant % 4,
                "flag": (payload_variant % 2) == 0,
            }),
        )
    }

    fn trace_terminal_response_for(
        request: &protocol::Request,
        ok: bool,
    ) -> protocol::ResponseEnvelope {
        if ok {
            protocol::ResponseEnvelope::Ok(protocol::Response {
                version: protocol::PROTOCOL_VERSION_V1,
                id: request.id.clone(),
                ok: true,
                result: serde_json::json!({"ok": true, "op": request.op}),
            })
        } else {
            protocol::ResponseEnvelope::Error(protocol::ErrorResponse {
                version: protocol::PROTOCOL_VERSION_V1,
                id: request.id.clone(),
                ok: false,
                error: protocol::ProtocolErrorDetail {
                    code: protocol::ProtocolErrorCode::JavascriptError,
                    message: "synthetic terminal failure for ESL trace test".to_string(),
                    retryable: false,
                },
            })
        }
    }

    fn send_frame(stream: &mut std::os::unix::net::UnixStream, message: &protocol::MessageType) {
        let frame = protocol::encode_frame(message).expect("encode frame");
        stream.write_all(&frame).expect("write frame");
    }

    fn read_frame(
        reader: &mut std::io::BufReader<std::os::unix::net::UnixStream>,
    ) -> protocol::MessageType {
        let mut line = Vec::new();
        let bytes_read = reader.read_until(b'\n', &mut line).expect("read frame");
        assert!(bytes_read > 0, "peer must send a complete frame");
        let (message, consumed) = protocol::decode_frame::<protocol::MessageType>(&line)
            .expect("decode frame")
            .expect("complete frame");
        assert_eq!(consumed, line.len(), "frame decode must consume full line");
        message
    }

    #[test]
    fn test_esl_journal_duplicate_terminal_request_replays_cached_response() {
        let mut journal = EslJournal::with_limits_for_test(60_000, 8, 1 << 20);
        let request = sample_request_struct("req-esl-replay", serde_json::json!({"tabId": 1}));
        let response = sample_response_envelope_for("req-esl-replay");
        let now_ms = unix_time_ms();

        let first = journal
            .begin_request("session-1", "epoch-1", &request, now_ms)
            .expect("first request should initialize in-progress entry");
        assert_eq!(
            first,
            EslBeginOutcome::Dispatch,
            "first delivery must dispatch to Chrome"
        );

        journal
            .record_terminal_response("session-1", "epoch-1", &request, &response, now_ms + 1)
            .expect("terminal response should be stored");

        let duplicate = journal
            .begin_request("session-1", "epoch-1", &request, now_ms + 2)
            .expect("duplicate request lookup should succeed");
        match duplicate {
            EslBeginOutcome::Replay(replayed) => assert_eq!(
                replayed, response,
                "duplicate request with matching fingerprint must replay cached terminal response"
            ),
            other => panic!("expected replay outcome, got {other:?}"),
        }
    }

    #[test]
    fn test_esl_journal_rejects_request_id_reuse_with_mismatched_fingerprint() {
        let mut journal = EslJournal::with_limits_for_test(60_000, 8, 1 << 20);
        let original = sample_request_struct("req-esl-fp", serde_json::json!({"tabId": 1}));
        let mismatched = sample_request_struct("req-esl-fp", serde_json::json!({"tabId": 2}));
        let now_ms = unix_time_ms();

        let first = journal
            .begin_request("session-1", "epoch-1", &original, now_ms)
            .expect("first request should dispatch");
        assert_eq!(
            first,
            EslBeginOutcome::Dispatch,
            "initial request must dispatch"
        );

        let duplicate = journal
            .begin_request("session-1", "epoch-1", &mismatched, now_ms + 1)
            .expect("fingerprint mismatch should return protocol reject response");
        match duplicate {
            EslBeginOutcome::Reject(protocol::ResponseEnvelope::Error(err)) => {
                assert_eq!(
                    err.error.code,
                    protocol::ProtocolErrorCode::ChromeBridgeProtocolMismatch,
                    "fingerprint mismatch must fail closed as invalid_request"
                );
                assert!(
                    err.error.message.contains("invalid_request"),
                    "error should surface invalid_request semantic for debugging"
                );
            }
            other => panic!("expected reject(error) outcome, got {other:?}"),
        }
    }

    #[test]
    fn test_esl_journal_rejects_duplicate_in_progress_request() {
        let mut journal = EslJournal::with_limits_for_test(60_000, 8, 1 << 20);
        let request = sample_request_struct("req-esl-busy", serde_json::json!({"tabId": 1}));
        let now_ms = unix_time_ms();

        let first = journal
            .begin_request("session-1", "epoch-1", &request, now_ms)
            .expect("first request should dispatch");
        assert_eq!(
            first,
            EslBeginOutcome::Dispatch,
            "initial request must dispatch"
        );

        let duplicate = journal
            .begin_request("session-1", "epoch-1", &request, now_ms + 1)
            .expect("duplicate in-progress request should return protocol reject");
        match duplicate {
            EslBeginOutcome::Reject(protocol::ResponseEnvelope::Error(err)) => {
                assert_eq!(
                    err.error.code,
                    protocol::ProtocolErrorCode::ChromeBridgeBusy,
                    "duplicate in-progress request must surface retryable busy state"
                );
                assert!(
                    err.error.retryable,
                    "in-progress ESL response must be retryable for bridge backoff logic"
                );
                assert!(
                    err.error.message.contains("in_progress"),
                    "busy error message must identify in_progress ESL state"
                );
            }
            other => panic!("expected reject(error) outcome, got {other:?}"),
        }
    }

    #[test]
    fn test_esl_journal_capacity_evicts_terminal_entries_before_in_progress_entries() {
        let mut journal = EslJournal::with_limits_for_test(60_000, 2, 1 << 20);
        let req_terminal =
            sample_request_struct("req-esl-terminal", serde_json::json!({"tabId": 1}));
        let req_in_progress =
            sample_request_struct("req-esl-in-progress", serde_json::json!({"tabId": 2}));
        let req_new = sample_request_struct("req-esl-new", serde_json::json!({"tabId": 3}));
        let now_ms = unix_time_ms();

        assert_eq!(
            journal
                .begin_request("session-1", "epoch-1", &req_terminal, now_ms)
                .expect("terminal request begin"),
            EslBeginOutcome::Dispatch,
            "first request must dispatch"
        );
        journal
            .record_terminal_response(
                "session-1",
                "epoch-1",
                &req_terminal,
                &sample_response_envelope_for("req-esl-terminal"),
                now_ms + 1,
            )
            .expect("terminal response stored");
        assert_eq!(
            journal
                .begin_request("session-1", "epoch-1", &req_in_progress, now_ms + 2)
                .expect("in-progress request begin"),
            EslBeginOutcome::Dispatch,
            "second request must dispatch and remain in_progress"
        );

        let third = journal
            .begin_request("session-1", "epoch-1", &req_new, now_ms + 3)
            .expect("third request should dispatch after terminal eviction");
        assert_eq!(
            third,
            EslBeginOutcome::Dispatch,
            "journal should evict the oldest terminal entry rather than any in_progress entry"
        );
        assert!(
            !journal.contains_key("session-1", "req-esl-terminal", "epoch-1"),
            "oldest terminal entry should be evicted to satisfy cap"
        );
        assert!(
            journal.contains_key("session-1", "req-esl-in-progress", "epoch-1"),
            "in_progress entry must be preserved during ESL cap eviction"
        );
        assert!(
            journal.contains_key("session-1", "req-esl-new", "epoch-1"),
            "new entry should be admitted after terminal eviction"
        );
    }

    #[test]
    fn test_esl_journal_capacity_rejects_when_only_in_progress_entries_can_be_evicted() {
        let mut journal = EslJournal::with_limits_for_test(60_000, 0, 1 << 20);
        let request = sample_request_struct("req-esl-indeterminate", serde_json::json!({"x": 1}));

        let outcome = journal
            .begin_request("session-1", "epoch-1", &request, unix_time_ms())
            .expect("capacity failure should be encoded as protocol reject");
        match outcome {
            EslBeginOutcome::Reject(protocol::ResponseEnvelope::Error(err)) => {
                assert_eq!(
                    err.error.code,
                    protocol::ProtocolErrorCode::ChromeBridgeExecutionIndeterminate,
                    "unsafe ESL eviction scenario must fail closed as indeterminate"
                );
            }
            other => panic!("expected indeterminate reject, got {other:?}"),
        }
    }

    #[test]
    fn test_esl_journal_ttl_prunes_terminal_entries_but_keeps_in_progress_entries() {
        let mut journal = EslJournal::with_limits_for_test(5, 8, 1 << 20);
        let terminal = sample_request_struct("req-esl-ttl-terminal", serde_json::json!({"x": 1}));
        let in_progress =
            sample_request_struct("req-esl-ttl-progress", serde_json::json!({"x": 2}));
        let now_ms = unix_time_ms();

        assert_eq!(
            journal
                .begin_request("session-1", "epoch-1", &terminal, now_ms)
                .expect("begin terminal"),
            EslBeginOutcome::Dispatch,
            "terminal candidate should dispatch"
        );
        journal
            .record_terminal_response(
                "session-1",
                "epoch-1",
                &terminal,
                &sample_response_envelope_for("req-esl-ttl-terminal"),
                now_ms,
            )
            .expect("store terminal response");
        assert_eq!(
            journal
                .begin_request("session-1", "epoch-1", &in_progress, now_ms)
                .expect("begin in-progress"),
            EslBeginOutcome::Dispatch,
            "in-progress candidate should dispatch"
        );

        journal.prune_expired_terminal_entries(now_ms + 10);

        assert!(
            !journal.contains_key("session-1", "req-esl-ttl-terminal", "epoch-1"),
            "TTL prune must remove expired terminal entries"
        );
        assert!(
            journal.contains_key("session-1", "req-esl-ttl-progress", "epoch-1"),
            "TTL prune must never evict in_progress entries"
        );
    }

    #[test]
    fn test_esl_journal_enforces_ttl_coupling_invariant() {
        let err = EslJournal::new(30_001).expect_err(
            "lease_ttl above the derived bound should violate ESL ttl coupling invariant",
        );
        assert!(
            matches!(err, NativeHostError::EslInvariant(_)),
            "coupling invariant violation must be explicit and fail closed"
        );
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 64, .. ProptestConfig::default() })]

        #[test]
        fn test_esl_proptest_duplicate_delivery_is_at_most_once_with_terminal_replay(
            payload in esl_json_value_strategy(),
            in_progress_duplicates in 0_usize..4,
            replay_duplicates in 0_usize..4,
        ) {
            let mut journal = EslJournal::with_limits_for_test(60_000, 64, 1 << 20);
            let request = sample_request_struct("req-esl-prop", payload);
            let response = protocol::ResponseEnvelope::Ok(protocol::Response {
                version: protocol::PROTOCOL_VERSION_V1,
                id: "req-esl-prop".to_string(),
                ok: true,
                result: serde_json::json!({"ok": true}),
            });
            let now_ms = unix_time_ms();
            let mut dispatches = 0_usize;

            match journal.begin_request("session-prop", "epoch-prop", &request, now_ms)? {
                EslBeginOutcome::Dispatch => dispatches = dispatches.saturating_add(1),
                other => prop_assert!(false, "first delivery must dispatch, got {other:?}"),
            }

            for i in 0..in_progress_duplicates {
                let outcome = journal.begin_request(
                    "session-prop",
                    "epoch-prop",
                    &request,
                    now_ms + 1 + i64::try_from(i).unwrap_or(i64::MAX),
                )?;
                match outcome {
                    EslBeginOutcome::Reject(protocol::ResponseEnvelope::Error(err)) => {
                        prop_assert_eq!(
                            err.error.code,
                            protocol::ProtocolErrorCode::ChromeBridgeBusy,
                            "duplicate while in-progress must be busy/retryable"
                        );
                    }
                    other => prop_assert!(false, "duplicate in-progress must reject, got {other:?}"),
                }
            }

            journal.record_terminal_response(
                "session-prop",
                "epoch-prop",
                &request,
                &response,
                now_ms + 50,
            )?;

            for i in 0..replay_duplicates {
                let outcome = journal.begin_request(
                    "session-prop",
                    "epoch-prop",
                    &request,
                    now_ms + 100 + i64::try_from(i).unwrap_or(i64::MAX),
                )?;
                match outcome {
                    EslBeginOutcome::Replay(replayed) => {
                        prop_assert_eq!(
                            replayed,
                            response.clone(),
                            "terminal duplicates must replay"
                        );
                    }
                    other => prop_assert!(false, "terminal duplicate must replay, got {other:?}"),
                }
            }

            prop_assert_eq!(
                dispatches,
                1,
                "same-epoch duplicate deliveries with stable fingerprint must dispatch at most once"
            );
        }

        #[test]
        fn test_esl_proptest_epoch_bump_invalidates_replay_scope_and_requires_new_dispatch(
            payload in esl_json_value_strategy(),
            epoch_suffix in 1_u16..2000,
        ) {
            let mut journal = EslJournal::with_limits_for_test(60_000, 64, 1 << 20);
            let request = sample_request_struct("req-esl-epoch", payload);
            let response = protocol::ResponseEnvelope::Ok(protocol::Response {
                version: protocol::PROTOCOL_VERSION_V1,
                id: "req-esl-epoch".to_string(),
                ok: true,
                result: serde_json::json!({"epoch": "a"}),
            });
            let epoch_a = "epoch-a";
            let epoch_b = format!("epoch-b-{epoch_suffix}");
            let now_ms = unix_time_ms();

            let first = journal.begin_request("session-prop", epoch_a, &request, now_ms)?;
            prop_assert_eq!(first, EslBeginOutcome::Dispatch, "first epoch delivery must dispatch");

            journal.record_terminal_response("session-prop", epoch_a, &request, &response, now_ms + 1)?;

            let replay_same_epoch = journal.begin_request("session-prop", epoch_a, &request, now_ms + 2)?;
            match replay_same_epoch {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(replayed, response),
                other => prop_assert!(false, "same-epoch duplicate must replay, got {other:?}"),
            }

            let new_epoch = journal.begin_request("session-prop", &epoch_b, &request, now_ms + 3)?;
            prop_assert_eq!(
                new_epoch,
                EslBeginOutcome::Dispatch,
                "host_epoch bump must create a distinct ESL key and require a new dispatch"
            );
        }

        #[test]
        fn test_esl_proptest_pi_session_scope_isolates_terminal_replay(
            payload_a in esl_json_value_strategy(),
            payload_b in esl_json_value_strategy(),
            session_suffix in 1_u16..2000,
        ) {
            let mut journal = EslJournal::with_limits_for_test(60_000, 64, 1 << 20);
            let request_a = sample_request_struct("req-esl-session-scope", payload_a);
            let request_b = sample_request_struct("req-esl-session-scope", payload_b);
            let response_a = protocol::ResponseEnvelope::Ok(protocol::Response {
                version: protocol::PROTOCOL_VERSION_V1,
                id: "req-esl-session-scope".to_string(),
                ok: true,
                result: serde_json::json!({"session": "a", "ok": true}),
            });
            let response_b = protocol::ResponseEnvelope::Ok(protocol::Response {
                version: protocol::PROTOCOL_VERSION_V1,
                id: "req-esl-session-scope".to_string(),
                ok: true,
                result: serde_json::json!({"session": "b", "ok": true}),
            });
            let session_a = "session-a";
            let session_b = format!("session-b-{session_suffix}");
            let epoch = "epoch-prop";
            let now_ms = unix_time_ms();

            let first_a = journal.begin_request(session_a, epoch, &request_a, now_ms)?;
            prop_assert_eq!(
                first_a,
                EslBeginOutcome::Dispatch,
                "first request in session A must dispatch"
            );
            journal.record_terminal_response(
                session_a,
                epoch,
                &request_a,
                &response_a,
                now_ms + 1,
            )?;

            let first_b = journal.begin_request(session_b.as_str(), epoch, &request_b, now_ms + 2)?;
            prop_assert_eq!(
                first_b,
                EslBeginOutcome::Dispatch,
                "same request_id/epoch in a different pi_session_id must dispatch independently"
            );
            journal.record_terminal_response(
                session_b.as_str(),
                epoch,
                &request_b,
                &response_b,
                now_ms + 3,
            )?;

            let replay_a = journal.begin_request(session_a, epoch, &request_a, now_ms + 4)?;
            match replay_a {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    response_a,
                    "session A duplicate must replay session A terminal response only"
                ),
                other => prop_assert!(
                    false,
                    "session A duplicate must replay after terminal record, got {other:?}"
                ),
            }

            let replay_b = journal.begin_request(session_b.as_str(), epoch, &request_b, now_ms + 5)?;
            match replay_b {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    response_b,
                    "session B duplicate must replay session B terminal response only"
                ),
                other => prop_assert!(
                    false,
                    "session B duplicate must replay after terminal record, got {other:?}"
                ),
            }
        }

        #[test]
        fn test_esl_proptest_request_id_scope_isolates_terminal_replay(
            payload_a in esl_json_value_strategy(),
            payload_b in esl_json_value_strategy(),
            request_suffix in 1_u16..2000,
        ) {
            let mut journal = EslJournal::with_limits_for_test(60_000, 64, 1 << 20);
            let request_a = sample_request_struct("req-esl-request-scope-a", payload_a);
            let request_b = protocol::Request {
                version: protocol::PROTOCOL_VERSION_V1,
                id: format!("req-esl-request-scope-b-{request_suffix}"),
                op: request_a.op.clone(),
                payload: payload_b,
            };
            let response_a = protocol::ResponseEnvelope::Ok(protocol::Response {
                version: protocol::PROTOCOL_VERSION_V1,
                id: request_a.id.clone(),
                ok: true,
                result: serde_json::json!({"request_scope": "a", "ok": true}),
            });
            let response_b = protocol::ResponseEnvelope::Ok(protocol::Response {
                version: protocol::PROTOCOL_VERSION_V1,
                id: request_b.id.clone(),
                ok: true,
                result: serde_json::json!({"request_scope": "b", "ok": true}),
            });
            let session = "session-prop";
            let epoch = "epoch-prop";
            let now_ms = unix_time_ms();

            let first_a = journal.begin_request(session, epoch, &request_a, now_ms)?;
            prop_assert_eq!(
                first_a,
                EslBeginOutcome::Dispatch,
                "first request_id must dispatch"
            );
            journal.record_terminal_response(
                session,
                epoch,
                &request_a,
                &response_a,
                now_ms + 1,
            )?;

            let first_b = journal.begin_request(session, epoch, &request_b, now_ms + 2)?;
            prop_assert_eq!(
                first_b,
                EslBeginOutcome::Dispatch,
                "different request_id in same session/epoch must dispatch independently"
            );
            journal.record_terminal_response(
                session,
                epoch,
                &request_b,
                &response_b,
                now_ms + 3,
            )?;

            let replay_a = journal.begin_request(session, epoch, &request_a, now_ms + 4)?;
            match replay_a {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    response_a,
                    "request_id A duplicate must replay request_id A terminal response only"
                ),
                other => prop_assert!(
                    false,
                    "request_id A duplicate must replay after terminal record, got {other:?}"
                ),
            }

            let replay_b = journal.begin_request(session, epoch, &request_b, now_ms + 5)?;
            match replay_b {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    response_b,
                    "request_id B duplicate must replay request_id B terminal response only"
                ),
                other => prop_assert!(
                    false,
                    "request_id B duplicate must replay after terminal record, got {other:?}"
                ),
            }
        }

        #[test]
        fn test_esl_proptest_trace_duplicate_requests_are_terminally_idempotent(
            trace in prop::collection::vec((0_u8..6_u8, 0_u8..8_u8, 0_u8..8_u8), 0..48)
        ) {
            let mut journal = EslJournal::with_limits_for_test(60_000, 512, 8 << 20);
            let mut now_ms = unix_time_ms();
            let mut epoch = "epoch-trace-a".to_string();
            let session = "session-trace";
            let mut dispatch_counts: std::collections::BTreeMap<(String, String, String), usize> =
                std::collections::BTreeMap::new();

            for (kind, slot_raw, variant_raw) in trace {
                match kind % 6 {
                    0..=2 => {
                        let request = trace_request_for_slot(slot_raw, variant_raw);
                        let key = (session.to_string(), request.id.clone(), epoch.clone());
                        let outcome = journal.begin_request(session, &epoch, &request, now_ms)?;
                        if outcome == EslBeginOutcome::Dispatch {
                            let entry = dispatch_counts.entry(key).or_insert(0);
                            *entry = entry.saturating_add(1);
                        }
                    }
                    3 => {
                        // Record a terminal success for the canonical payload variant.
                        let request = trace_request_for_slot(slot_raw, 0);
                        let response = trace_terminal_response_for(&request, true);
                        journal.record_terminal_response(session, &epoch, &request, &response, now_ms)?;
                    }
                    4 => {
                        // Record a terminal failure for the canonical payload variant.
                        let request = trace_request_for_slot(slot_raw, 0);
                        let response = trace_terminal_response_for(&request, false);
                        journal.record_terminal_response(session, &epoch, &request, &response, now_ms)?;
                    }
                    5 => {
                        epoch = if epoch == "epoch-trace-a" {
                            format!("epoch-trace-b-{}", variant_raw % 4)
                        } else {
                            "epoch-trace-a".to_string()
                        };
                    }
                    _ => unreachable!("kind % 6 constrains the action space"),
                }
                now_ms = now_ms.saturating_add(1);
            }

            for ((sess, request_id, host_epoch), count) in &dispatch_counts {
                prop_assert!(
                    *count <= 1,
                    "ESL duplicate-delivery invariant violated: dispatch_count={count} for ({sess}, {request_id}, {host_epoch})",
                );
            }
        }

        #[test]
        fn test_esl_proptest_fingerprint_mismatch_rejects_without_corrupting_terminal_replay(
            canonical_payload in esl_json_value_strategy(),
            mismatched_payload in esl_json_value_strategy(),
        ) {
            prop_assume!(canonical_payload != mismatched_payload);

            let mut journal = EslJournal::with_limits_for_test(60_000, 64, 1 << 20);
            let canonical = sample_request_struct("req-esl-fingerprint", canonical_payload);
            let mismatched = sample_request_struct("req-esl-fingerprint", mismatched_payload);
            let response = sample_response_envelope_for("req-esl-fingerprint");
            let now_ms = unix_time_ms();

            let first = journal.begin_request("session-prop", "epoch-prop", &canonical, now_ms)?;
            prop_assert_eq!(
                first,
                EslBeginOutcome::Dispatch,
                "initial request must dispatch before a terminal replay can exist"
            );
            journal.record_terminal_response(
                "session-prop",
                "epoch-prop",
                &canonical,
                &response,
                now_ms + 1,
            )?;

            let mismatched_outcome = journal.begin_request(
                "session-prop",
                "epoch-prop",
                &mismatched,
                now_ms + 2,
            )?;
            match mismatched_outcome {
                EslBeginOutcome::Reject(protocol::ResponseEnvelope::Error(err)) => {
                    prop_assert_eq!(
                        err.error.code,
                        protocol::ProtocolErrorCode::ChromeBridgeProtocolMismatch,
                        "fingerprint mismatch must fail closed as invalid_request-class error"
                    );
                    prop_assert!(
                        err.error.message.starts_with("invalid_request:"),
                        "fingerprint mismatch reject should preserve invalid_request prefix"
                    );
                    prop_assert!(
                        !err.error.retryable,
                        "fingerprint mismatch reject must not be retryable"
                    );
                }
                other => prop_assert!(
                    false,
                    "fingerprint-mismatched duplicate must reject, got {other:?}"
                ),
            }

            let replay = journal.begin_request("session-prop", "epoch-prop", &canonical, now_ms + 3)?;
            match replay {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    response,
                    "mismatched duplicate must not corrupt canonical terminal replay"
                ),
                other => prop_assert!(
                    false,
                    "canonical duplicate after mismatch must still replay terminal response, got {other:?}"
                ),
            }
        }

        #[test]
        fn test_esl_proptest_in_progress_fingerprint_mismatch_rejects_without_corrupting_in_flight_state(
            canonical_payload in esl_json_value_strategy(),
            mismatched_payload in esl_json_value_strategy(),
        ) {
            prop_assume!(canonical_payload != mismatched_payload);

            let mut journal = EslJournal::with_limits_for_test(60_000, 64, 1 << 20);
            let canonical = sample_request_struct("req-esl-inprogress-mismatch", canonical_payload);
            let mismatched =
                sample_request_struct("req-esl-inprogress-mismatch", mismatched_payload);
            let response = sample_response_envelope_for("req-esl-inprogress-mismatch");
            let now_ms = unix_time_ms();

            let first = journal.begin_request("session-prop", "epoch-prop", &canonical, now_ms)?;
            prop_assert_eq!(
                first,
                EslBeginOutcome::Dispatch,
                "initial canonical request must dispatch and create in_progress entry"
            );

            let mismatched_outcome =
                journal.begin_request("session-prop", "epoch-prop", &mismatched, now_ms + 1)?;
            match mismatched_outcome {
                EslBeginOutcome::Reject(protocol::ResponseEnvelope::Error(err)) => {
                    prop_assert_eq!(
                        err.error.code,
                        protocol::ProtocolErrorCode::ChromeBridgeProtocolMismatch,
                        "fingerprint-mismatched duplicate must fail closed before busy handling"
                    );
                    prop_assert!(
                        !err.error.retryable,
                        "fingerprint mismatch must not be marked retryable"
                    );
                }
                other => prop_assert!(
                    false,
                    "in-progress fingerprint mismatch must reject invalid_request-style, got {other:?}"
                ),
            }

            let canonical_duplicate =
                journal.begin_request("session-prop", "epoch-prop", &canonical, now_ms + 2)?;
            match canonical_duplicate {
                EslBeginOutcome::Reject(protocol::ResponseEnvelope::Error(err)) => {
                    prop_assert_eq!(
                        err.error.code,
                        protocol::ProtocolErrorCode::ChromeBridgeBusy,
                        "mismatched duplicate must not corrupt canonical in_progress state"
                    );
                    prop_assert!(
                        err.error.retryable,
                        "canonical in-progress duplicate should remain retryable busy"
                    );
                }
                other => prop_assert!(
                    false,
                    "canonical duplicate should still be busy while request is in flight, got {other:?}"
                ),
            }

            journal.record_terminal_response(
                "session-prop",
                "epoch-prop",
                &canonical,
                &response,
                now_ms + 3,
            )?;

            let replay = journal.begin_request("session-prop", "epoch-prop", &canonical, now_ms + 4)?;
            match replay {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    response,
                    "mismatched in-progress duplicate must not corrupt canonical terminal replay"
                ),
                other => prop_assert!(
                    false,
                    "canonical duplicate after terminal record must replay, got {other:?}"
                ),
            }
        }

        #[test]
        fn test_esl_proptest_mismatched_terminal_record_is_noop_and_preserves_replay(
            canonical_payload in esl_json_value_strategy(),
            mismatched_payload in esl_json_value_strategy(),
            alt_terminal_ok in any::<bool>(),
        ) {
            prop_assume!(canonical_payload != mismatched_payload);

            let mut journal = EslJournal::with_limits_for_test(60_000, 64, 1 << 20);
            let canonical = sample_request_struct("req-esl-record-mismatch", canonical_payload);
            let mismatched = sample_request_struct("req-esl-record-mismatch", mismatched_payload);
            let canonical_response = sample_response_envelope_for("req-esl-record-mismatch");
            let mismatched_response = trace_terminal_response_for(&mismatched, alt_terminal_ok);
            let now_ms = unix_time_ms();

            let first = journal.begin_request("session-prop", "epoch-prop", &canonical, now_ms)?;
            prop_assert_eq!(
                first,
                EslBeginOutcome::Dispatch,
                "initial request must dispatch before terminal state can be recorded"
            );
            journal.record_terminal_response(
                "session-prop",
                "epoch-prop",
                &canonical,
                &canonical_response,
                now_ms + 1,
            )?;

            journal.record_terminal_response(
                "session-prop",
                "epoch-prop",
                &mismatched,
                &mismatched_response,
                now_ms + 2,
            )?;

            let replay = journal.begin_request("session-prop", "epoch-prop", &canonical, now_ms + 3)?;
            match replay {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    canonical_response,
                    "fingerprint-mismatched terminal record must be a no-op"
                ),
                other => prop_assert!(
                    false,
                    "canonical duplicate after mismatched terminal record must replay, got {other:?}"
                ),
            }
        }

        #[test]
        fn test_esl_proptest_terminal_replay_expires_at_ttl_boundary(
            payload in esl_json_value_strategy(),
            ttl_ms in 1_i64..5_000_i64,
        ) {
            let request = sample_request_struct("req-esl-ttl-boundary", payload);
            let response = sample_response_envelope_for("req-esl-ttl-boundary");
            let now_ms = unix_time_ms();
            let terminal_ms = now_ms + 1;

            let mut before_boundary = EslJournal::with_limits_for_test(ttl_ms, 64, 1 << 20);
            let first_before = before_boundary.begin_request(
                "session-prop",
                "epoch-prop",
                &request,
                now_ms,
            )?;
            prop_assert_eq!(
                first_before,
                EslBeginOutcome::Dispatch,
                "first request must dispatch"
            );
            before_boundary.record_terminal_response(
                "session-prop",
                "epoch-prop",
                &request,
                &response,
                terminal_ms,
            )?;
            let replay_before_boundary = before_boundary.begin_request(
                "session-prop",
                "epoch-prop",
                &request,
                terminal_ms + ttl_ms.saturating_sub(1),
            )?;
            match replay_before_boundary {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    response.clone(),
                    "terminal entry must replay strictly before TTL boundary"
                ),
                other => prop_assert!(
                    false,
                    "expected replay before TTL boundary, got {other:?}"
                ),
            }

            let mut at_boundary = EslJournal::with_limits_for_test(ttl_ms, 64, 1 << 20);
            let first_at = at_boundary.begin_request("session-prop", "epoch-prop", &request, now_ms)?;
            prop_assert_eq!(
                first_at,
                EslBeginOutcome::Dispatch,
                "first request must dispatch in independent journal"
            );
            at_boundary.record_terminal_response(
                "session-prop",
                "epoch-prop",
                &request,
                &response,
                terminal_ms,
            )?;
            let dispatch_at_boundary = at_boundary.begin_request(
                "session-prop",
                "epoch-prop",
                &request,
                terminal_ms + ttl_ms,
            )?;
            prop_assert_eq!(
                dispatch_at_boundary,
                EslBeginOutcome::Dispatch,
                "terminal replay cache must expire at TTL boundary (>= ttl)"
            );
        }

        #[test]
        fn test_esl_proptest_terminal_replay_refresh_extends_ttl_window(
            payload in esl_json_value_strategy(),
            ttl_ms in 2_i64..5_000_i64,
        ) {
            let request = sample_request_struct("req-esl-ttl-refresh", payload);
            let response = sample_response_envelope_for("req-esl-ttl-refresh");
            let now_ms = unix_time_ms();
            let terminal_ms = now_ms + 1;
            let replay_refresh_ms = terminal_ms + ttl_ms - 1;

            let mut extension_journal = EslJournal::with_limits_for_test(ttl_ms, 64, 1 << 20);
            let first = extension_journal.begin_request("session-prop", "epoch-prop", &request, now_ms)?;
            prop_assert_eq!(
                first,
                EslBeginOutcome::Dispatch,
                "first request must dispatch before terminal replay cache exists"
            );
            extension_journal.record_terminal_response(
                "session-prop",
                "epoch-prop",
                &request,
                &response,
                terminal_ms,
            )?;

            let replay_before_original_boundary = extension_journal.begin_request(
                "session-prop",
                "epoch-prop",
                &request,
                replay_refresh_ms,
            )?;
            match replay_before_original_boundary {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    response.clone(),
                    "terminal duplicate just before TTL boundary must replay"
                ),
                other => prop_assert!(
                    false,
                    "expected replay before original TTL boundary, got {other:?}"
                ),
            }

            let replay_after_original_boundary = extension_journal.begin_request(
                "session-prop",
                "epoch-prop",
                &request,
                terminal_ms + ttl_ms,
            )?;
            match replay_after_original_boundary {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    response.clone(),
                    "terminal replay should refresh TTL eligibility past the original boundary"
                ),
                other => prop_assert!(
                    false,
                    "terminal replay refresh must extend TTL window, got {other:?}"
                ),
            }

            let mut expiry_journal = EslJournal::with_limits_for_test(ttl_ms, 64, 1 << 20);
            let first_expiry = expiry_journal.begin_request("session-prop", "epoch-prop", &request, now_ms)?;
            prop_assert_eq!(
                first_expiry,
                EslBeginOutcome::Dispatch,
                "independent journal setup must dispatch initially"
            );
            expiry_journal.record_terminal_response(
                "session-prop",
                "epoch-prop",
                &request,
                &response,
                terminal_ms,
            )?;
            let replay_for_refresh = expiry_journal.begin_request(
                "session-prop",
                "epoch-prop",
                &request,
                replay_refresh_ms,
            )?;
            match replay_for_refresh {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    response.clone(),
                    "independent journal must replay at refresh point"
                ),
                other => prop_assert!(
                    false,
                    "independent journal expected replay at refresh point, got {other:?}"
                ),
            }

            let dispatch_at_refreshed_boundary = expiry_journal.begin_request(
                "session-prop",
                "epoch-prop",
                &request,
                replay_refresh_ms + ttl_ms,
            )?;
            prop_assert_eq!(
                dispatch_at_refreshed_boundary,
                EslBeginOutcome::Dispatch,
                "terminal replay cache must expire at the refreshed TTL boundary"
            );
        }

        #[test]
        fn test_esl_proptest_in_progress_entries_do_not_expire_via_ttl(
            payload in esl_json_value_strategy(),
            ttl_ms in 1_i64..5_000_i64,
            extra_idle_ms in 0_i64..5_000_i64,
        ) {
            let mut journal = EslJournal::with_limits_for_test(ttl_ms, 64, 1 << 20);
            let request = sample_request_struct("req-esl-inprogress-ttl", payload);
            let now_ms = unix_time_ms();

            let first = journal.begin_request("session-prop", "epoch-prop", &request, now_ms)?;
            prop_assert_eq!(
                first,
                EslBeginOutcome::Dispatch,
                "initial request must dispatch and create in_progress entry"
            );

            let duplicate = journal.begin_request(
                "session-prop",
                "epoch-prop",
                &request,
                now_ms + ttl_ms + extra_idle_ms,
            )?;
            match duplicate {
                EslBeginOutcome::Reject(protocol::ResponseEnvelope::Error(err)) => {
                    prop_assert_eq!(
                        err.error.code,
                        protocol::ProtocolErrorCode::ChromeBridgeBusy,
                        "TTL pruning must never evict in_progress entries"
                    );
                    prop_assert!(
                        err.error.retryable,
                        "in_progress duplicate rejects must remain retryable after long idle"
                    );
                }
                other => prop_assert!(
                    false,
                    "long-idle duplicate of in_progress request must reject busy, got {other:?}"
                ),
            }
        }

        #[test]
        fn test_esl_proptest_accounting_and_capacity_invariants_hold_across_trace(
            trace in prop::collection::vec((0_u8..8_u8, 0_u8..8_u8, 0_u8..8_u8, 0_u16..512_u16), 0..96)
        ) {
            let ttl_ms = 64_i64;
            let mut journal = EslJournal::with_limits_for_test(ttl_ms, 8, 16 << 10);
            let session = "session-accounting";
            let mut epoch = "epoch-accounting-a".to_string();
            let mut now_ms = unix_time_ms();

            for (kind, slot_raw, variant_raw, advance_raw) in trace {
                now_ms = now_ms.saturating_add(i64::from(advance_raw % 9));

                match kind % 8 {
                    0..=2 => {
                        let request = trace_request_for_slot(slot_raw, variant_raw);
                        let _ = journal.begin_request(session, &epoch, &request, now_ms)?;
                    }
                    3 => {
                        let request = trace_request_for_slot(slot_raw, 0);
                        let response = trace_terminal_response_for(&request, true);
                        journal.record_terminal_response(session, &epoch, &request, &response, now_ms)?;
                    }
                    4 => {
                        let request = trace_request_for_slot(slot_raw, 0);
                        let response = trace_terminal_response_for(&request, false);
                        journal.record_terminal_response(session, &epoch, &request, &response, now_ms)?;
                    }
                    5 => {
                        // Explicit prune step to exercise accounting cleanup independent of begin_request().
                        journal.prune_expired_terminal_entries(
                            now_ms.saturating_add(i64::from(advance_raw % 200)),
                        );
                    }
                    6 => {
                        epoch = if epoch == "epoch-accounting-a" {
                            format!("epoch-accounting-b-{}", variant_raw % 4)
                        } else {
                            "epoch-accounting-a".to_string()
                        };
                    }
                    7 => {
                        // Touching capacity checks with zero additional bytes should be a no-op success.
                        let _ = journal.ensure_capacity_for_new_entry(0, now_ms);
                    }
                    _ => unreachable!("kind % 8 constrains action space"),
                }

                let accounted_bytes: usize =
                    journal.entries.values().map(|entry| entry.approx_bytes).sum();
                prop_assert_eq!(
                    journal.current_bytes,
                    accounted_bytes,
                    "ESL byte accounting drifted from entry sum"
                );
                prop_assert!(
                    journal.entries.len() <= journal.max_entries,
                    "ESL entry count exceeded max_entries: {} > {}",
                    journal.entries.len(),
                    journal.max_entries
                );
                prop_assert!(
                    journal.current_bytes <= journal.max_bytes,
                    "ESL byte usage exceeded max_bytes: {} > {}",
                    journal.current_bytes,
                    journal.max_bytes
                );

                for entry in journal.entries.values() {
                    prop_assert!(
                        entry.last_access_ms >= entry.created_at_ms,
                        "ESL entry last_access_ms must not move before created_at_ms"
                    );
                    prop_assert!(
                        entry.approx_bytes > 0,
                        "ESL entry approx_bytes must remain positive for accounting safety"
                    );
                }
            }
        }

        #[test]
        fn test_esl_proptest_capacity_and_ttl_never_evict_unrelated_in_progress_entries(
            trace in prop::collection::vec((0_u8..8_u8, 0_u8..8_u8, 0_u16..512_u16), 0..96)
        ) {
            let mut journal = EslJournal::with_limits_for_test(32, 6, 8 << 10);
            let session = "session-progress-survival";
            let mut epoch = "epoch-progress-survival-a".to_string();
            let mut now_ms = unix_time_ms();

            for (kind, slot_raw, advance_raw) in trace {
                now_ms = now_ms.saturating_add(i64::from(advance_raw % 7));
                let prior_in_progress: Vec<EslJournalKey> = journal
                    .entries
                    .iter()
                    .filter_map(|(key, entry)| {
                        if matches!(entry.state, EslJournalState::InProgress) {
                            Some(key.clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                let terminal_target = match kind % 8 {
                    0..=3 => {
                        let request = trace_request_for_slot(slot_raw, 0);
                        let _ = journal.begin_request(session, &epoch, &request, now_ms)?;
                        None
                    }
                    4 => {
                        let request = trace_request_for_slot(slot_raw, 0);
                        let response = trace_terminal_response_for(&request, true);
                        journal.record_terminal_response(session, &epoch, &request, &response, now_ms)?;
                        Some(EslJournalKey {
                            pi_session_id: session.to_string(),
                            request_id: request.id,
                            host_epoch: epoch.clone(),
                        })
                    }
                    5 => {
                        let request = trace_request_for_slot(slot_raw, 0);
                        let response = trace_terminal_response_for(&request, false);
                        journal.record_terminal_response(session, &epoch, &request, &response, now_ms)?;
                        Some(EslJournalKey {
                            pi_session_id: session.to_string(),
                            request_id: request.id,
                            host_epoch: epoch.clone(),
                        })
                    }
                    6 => {
                        journal.prune_expired_terminal_entries(
                            now_ms.saturating_add(i64::from(advance_raw % 128)),
                        );
                        None
                    }
                    7 => {
                        epoch = if epoch == "epoch-progress-survival-a" {
                            "epoch-progress-survival-b".to_string()
                        } else {
                            "epoch-progress-survival-a".to_string()
                        };
                        None
                    }
                    _ => unreachable!("kind % 8 constrains action space"),
                };

                for key in prior_in_progress {
                    if terminal_target.as_ref() == Some(&key) {
                        continue;
                    }

                    let Some(entry) = journal.entries.get(&key) else {
                        prop_assert!(
                            false,
                            "capacity/ttl handling must never evict unrelated in_progress entry: {:?}",
                            key
                        );
                        continue;
                    };
                    prop_assert!(
                        matches!(entry.state, EslJournalState::InProgress),
                        "unrelated in_progress entry must remain in_progress under capacity/ttl pressure"
                    );
                }
            }
        }

        #[test]
        fn test_esl_proptest_terminal_replay_refreshes_lru_and_protects_recent_entry(
            payload_a in esl_json_value_strategy(),
            payload_b in esl_json_value_strategy(),
            payload_c in esl_json_value_strategy(),
            refresh_a in any::<bool>(),
        ) {
            let mut journal = EslJournal::with_limits_for_test(60_000, 2, 1 << 20);
            let req_a = sample_request_struct("req-esl-lru-a", payload_a);
            let req_b = sample_request_struct("req-esl-lru-b", payload_b);
            let req_c = sample_request_struct("req-esl-lru-c", payload_c);
            let resp_a = sample_response_envelope_for("req-esl-lru-a");
            let resp_b = sample_response_envelope_for("req-esl-lru-b");
            let now_ms = unix_time_ms();

            let first_a = journal.begin_request("session-prop", "epoch-prop", &req_a, now_ms)?;
            prop_assert_eq!(first_a, EslBeginOutcome::Dispatch, "A must dispatch initially");
            journal.record_terminal_response(
                "session-prop",
                "epoch-prop",
                &req_a,
                &resp_a,
                now_ms + 1,
            )?;

            let first_b = journal.begin_request("session-prop", "epoch-prop", &req_b, now_ms + 2)?;
            prop_assert_eq!(first_b, EslBeginOutcome::Dispatch, "B must dispatch initially");
            journal.record_terminal_response(
                "session-prop",
                "epoch-prop",
                &req_b,
                &resp_b,
                now_ms + 3,
            )?;

            let (replayed_req, replayed_resp, should_survive_id, should_evict_id) = if refresh_a {
                (&req_a, &resp_a, "req-esl-lru-a", "req-esl-lru-b")
            } else {
                (&req_b, &resp_b, "req-esl-lru-b", "req-esl-lru-a")
            };

            let replay_outcome =
                journal.begin_request("session-prop", "epoch-prop", replayed_req, now_ms + 4)?;
            match replay_outcome {
                EslBeginOutcome::Replay(replayed) => prop_assert_eq!(
                    replayed,
                    replayed_resp.clone(),
                    "terminal duplicate must replay cached response before LRU pressure"
                ),
                other => prop_assert!(
                    false,
                    "expected terminal replay when refreshing LRU recency, got {other:?}"
                ),
            }

            let c_outcome = journal.begin_request("session-prop", "epoch-prop", &req_c, now_ms + 5)?;
            prop_assert_eq!(
                c_outcome,
                EslBeginOutcome::Dispatch,
                "new request should dispatch after evicting one terminal entry under entry-cap pressure"
            );

            prop_assert!(
                journal.contains_key("session-prop", should_survive_id, "epoch-prop"),
                "replayed terminal entry should survive LRU eviction because replay refreshes recency"
            );
            prop_assert!(
                !journal.contains_key("session-prop", should_evict_id, "epoch-prop"),
                "non-replayed terminal entry should be evicted first as oldest terminal"
            );
            prop_assert!(
                journal.contains_key("session-prop", "req-esl-lru-c", "epoch-prop"),
                "new request should be inserted after terminal eviction"
            );
        }
    }

    #[test]
    fn test_native_host_auth_claim_accepts_and_updates_discovery_claim() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.startup().await.expect("startup should succeed");

            let response = host
                .handle_auth_claim(sample_auth_claim("secret-test-token"))
                .expect("auth claim should be processed");

            match response {
                protocol::MessageType::AuthOk(auth_ok) => {
                    assert_eq!(auth_ok.host_id, "host-test", "host_id in auth_ok");
                    assert_eq!(
                        auth_ok.host_epoch, "epoch-test",
                        "auth_ok should advertise current host epoch"
                    );
                    assert_eq!(
                        auth_ok.claimed_by.pi_session_id, "session-1",
                        "claim owner should match requester"
                    );
                }
                other => panic!("expected auth_ok, got {other:?}"),
            }

            assert_eq!(
                host.claimed_by(),
                Some(&protocol::ClaimedBy {
                    pi_session_id: "session-1".to_string(),
                    client_instance_id: "client-1".to_string(),
                }),
                "host should store exclusive claim state after auth_ok"
            );

            let raw = fs::read(host.discovery_path()).expect("read discovery");
            let record: DiscoveryRecord = serde_json::from_slice(&raw).expect("parse discovery");
            assert_eq!(
                record.claimed_by,
                host.claimed_by().cloned(),
                "discovery record should publish current claim holder for rendezvous selection"
            );
        });
    }

    #[test]
    fn test_native_host_auth_claim_rejects_token_mismatch() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.startup().await.expect("startup should succeed");

            let response = host
                .handle_auth_claim(sample_auth_claim("wrong-token"))
                .expect("handler should return protocol error response");

            match response {
                protocol::MessageType::Response(protocol::ResponseEnvelope::Error(err)) => {
                    assert_eq!(
                        err.error.code,
                        protocol::ProtocolErrorCode::ChromeBridgeAuthFailed,
                        "token mismatch must be rejected as auth failure"
                    );
                }
                other => panic!("expected auth failure response, got {other:?}"),
            }
            assert!(
                host.claimed_by().is_none(),
                "failed auth claim must not mutate exclusive claim state"
            );
        });
    }

    #[test]
    fn test_native_host_auth_claim_rejects_protocol_mismatch() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.startup().await.expect("startup should succeed");

            let mut claim = sample_auth_claim("secret-test-token");
            claim.protocol_min = protocol::PROTOCOL_MAX_SUPPORTED.saturating_add(1);
            claim.protocol_max = claim.protocol_min;

            let response = host
                .handle_auth_claim(claim)
                .expect("handler should return protocol mismatch response");

            match response {
                protocol::MessageType::Response(protocol::ResponseEnvelope::Error(err)) => {
                    assert_eq!(
                        err.error.code,
                        protocol::ProtocolErrorCode::ChromeBridgeProtocolMismatch,
                        "non-overlapping protocol range must be rejected"
                    );
                }
                other => panic!("expected protocol mismatch response, got {other:?}"),
            }
        });
    }

    #[test]
    fn test_native_host_auth_claim_enforces_exclusive_claim_with_same_session_reclaim() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.startup().await.expect("startup should succeed");

            let first = host
                .handle_auth_claim(sample_auth_claim("secret-test-token"))
                .expect("initial auth claim should succeed");
            assert!(
                matches!(first, protocol::MessageType::AuthOk(_)),
                "initial claim should be accepted"
            );

            let mut other_claim = sample_auth_claim("secret-test-token");
            other_claim.pi_session_id = "session-2".to_string();
            other_claim.client_instance_id = "client-2".to_string();
            let busy = host
                .handle_auth_claim(other_claim)
                .expect("busy rejection should be encoded as protocol message");
            match busy {
                protocol::MessageType::AuthBusy(auth_busy) => {
                    assert_eq!(
                        auth_busy.claimed_by.pi_session_id, "session-1",
                        "busy response must identify current claim holder"
                    );
                }
                other => panic!("expected auth_busy, got {other:?}"),
            }

            let reclaim = host
                .handle_auth_claim(sample_auth_claim("secret-test-token"))
                .expect("same-session reclaim should be allowed");
            assert!(
                matches!(reclaim, protocol::MessageType::AuthOk(_)),
                "same session/client should be able to reclaim during lease window"
            );
        });
    }

    #[test]
    fn test_native_host_socket_auth_claim_roundtrip_returns_auth_ok() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.startup().await.expect("startup should succeed");

            let socket_path = host.socket_path().to_path_buf();
            let client = std::thread::spawn(move || {
                let mut stream =
                    std::os::unix::net::UnixStream::connect(&socket_path).expect("client connect");
                let mut reader = std::io::BufReader::new(
                    stream
                        .try_clone()
                        .expect("clone client stream for buffered reads"),
                );
                send_frame(
                    &mut stream,
                    &protocol::MessageType::AuthClaim(sample_auth_claim("secret-test-token")),
                );
                read_frame(&mut reader)
            });

            let server_response = host
                .accept_and_handle_claim_for_test()
                .await
                .expect("server handshake should complete");
            assert!(
                matches!(server_response, protocol::MessageType::AuthOk(_)),
                "server should produce auth_ok for valid claim"
            );

            let client_response = client.join().expect("client thread join");
            match client_response {
                protocol::MessageType::AuthOk(auth_ok) => {
                    assert_eq!(auth_ok.host_id, "host-test", "roundtrip auth_ok host id");
                    assert_eq!(auth_ok.host_epoch, "epoch-test", "roundtrip host epoch");
                }
                other => panic!("expected auth_ok over socket roundtrip, got {other:?}"),
            }
        });
    }

    #[test]
    fn test_native_messaging_frame_roundtrip_preserves_json_payload() {
        let message =
            protocol::MessageType::Response(protocol::ResponseEnvelope::Ok(protocol::Response {
                version: protocol::PROTOCOL_VERSION_V1,
                id: "req-1".to_string(),
                ok: true,
                result: serde_json::json!({"title": "Example", "url": "https://example.test"}),
            }));

        let mut bytes = Vec::new();
        write_native_messaging_message(&mut bytes, &message)
            .expect("native messaging write should succeed");
        assert!(
            bytes.len() >= 4,
            "native messaging frame must include 4-byte LE length prefix"
        );
        let declared_len = u32::from_le_bytes(bytes[..4].try_into().expect("header")) as usize;
        assert_eq!(
            declared_len,
            bytes.len() - 4,
            "4-byte LE header must match serialized JSON payload length"
        );

        let mut cursor = std::io::Cursor::new(bytes);
        let decoded = read_native_messaging_message(&mut cursor)
            .expect("native messaging frame should roundtrip decode");
        assert_eq!(
            decoded, message,
            "native messaging codec must preserve message"
        );
    }

    #[test]
    fn test_native_messaging_frame_rejects_oversized_payload() {
        let oversized = vec![b'x'; protocol::MAX_SOCKET_FRAME_BYTES + 1];
        let err = write_native_messaging_frame(&mut Vec::new(), &oversized)
            .expect_err("payload larger than Chrome native messaging cap must be rejected");
        assert!(
            matches!(err, NativeHostError::NativeMessageFrameTooLarge { .. }),
            "expected native frame size error, got {err:?}"
        );
    }

    #[test]
    fn test_relay_agent_request_to_chrome_preserves_message_type_and_payload() {
        let request = protocol::MessageType::Request(protocol::Request {
            version: protocol::PROTOCOL_VERSION_V1,
            id: "req-relay-1".to_string(),
            op: "navigate".to_string(),
            payload: serde_json::json!({"url": "https://relay.test"}),
        });
        let agent_bytes = protocol::encode_frame(&request).expect("encode agent frame");
        let mut agent_reader = std::io::Cursor::new(agent_bytes);
        let mut chrome_writer = Vec::new();

        let relayed = relay_one_agent_message_to_chrome(&mut agent_reader, &mut chrome_writer)
            .expect("relay agent->chrome should succeed");
        assert_eq!(
            relayed, request,
            "relay helper should return parsed agent message"
        );

        let mut chrome_reader = std::io::Cursor::new(chrome_writer);
        let chrome_message = read_native_messaging_message(&mut chrome_reader)
            .expect("chrome native frame should decode");
        assert_eq!(
            chrome_message, request,
            "agent->chrome relay must preserve request type and payload"
        );
    }

    #[test]
    fn test_relay_chrome_messages_to_agent_preserves_order_and_type_integrity() {
        let response =
            protocol::MessageType::Response(protocol::ResponseEnvelope::Ok(protocol::Response {
                version: protocol::PROTOCOL_VERSION_V1,
                id: "req-relay-2".to_string(),
                ok: true,
                result: serde_json::json!({"ok": true}),
            }));
        let observation = protocol::MessageType::Observation(protocol::ObservationEvent {
            version: protocol::PROTOCOL_VERSION_V1,
            observer_id: "obs-1".to_string(),
            events: vec![protocol::ObservationEntry {
                kind: "load_complete".to_string(),
                message: Some("done".to_string()),
                source: Some("page".to_string()),
                url: Some("https://relay.test".to_string()),
                ts: 1_708_700_001,
            }],
        });

        let mut chrome_bytes = Vec::new();
        write_native_messaging_message(&mut chrome_bytes, &response).expect("write response frame");
        write_native_messaging_message(&mut chrome_bytes, &observation)
            .expect("write observation frame");

        let mut chrome_reader = std::io::Cursor::new(chrome_bytes);
        let mut agent_writer = Vec::new();
        let first = relay_one_chrome_message_to_agent(&mut chrome_reader, &mut agent_writer)
            .expect("relay response should succeed");
        let second = relay_one_chrome_message_to_agent(&mut chrome_reader, &mut agent_writer)
            .expect("relay observation should succeed");
        assert_eq!(
            first, response,
            "first relayed message should remain response"
        );
        assert_eq!(
            second, observation,
            "second relayed message should remain observation"
        );

        let mut agent_reader = std::io::Cursor::new(agent_writer);
        let decoded_first = read_agent_socket_message_blocking(&mut agent_reader)
            .expect("decode first agent frame");
        let decoded_second = read_agent_socket_message_blocking(&mut agent_reader)
            .expect("decode second agent frame");
        assert_eq!(
            decoded_first, response,
            "chrome->agent relay must preserve first message ordering"
        );
        assert_eq!(
            decoded_second, observation,
            "chrome->agent relay must preserve second message ordering and type"
        );
    }

    #[test]
    fn test_native_host_agent_to_chrome_roundtrip_relays_request_and_response() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.startup().await.expect("startup should succeed");

            let request = sample_request();
            let response = sample_response_for("req-e2e-1");
            let mut chrome_in = Vec::new();
            write_native_messaging_message(&mut chrome_in, &response)
                .expect("encode mock chrome response");
            let mut chrome_reader = std::io::Cursor::new(chrome_in);
            let mut chrome_writer = Vec::new();

            let socket_path = host.socket_path().to_path_buf();
            let request_for_client = request.clone();
            let client = std::thread::spawn(move || {
                let mut stream =
                    std::os::unix::net::UnixStream::connect(&socket_path).expect("client connect");
                let mut reader = std::io::BufReader::new(
                    stream.try_clone().expect("clone client stream for reads"),
                );

                send_frame(
                    &mut stream,
                    &protocol::MessageType::AuthClaim(sample_auth_claim("secret-test-token")),
                );
                let handshake = read_frame(&mut reader);
                send_frame(&mut stream, &request_for_client);
                let relayed_response = read_frame(&mut reader);
                (handshake, relayed_response)
            });

            let (handshake, forwarded_agent, forwarded_chrome) = host
                .accept_claim_and_relay_single_exchange_for_test(
                    &mut chrome_reader,
                    &mut chrome_writer,
                )
                .await
                .expect("host should complete auth + one relay exchange");

            assert!(
                matches!(handshake, protocol::MessageType::AuthOk(_)),
                "server handshake should succeed"
            );
            assert_eq!(
                forwarded_agent, request,
                "host must relay the agent request to Chrome native messaging unchanged"
            );
            assert_eq!(
                forwarded_chrome, response,
                "host must relay the Chrome response back to the agent unchanged"
            );

            let mut chrome_wire_reader = std::io::Cursor::new(chrome_writer);
            let decoded_forwarded_request = read_native_messaging_message(&mut chrome_wire_reader)
                .expect("decode forwarded request from chrome writer");
            assert_eq!(
                decoded_forwarded_request, request,
                "native messaging outbound bytes must encode the same request sent by agent"
            );

            let (client_handshake, client_response) = client.join().expect("client thread join");
            assert!(
                matches!(client_handshake, protocol::MessageType::AuthOk(_)),
                "client should observe auth_ok over the socket"
            );
            assert_eq!(
                client_response, response,
                "client should receive the relayed Chrome response over the socket"
            );
        });
    }

    #[test]
    fn test_native_host_run_with_io_relay_disconnect_clears_claim_and_updates_discovery() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.startup().await.expect("startup should succeed");

            let request = sample_request();
            let response = sample_response_for("req-e2e-1");
            let mut chrome_in = Vec::new();
            write_native_messaging_message(&mut chrome_in, &response)
                .expect("encode mock chrome response");
            let mut chrome_reader = std::io::Cursor::new(chrome_in);
            let mut chrome_writer = Vec::new();

            let socket_path = host.socket_path().to_path_buf();
            let request_for_client = request.clone();
            let response_for_client = response.clone();
            let client = std::thread::spawn(move || {
                let mut stream =
                    std::os::unix::net::UnixStream::connect(&socket_path).expect("client connect");
                let mut reader = std::io::BufReader::new(
                    stream.try_clone().expect("clone client stream for reads"),
                );

                send_frame(
                    &mut stream,
                    &protocol::MessageType::AuthClaim(sample_auth_claim("secret-test-token")),
                );
                let handshake = read_frame(&mut reader);
                send_frame(&mut stream, &request_for_client);
                let relayed_response = read_frame(&mut reader);
                assert_eq!(
                    relayed_response, response_for_client,
                    "client should receive forwarded chrome response before disconnecting"
                );
                handshake
            });

            let outcome = host
                .run_with_io(&mut chrome_reader, &mut chrome_writer)
                .await
                .expect("run_with_io should exit cleanly after agent disconnect");
            assert_eq!(
                outcome,
                NativeHostRunOutcome::AgentConnected,
                "run_with_io should report that an agent connected before disconnect"
            );

            let client_handshake = client.join().expect("client thread join");
            assert!(
                matches!(client_handshake, protocol::MessageType::AuthOk(_)),
                "client must observe auth_ok on successful claim"
            );

            assert!(
                host.claimed_by().is_none(),
                "host must clear exclusive claim state after relay loop exits on disconnect"
            );

            let raw = fs::read(host.discovery_path()).expect("read discovery after disconnect");
            let record: DiscoveryRecord =
                serde_json::from_slice(&raw).expect("parse discovery after disconnect");
            assert!(
                record.claimed_by.is_none(),
                "discovery record must clear claimed_by after agent disconnect"
            );

            let mut chrome_wire_reader = std::io::Cursor::new(chrome_writer);
            let decoded_forwarded_request = read_native_messaging_message(&mut chrome_wire_reader)
                .expect("decode forwarded request");
            assert_eq!(
                decoded_forwarded_request, request,
                "run_with_io must forward agent request to chrome native-messaging writer"
            );
        });
    }

    #[test]
    fn test_native_host_run_with_io_forwards_observation_before_terminal_response() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.startup().await.expect("startup should succeed");

            let request = sample_request();
            let observation = protocol::MessageType::Observation(protocol::ObservationEvent {
                version: protocol::PROTOCOL_VERSION_V1,
                observer_id: "observer-run-loop".to_string(),
                events: vec![protocol::ObservationEntry {
                    kind: "console_warn".to_string(),
                    message: Some("slow render".to_string()),
                    source: Some("page".to_string()),
                    url: Some("https://example.test".to_string()),
                    ts: unix_time_ms(),
                }],
            });
            let response = sample_response_for("req-e2e-1");
            let mut chrome_in = Vec::new();
            write_native_messaging_message(&mut chrome_in, &observation)
                .expect("encode mock chrome observation");
            write_native_messaging_message(&mut chrome_in, &response)
                .expect("encode mock chrome response");
            let mut chrome_reader = std::io::Cursor::new(chrome_in);
            let mut chrome_writer = Vec::new();

            let socket_path = host.socket_path().to_path_buf();
            let request_for_client = request.clone();
            let observation_for_client = observation.clone();
            let response_for_client = response.clone();
            let client = std::thread::spawn(move || {
                let mut stream =
                    std::os::unix::net::UnixStream::connect(&socket_path).expect("client connect");
                let mut reader = std::io::BufReader::new(
                    stream.try_clone().expect("clone client stream for reads"),
                );

                send_frame(
                    &mut stream,
                    &protocol::MessageType::AuthClaim(sample_auth_claim("secret-test-token")),
                );
                let handshake = read_frame(&mut reader);
                send_frame(&mut stream, &request_for_client);
                let relayed_observation = read_frame(&mut reader);
                let relayed_response = read_frame(&mut reader);
                (handshake, relayed_observation, relayed_response)
            });

            let outcome = host
                .run_with_io(&mut chrome_reader, &mut chrome_writer)
                .await
                .expect(
                    "run_with_io should relay observation + response and exit after disconnect",
                );
            assert_eq!(
                outcome,
                NativeHostRunOutcome::AgentConnected,
                "agent connection should be recorded on successful relay session"
            );

            let (client_handshake, client_observation, client_response) =
                client.join().expect("client thread join");
            assert!(
                matches!(client_handshake, protocol::MessageType::AuthOk(_)),
                "client must observe auth_ok before relay traffic"
            );
            assert_eq!(
                client_observation, observation_for_client,
                "run loop must forward observation messages before the terminal response"
            );
            assert_eq!(
                client_response, response_for_client,
                "run loop must forward terminal response after preceding observations"
            );

            let mut chrome_wire_reader = std::io::Cursor::new(chrome_writer);
            let decoded_forwarded_request = read_native_messaging_message(&mut chrome_wire_reader)
                .expect("decode forwarded request");
            assert_eq!(
                decoded_forwarded_request, request,
                "agent request forwarded to chrome must remain intact"
            );
        });
    }

    #[test]
    fn test_native_host_run_with_io_error_path_clears_claim_and_updates_discovery() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.startup().await.expect("startup should succeed");

            let request = sample_request();
            let mut chrome_in = Vec::new();
            write_native_messaging_frame(&mut chrome_in, b"{not-json")
                .expect("encode malformed chrome frame");
            let mut chrome_reader = std::io::Cursor::new(chrome_in);
            let mut chrome_writer = Vec::new();

            let socket_path = host.socket_path().to_path_buf();
            let request_for_client = request.clone();
            let client = std::thread::spawn(move || {
                let mut stream =
                    std::os::unix::net::UnixStream::connect(&socket_path).expect("client connect");
                let mut reader = std::io::BufReader::new(
                    stream.try_clone().expect("clone client stream for reads"),
                );

                send_frame(
                    &mut stream,
                    &protocol::MessageType::AuthClaim(sample_auth_claim("secret-test-token")),
                );
                let handshake = read_frame(&mut reader);
                assert!(
                    matches!(handshake, protocol::MessageType::AuthOk(_)),
                    "client must receive auth_ok before relay error is triggered"
                );
                send_frame(&mut stream, &request_for_client);
                // Drop connection after sending request; host should fail on malformed chrome payload.
            });

            let err = host
                .run_with_io(&mut chrome_reader, &mut chrome_writer)
                .await
                .expect_err("malformed chrome payload must surface as relay error");
            assert!(
                matches!(err, NativeHostError::NativeMessageJson(_)),
                "run loop should report malformed chrome payload as NativeMessageJson"
            );

            client.join().expect("client thread join");

            assert!(
                host.claimed_by().is_none(),
                "host must clear exclusive claim state even when relay exits with error"
            );

            let raw = fs::read(host.discovery_path()).expect("read discovery after relay error");
            let record: DiscoveryRecord =
                serde_json::from_slice(&raw).expect("parse discovery after relay error");
            assert!(
                record.claimed_by.is_none(),
                "discovery record must clear claimed_by after relay error"
            );

            let mut chrome_wire_reader = std::io::Cursor::new(chrome_writer);
            let decoded_forwarded_request = read_native_messaging_message(&mut chrome_wire_reader)
                .expect("decode forwarded request");
            assert_eq!(
                decoded_forwarded_request, request,
                "request should still be forwarded to Chrome before the malformed response error"
            );
        });
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_native_host_run_with_io_handles_multiple_request_cycles_with_observations() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.startup().await.expect("startup should succeed");

            let request1 = sample_request();
            let request2 = protocol::MessageType::Request(protocol::Request {
                version: protocol::PROTOCOL_VERSION_V1,
                id: "req-e2e-2".to_string(),
                op: "tabs_context".to_string(),
                payload: serde_json::json!({"tabId": 456}),
            });

            let observation1 = protocol::MessageType::Observation(protocol::ObservationEvent {
                version: protocol::PROTOCOL_VERSION_V1,
                observer_id: "observer-cycle-1".to_string(),
                events: vec![protocol::ObservationEntry {
                    kind: "navigation".to_string(),
                    message: Some("navigated".to_string()),
                    source: Some("page".to_string()),
                    url: Some("https://one.test".to_string()),
                    ts: unix_time_ms(),
                }],
            });
            let response1 = sample_response_for("req-e2e-1");
            let observation2 = protocol::MessageType::Observation(protocol::ObservationEvent {
                version: protocol::PROTOCOL_VERSION_V1,
                observer_id: "observer-cycle-2".to_string(),
                events: vec![protocol::ObservationEntry {
                    kind: "load_complete".to_string(),
                    message: Some("loaded".to_string()),
                    source: Some("page".to_string()),
                    url: Some("https://two.test".to_string()),
                    ts: unix_time_ms(),
                }],
            });
            let response2 = sample_response_for("req-e2e-2");

            let mut chrome_in = Vec::new();
            write_native_messaging_message(&mut chrome_in, &observation1)
                .expect("encode observation1");
            write_native_messaging_message(&mut chrome_in, &response1).expect("encode response1");
            write_native_messaging_message(&mut chrome_in, &observation2)
                .expect("encode observation2");
            write_native_messaging_message(&mut chrome_in, &response2).expect("encode response2");
            let mut chrome_reader = std::io::Cursor::new(chrome_in);
            let mut chrome_writer = Vec::new();

            let socket_path = host.socket_path().to_path_buf();
            let request1_for_client = request1.clone();
            let request2_for_client = request2.clone();
            let observation1_for_client = observation1.clone();
            let observation2_for_client = observation2.clone();
            let response1_for_client = response1.clone();
            let response2_for_client = response2.clone();
            let client = std::thread::spawn(move || {
                let mut stream =
                    std::os::unix::net::UnixStream::connect(&socket_path).expect("client connect");
                let mut reader = std::io::BufReader::new(
                    stream.try_clone().expect("clone client stream for reads"),
                );

                send_frame(
                    &mut stream,
                    &protocol::MessageType::AuthClaim(sample_auth_claim("secret-test-token")),
                );
                let handshake = read_frame(&mut reader);

                send_frame(&mut stream, &request1_for_client);
                let cycle1_obs = read_frame(&mut reader);
                let cycle1_resp = read_frame(&mut reader);

                send_frame(&mut stream, &request2_for_client);
                let cycle2_obs = read_frame(&mut reader);
                let cycle2_resp = read_frame(&mut reader);

                (
                    handshake,
                    cycle1_obs,
                    cycle1_resp,
                    cycle2_obs,
                    cycle2_resp,
                    observation1_for_client,
                    response1_for_client,
                    observation2_for_client,
                    response2_for_client,
                )
            });

            let outcome = host
                .run_with_io(&mut chrome_reader, &mut chrome_writer)
                .await
                .expect("run_with_io should process multiple relay cycles and exit on disconnect");
            assert_eq!(
                outcome,
                NativeHostRunOutcome::AgentConnected,
                "host should record that an agent connected for multi-cycle relay"
            );

            let (
                client_handshake,
                cycle1_obs,
                cycle1_resp,
                cycle2_obs,
                cycle2_resp,
                observation1_expected,
                response1_expected,
                observation2_expected,
                response2_expected,
            ) = client.join().expect("client thread join");
            assert!(
                matches!(client_handshake, protocol::MessageType::AuthOk(_)),
                "client must observe auth_ok before relay cycles begin"
            );
            assert_eq!(
                cycle1_obs, observation1_expected,
                "cycle 1 observation must be forwarded before cycle 1 response"
            );
            assert_eq!(
                cycle1_resp, response1_expected,
                "cycle 1 response must be forwarded after cycle 1 observation"
            );
            assert_eq!(
                cycle2_obs, observation2_expected,
                "cycle 2 observation must be forwarded before cycle 2 response"
            );
            assert_eq!(
                cycle2_resp, response2_expected,
                "cycle 2 response must be forwarded after cycle 2 observation"
            );

            let mut chrome_wire_reader = std::io::Cursor::new(chrome_writer);
            let forwarded1 = read_native_messaging_message(&mut chrome_wire_reader)
                .expect("decode forwarded request1");
            let forwarded2 = read_native_messaging_message(&mut chrome_wire_reader)
                .expect("decode forwarded request2");
            assert_eq!(
                forwarded1, request1,
                "first agent request must be forwarded to chrome in order"
            );
            assert_eq!(
                forwarded2, request2,
                "second agent request must be forwarded to chrome in order"
            );
        });
    }

    #[test]
    fn test_relay_until_disconnect_replays_duplicate_request_without_second_chrome_dispatch() {
        let (mut host_side, mut client_side) =
            std::os::unix::net::UnixStream::pair().expect("socket pair");
        host_side
            .set_nonblocking(false)
            .expect("host-side socket should be blocking");
        client_side
            .set_nonblocking(false)
            .expect("client-side socket should be blocking");

        let request = sample_request();
        let response = sample_response_for("req-e2e-1");
        let mut chrome_in = Vec::new();
        write_native_messaging_message(&mut chrome_in, &response)
            .expect("encode only one chrome response for first execution");
        let mut chrome_reader = std::io::Cursor::new(chrome_in);
        let mut chrome_writer = Vec::new();
        let mut journal = EslJournal::with_limits_for_test(60_000, 8, 1 << 20);

        let request_for_client = request.clone();
        let response_expected = response.clone();
        let client = std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(
                client_side
                    .try_clone()
                    .expect("clone client stream for buffered reads"),
            );

            send_frame(&mut client_side, &request_for_client);
            let first_response = read_frame(&mut reader);
            send_frame(&mut client_side, &request_for_client);
            let replayed_response = read_frame(&mut reader);
            (first_response, replayed_response, response_expected)
        });

        relay_until_disconnect(
            &mut host_side,
            &mut chrome_reader,
            &mut chrome_writer,
            "session-1",
            "epoch-1",
            &mut journal,
        )
        .expect("relay loop should replay duplicate request and exit on client disconnect");

        let (first_response, replayed_response, response_expected) =
            client.join().expect("client thread join");
        assert_eq!(
            first_response, response_expected,
            "first request should receive the Chrome terminal response"
        );
        assert_eq!(
            replayed_response, response_expected,
            "duplicate request should replay the cached terminal response"
        );

        let mut chrome_wire_reader = std::io::Cursor::new(chrome_writer);
        let forwarded = read_native_messaging_message(&mut chrome_wire_reader)
            .expect("first request should be forwarded to Chrome");
        assert_eq!(
            forwarded, request,
            "only the first duplicate request should be dispatched to Chrome"
        );
        let err = read_native_messaging_message(&mut chrome_wire_reader)
            .expect_err("duplicate request replay should avoid a second Chrome dispatch");
        match err {
            NativeHostError::Io { source, .. } => assert_eq!(
                source.kind(),
                std::io::ErrorKind::UnexpectedEof,
                "Chrome wire should contain exactly one dispatched request frame"
            ),
            other => panic!("expected EOF after one Chrome dispatch, got {other:?}"),
        }
        assert_eq!(
            journal.terminal_count(),
            1,
            "journal should retain one terminal entry for the replayed request"
        );
    }

    #[test]
    fn test_native_host_run_with_io_returns_indeterminate_when_esl_caps_are_unsafely_exhausted() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let mut host = NativeHost::new(test_config(tempdir.path())).expect("host init");
            host.journal = EslJournal::with_limits_for_test(60_000, 0, 1 << 20);
            host.startup().await.expect("startup should succeed");

            let request = sample_request();
            let mut chrome_reader = std::io::Cursor::new(Vec::<u8>::new());
            let mut chrome_writer = Vec::new();

            let socket_path = host.socket_path().to_path_buf();
            let request_for_client = request.clone();
            let client = std::thread::spawn(move || {
                let mut stream =
                    std::os::unix::net::UnixStream::connect(&socket_path).expect("client connect");
                let mut reader = std::io::BufReader::new(
                    stream.try_clone().expect("clone client stream for reads"),
                );

                send_frame(
                    &mut stream,
                    &protocol::MessageType::AuthClaim(sample_auth_claim("secret-test-token")),
                );
                let handshake = read_frame(&mut reader);
                send_frame(&mut stream, &request_for_client);
                let reject = read_frame(&mut reader);
                (handshake, reject)
            });

            let outcome = host
                .run_with_io(&mut chrome_reader, &mut chrome_writer)
                .await
                .expect("indeterminate ESL reject should still exit run loop cleanly");
            assert_eq!(
                outcome,
                NativeHostRunOutcome::AgentConnected,
                "host should still report successful agent connection before ESL reject"
            );

            let (handshake, reject) = client.join().expect("client thread join");
            assert!(
                matches!(handshake, protocol::MessageType::AuthOk(_)),
                "client must observe auth_ok before ESL indeterminate reject"
            );
            match reject {
                protocol::MessageType::Response(protocol::ResponseEnvelope::Error(err)) => {
                    assert_eq!(
                        err.error.code,
                        protocol::ProtocolErrorCode::ChromeBridgeExecutionIndeterminate,
                        "unsafe ESL cap exhaustion must fail closed as indeterminate"
                    );
                }
                other => panic!("expected ESL indeterminate error response, got {other:?}"),
            }

            assert!(
                chrome_writer.is_empty(),
                "indeterminate ESL reject must not dispatch the request to Chrome"
            );
        });
    }
}
