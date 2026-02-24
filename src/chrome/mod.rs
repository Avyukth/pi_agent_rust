//! Chrome integration modules (Pi Chrome).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use asupersync::channel::oneshot;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::unix::{OwnedReadHalf, OwnedWriteHalf, UnixStream};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod protocol;

const DEFAULT_DISCOVERY_DIR: &str = "/tmp";
const DISCOVERY_PREFIX: &str = "pi-chrome-host-";
const DISCOVERY_SUFFIX: &str = ".discovery.json";
const DEFAULT_MAX_RECONNECT_ATTEMPTS: u8 = 3;
const DEFAULT_RECONNECT_BACKOFF_MS: u64 = 1000;

type PendingResponses = HashMap<String, oneshot::Sender<protocol::ResponseEnvelope>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    Connected,
    Disabled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChromeBridgeStatus {
    pub state: ConnectionState,
    pub pinned_host_id: Option<String>,
    pub host_epoch: Option<String>,
    pub consecutive_failures: u8,
    pub browser_tools_disabled: bool,
}

#[derive(Debug, Clone)]
pub struct ChromeBridgeConfig {
    pub pi_session_id: String,
    pub client_instance_id: String,
    pub discovery_dir: PathBuf,
    pub want_capabilities: Vec<String>,
    pub max_reconnect_attempts: u8,
    pub reconnect_backoff_ms: u64,
}

impl ChromeBridgeConfig {
    #[must_use]
    pub fn new(pi_session_id: impl Into<String>, client_instance_id: impl Into<String>) -> Self {
        Self {
            pi_session_id: pi_session_id.into(),
            client_instance_id: client_instance_id.into(),
            discovery_dir: PathBuf::from(DEFAULT_DISCOVERY_DIR),
            want_capabilities: vec!["browser_tools".to_string(), "observations".to_string()],
            max_reconnect_attempts: DEFAULT_MAX_RECONNECT_ATTEMPTS,
            reconnect_backoff_ms: DEFAULT_RECONNECT_BACKOFF_MS,
        }
    }
}

impl Default for ChromeBridgeConfig {
    fn default() -> Self {
        Self::new("pi-session", "pi-client")
    }
}

#[derive(Debug)]
pub struct ChromeBridge {
    config: ChromeBridgeConfig,
    inner: Arc<StdMutex<ChromeBridgeInner>>,
    writer: Arc<StdMutex<Option<OwnedWriteHalf>>>,
    pending: Arc<StdMutex<PendingResponses>>,
    observations: Arc<StdMutex<Vec<protocol::ObservationEvent>>>,
    request_seq: AtomicU64,
    connection_seq: AtomicU64,
}

#[derive(Debug)]
struct ChromeBridgeInner {
    state: ConnectionState,
    pinned_host_id: Option<String>,
    host_epoch: Option<String>,
    consecutive_failures: u8,
    browser_tools_disabled: bool,
    connection_token: u64,
}

impl ChromeBridge {
    #[must_use]
    pub fn new(config: ChromeBridgeConfig) -> Self {
        Self {
            config,
            inner: Arc::new(StdMutex::new(ChromeBridgeInner {
                state: ConnectionState::Disconnected,
                pinned_host_id: None,
                host_epoch: None,
                consecutive_failures: 0,
                browser_tools_disabled: false,
                connection_token: 0,
            })),
            writer: Arc::new(StdMutex::new(None)),
            pending: Arc::new(StdMutex::new(HashMap::new())),
            observations: Arc::new(StdMutex::new(Vec::new())),
            request_seq: AtomicU64::new(1),
            connection_seq: AtomicU64::new(1),
        }
    }

    #[must_use]
    pub fn status(&self) -> ChromeBridgeStatus {
        let guard = self.inner.lock().expect("chrome bridge mutex poisoned");
        ChromeBridgeStatus {
            state: guard.state,
            pinned_host_id: guard.pinned_host_id.clone(),
            host_epoch: guard.host_epoch.clone(),
            consecutive_failures: guard.consecutive_failures,
            browser_tools_disabled: guard.browser_tools_disabled,
        }
    }

    pub fn disconnect(&self) -> Result<(), ChromeBridgeError> {
        self.writer
            .lock()
            .expect("chrome bridge writer mutex poisoned")
            .take();
        self.pending
            .lock()
            .expect("pending responses mutex poisoned")
            .clear();
        let mut guard = self.inner.lock().expect("chrome bridge mutex poisoned");
        guard.connection_token = 0;
        guard.state = if guard.browser_tools_disabled {
            ConnectionState::Disabled
        } else {
            ConnectionState::Disconnected
        };
        Ok(())
    }

    pub async fn connect(&self) -> Result<(), ChromeBridgeError> {
        if self.status().browser_tools_disabled {
            return Err(ChromeBridgeError::BrowserToolsDisabled);
        }

        let attempts = self.config.max_reconnect_attempts.max(1);
        let mut last_error: Option<ChromeBridgeError> = None;

        for attempt_idx in 0..attempts {
            self.set_state(ConnectionState::Connecting);
            let records = match self.discover_hosts() {
                Ok(records) => records,
                Err(err) => {
                    last_error = Some(err);
                    if attempt_idx + 1 < attempts {
                        asupersync::time::sleep(
                            asupersync::time::wall_now(),
                            Duration::from_millis(self.config.reconnect_backoff_ms),
                        )
                        .await;
                    }
                    continue;
                }
            };
            if records.is_empty() {
                last_error = Some(ChromeBridgeError::NoHostsFound);
            } else {
                for record in records {
                    match self.connect_to_record(&record).await {
                        Ok(()) => {
                            self.reset_failure_streak();
                            return Ok(());
                        }
                        Err(ChromeBridgeError::AuthBusy { .. }) => {
                            last_error = Some(ChromeBridgeError::AuthBusy {
                                host_id: record.host_id.clone(),
                                claimed_by: record.claimed_by.clone(),
                            });
                            continue;
                        }
                        Err(err) => {
                            last_error = Some(err);
                        }
                    }
                }
            }

            if attempt_idx + 1 < attempts {
                asupersync::time::sleep(
                    asupersync::time::wall_now(),
                    Duration::from_millis(self.config.reconnect_backoff_ms),
                )
                .await;
            }
        }

        self.record_failure();
        Err(last_error.unwrap_or(ChromeBridgeError::NoHostsFound))
    }

    pub async fn connect_to_record(
        &self,
        record: &DiscoveryRecord,
    ) -> Result<(), ChromeBridgeError> {
        if self.status().browser_tools_disabled {
            return Err(ChromeBridgeError::BrowserToolsDisabled);
        }

        let _ = self.disconnect();
        self.set_state(ConnectionState::Connecting);
        let mut stream = UnixStream::connect(&record.socket_path)
            .await
            .map_err(ChromeBridgeError::Io)?;

        self.set_state(ConnectionState::Authenticating);
        let auth_ok = match self.authenticate_stream(&mut stream, record).await {
            Ok(auth_ok) => auth_ok,
            Err(err) => {
                self.set_state(ConnectionState::Disconnected);
                return Err(err);
            }
        };

        let (read_half, write_half) = stream.into_split();
        {
            let mut writer_guard = self
                .writer
                .lock()
                .expect("chrome bridge writer mutex poisoned");
            *writer_guard = Some(write_half);
        }
        let connection_token = self.connection_seq.fetch_add(1, Ordering::Relaxed);
        {
            let mut guard = self.inner.lock().expect("chrome bridge mutex poisoned");
            guard.pinned_host_id = Some(auth_ok.host_id.clone());
            guard.host_epoch = Some(auth_ok.host_epoch.clone());
            guard.consecutive_failures = 0;
            guard.browser_tools_disabled = false;
            guard.connection_token = connection_token;
            guard.state = ConnectionState::Connected;
        }
        self.spawn_reader_thread(read_half, connection_token);
        Ok(())
    }

    pub fn discover_hosts(&self) -> Result<Vec<DiscoveryRecord>, ChromeBridgeError> {
        let now_ms = unix_time_ms();
        let pinned_host_id = self.status().pinned_host_id;
        discover_hosts_in_dir(
            &self.config.discovery_dir,
            now_ms,
            pinned_host_id.as_deref(),
        )
    }

    #[must_use]
    pub fn next_request_id(&self) -> String {
        let seq = self.request_seq.fetch_add(1, Ordering::Relaxed);
        format!("chrome-{seq}")
    }

    pub async fn send_request(
        &self,
        op: impl Into<String>,
        payload: serde_json::Value,
    ) -> Result<protocol::ResponseEnvelope, ChromeBridgeError> {
        if self.status().state != ConnectionState::Connected {
            return Err(ChromeBridgeError::NotConnected);
        }

        let request = protocol::Request {
            version: protocol::PROTOCOL_VERSION_V1,
            id: self.next_request_id(),
            op: op.into(),
            payload,
        };
        let request_id = request.id.clone();
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .expect("pending responses mutex poisoned")
            .insert(request_id.clone(), tx);

        let write_result = async {
            let mut writer_guard = self
                .writer
                .lock()
                .expect("chrome bridge writer mutex poisoned");
            let writer = writer_guard
                .as_mut()
                .ok_or(ChromeBridgeError::NotConnected)?;
            write_request_frame(writer, &protocol::MessageType::Request(request)).await
        }
        .await;

        if let Err(err) = write_result {
            self.pending
                .lock()
                .expect("pending responses mutex poisoned")
                .remove(&request_id);
            self.mark_disconnected();
            return Err(err);
        }

        let cx = asupersync::Cx::for_request();
        rx.recv(&cx)
            .await
            .map_err(|_| ChromeBridgeError::ResponseChannelClosed { request_id })
    }

    #[must_use]
    pub fn pending_response_count(&self) -> usize {
        self.pending
            .lock()
            .expect("pending responses mutex poisoned")
            .len()
    }

    #[must_use]
    pub fn observation_buffer_len(&self) -> usize {
        self.observations
            .lock()
            .expect("observations mutex poisoned")
            .len()
    }

    pub fn take_observations(&self) -> Vec<protocol::ObservationEvent> {
        let mut guard = self
            .observations
            .lock()
            .expect("observations mutex poisoned");
        std::mem::take(&mut *guard)
    }

    async fn authenticate_stream(
        &self,
        stream: &mut UnixStream,
        record: &DiscoveryRecord,
    ) -> Result<protocol::AuthOk, ChromeBridgeError> {
        let auth_claim = protocol::MessageType::AuthClaim(protocol::AuthClaim {
            version: protocol::PROTOCOL_VERSION_V1,
            host_id: record.host_id.clone(),
            pi_session_id: self.config.pi_session_id.clone(),
            client_instance_id: self.config.client_instance_id.clone(),
            token: record.token.clone(),
            protocol_min: protocol::PROTOCOL_MIN_SUPPORTED,
            protocol_max: protocol::PROTOCOL_MAX_SUPPORTED,
            want_capabilities: self.config.want_capabilities.clone(),
        });
        write_message(stream, &auth_claim).await?;

        let message = read_message(stream).await?;
        match message {
            protocol::MessageType::AuthOk(auth_ok) => {
                if auth_ok.protocol < protocol::PROTOCOL_MIN_SUPPORTED
                    || auth_ok.protocol > protocol::PROTOCOL_MAX_SUPPORTED
                {
                    return Err(ChromeBridgeError::ProtocolMismatch(format!(
                        "host negotiated unsupported protocol {}",
                        auth_ok.protocol
                    )));
                }
                Ok(auth_ok)
            }
            protocol::MessageType::AuthBusy(auth_busy) => Err(ChromeBridgeError::AuthBusy {
                host_id: auth_busy.host_id,
                claimed_by: Some(auth_busy.claimed_by),
            }),
            protocol::MessageType::Response(protocol::ResponseEnvelope::Error(err))
                if err.error.code == protocol::ProtocolErrorCode::ChromeBridgeProtocolMismatch =>
            {
                Err(ChromeBridgeError::ProtocolMismatch(err.error.message))
            }
            protocol::MessageType::Response(protocol::ResponseEnvelope::Error(err))
                if err.error.code == protocol::ProtocolErrorCode::ChromeBridgeAuthFailed =>
            {
                Err(ChromeBridgeError::AuthRejected(err.error.message))
            }
            other => Err(ChromeBridgeError::UnexpectedHandshakeMessage(format!(
                "{other:?}"
            ))),
        }
    }

    fn set_state(&self, state: ConnectionState) {
        let mut guard = self.inner.lock().expect("chrome bridge mutex poisoned");
        guard.state = state;
    }

    fn spawn_reader_thread(&self, read_half: OwnedReadHalf, connection_token: u64) {
        let pending = Arc::clone(&self.pending);
        let observations = Arc::clone(&self.observations);
        let inner = Arc::clone(&self.inner);
        let writer = Arc::clone(&self.writer);

        let _reader = std::thread::spawn(move || {
            let runtime = match asupersync::runtime::RuntimeBuilder::current_thread().build() {
                Ok(runtime) => runtime,
                Err(err) => {
                    tracing::debug!("chrome reader runtime init failed: {err}");
                    finalize_reader_shutdown(connection_token, &inner, &writer, &pending);
                    return;
                }
            };

            let result = runtime.block_on(reader_loop(
                read_half,
                Arc::clone(&pending),
                Arc::clone(&observations),
            ));
            if let Err(err) = result {
                tracing::debug!("chrome reader loop exited with error: {err}");
            }
            finalize_reader_shutdown(connection_token, &inner, &writer, &pending);
        });
    }

    fn mark_disconnected(&self) {
        self.writer
            .lock()
            .expect("chrome bridge writer mutex poisoned")
            .take();
        let mut guard = self.inner.lock().expect("chrome bridge mutex poisoned");
        guard.connection_token = 0;
        if guard.state != ConnectionState::Disabled {
            guard.state = ConnectionState::Disconnected;
        }
    }

    fn reset_failure_streak(&self) {
        let mut guard = self.inner.lock().expect("chrome bridge mutex poisoned");
        guard.consecutive_failures = 0;
        guard.browser_tools_disabled = false;
        if guard.state == ConnectionState::Disabled {
            guard.state = ConnectionState::Disconnected;
        }
    }

    fn record_failure(&self) {
        self.writer
            .lock()
            .expect("chrome bridge writer mutex poisoned")
            .take();
        let mut guard = self.inner.lock().expect("chrome bridge mutex poisoned");
        guard.consecutive_failures = guard.consecutive_failures.saturating_add(1);
        guard.connection_token = 0;
        if guard.consecutive_failures >= self.config.max_reconnect_attempts.max(1) {
            guard.browser_tools_disabled = true;
            guard.state = ConnectionState::Disabled;
        } else {
            guard.state = ConnectionState::Disconnected;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryRecord {
    pub host_id: String,
    pub host_epoch: String,
    #[serde(alias = "socket")]
    pub socket_path: PathBuf,
    pub token: String,
    #[serde(
        default = "default_protocol_min",
        alias = "protocolMin",
        alias = "protocol_min_version"
    )]
    pub protocol_min: u16,
    #[serde(
        default = "default_protocol_max",
        alias = "protocolMax",
        alias = "protocol_max_version"
    )]
    pub protocol_max: u16,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub claimed_by: Option<protocol::ClaimedBy>,
    #[serde(default, alias = "lease_expires_at")]
    pub lease_expires_at_ms: Option<i64>,
    #[serde(default, alias = "expires_at", alias = "discovery_expires_at")]
    pub expires_at_ms: Option<i64>,
}

impl DiscoveryRecord {
    #[must_use]
    pub fn is_expired(&self, now_ms: i64) -> bool {
        self.expires_at_ms.is_some_and(|ts| ts <= now_ms)
    }
}

const fn default_protocol_min() -> u16 {
    protocol::PROTOCOL_MIN_SUPPORTED
}

const fn default_protocol_max() -> u16 {
    protocol::PROTOCOL_MAX_SUPPORTED
}

#[derive(Debug, Error)]
pub enum ChromeBridgeError {
    #[error("browser tools disabled for this session after consecutive failures")]
    BrowserToolsDisabled,
    #[error("no valid chrome host discovery records found")]
    NoHostsFound,
    #[error("failed to read discovery directory {path}: {source}")]
    DiscoveryDirRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to read discovery record {path}: {source}")]
    DiscoveryFileRead {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse discovery record {path}: {source}")]
    DiscoveryFileParse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("chrome bridge I/O error: {0}")]
    Io(std::io::Error),
    #[error("chrome bridge frame codec error: {0}")]
    Frame(#[from] protocol::FrameCodecError),
    #[error("chrome bridge is not connected")]
    NotConnected,
    #[error("response channel closed before request {request_id} completed")]
    ResponseChannelClosed { request_id: String },
    #[error("host {host_id} is busy (claimed_by={claimed_by:?})")]
    AuthBusy {
        host_id: String,
        claimed_by: Option<protocol::ClaimedBy>,
    },
    #[error("chrome bridge auth rejected: {0}")]
    AuthRejected(String),
    #[error("chrome bridge protocol mismatch: {0}")]
    ProtocolMismatch(String),
    #[error("unexpected handshake message: {0}")]
    UnexpectedHandshakeMessage(String),
}

fn discover_hosts_in_dir(
    dir: &Path,
    now_ms: i64,
    pinned_host_id: Option<&str>,
) -> Result<Vec<DiscoveryRecord>, ChromeBridgeError> {
    let entries = fs::read_dir(dir).map_err(|source| ChromeBridgeError::DiscoveryDirRead {
        path: dir.to_path_buf(),
        source,
    })?;

    let mut discovered = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                // Keep discovery robust under concurrent file churn.
                tracing::debug!("Skipping unreadable discovery entry: {err}");
                continue;
            }
        };

        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !name.starts_with(DISCOVERY_PREFIX) || !name.ends_with(DISCOVERY_SUFFIX) {
            continue;
        }

        let raw = fs::read(&path).map_err(|source| ChromeBridgeError::DiscoveryFileRead {
            path: path.clone(),
            source,
        })?;
        let record: DiscoveryRecord = serde_json::from_slice(&raw).map_err(|source| {
            ChromeBridgeError::DiscoveryFileParse {
                path: path.clone(),
                source,
            }
        })?;

        if record.is_expired(now_ms) {
            continue;
        }
        if !record.socket_path.exists() {
            continue;
        }
        discovered.push(record);
    }

    discovered.sort_by(|a, b| a.host_id.cmp(&b.host_id));
    if let Some(pinned) = pinned_host_id {
        discovered.sort_by_key(|record| if record.host_id == pinned { 0_u8 } else { 1_u8 });
    }
    Ok(discovered)
}

async fn write_message(
    stream: &mut UnixStream,
    message: &protocol::MessageType,
) -> Result<(), ChromeBridgeError> {
    let frame = protocol::encode_frame(message)?;
    stream
        .write_all(&frame)
        .await
        .map_err(ChromeBridgeError::Io)
}

async fn read_message(stream: &mut UnixStream) -> Result<protocol::MessageType, ChromeBridgeError> {
    let mut buf = Vec::with_capacity(256);
    loop {
        let byte = stream.read_u8().await.map_err(ChromeBridgeError::Io)?;
        buf.push(byte);
        if let Some((message, consumed)) = protocol::decode_frame::<protocol::MessageType>(&buf)? {
            if consumed != buf.len() {
                return Err(ChromeBridgeError::UnexpectedHandshakeMessage(
                    "multiple frames in single handshake read not yet supported".to_string(),
                ));
            }
            return Ok(message);
        }
    }
}

fn finalize_reader_shutdown(
    connection_token: u64,
    inner: &Arc<StdMutex<ChromeBridgeInner>>,
    writer: &Arc<StdMutex<Option<OwnedWriteHalf>>>,
    pending: &Arc<StdMutex<PendingResponses>>,
) {
    let should_finalize = {
        let mut guard = inner.lock().expect("chrome bridge mutex poisoned");
        if guard.connection_token != connection_token {
            false
        } else {
            guard.connection_token = 0;
            if guard.state != ConnectionState::Disabled {
                guard.state = ConnectionState::Disconnected;
            }
            true
        }
    };

    if should_finalize {
        pending
            .lock()
            .expect("pending responses mutex poisoned")
            .clear();
        writer
            .lock()
            .expect("chrome bridge writer mutex poisoned")
            .take();
    }
}

async fn reader_loop(
    mut read_half: OwnedReadHalf,
    pending: Arc<StdMutex<PendingResponses>>,
    observations: Arc<StdMutex<Vec<protocol::ObservationEvent>>>,
) -> Result<(), ChromeBridgeError> {
    let cx = asupersync::Cx::for_request();
    let mut buf = Vec::with_capacity(1024);

    loop {
        let byte = read_half.read_u8().await.map_err(ChromeBridgeError::Io)?;
        buf.push(byte);

        if let Some((message, consumed)) = protocol::decode_frame::<protocol::MessageType>(&buf)? {
            if consumed != buf.len() {
                let trailing = buf.split_off(consumed);
                buf = trailing;
            } else {
                buf.clear();
            }

            match message {
                protocol::MessageType::Response(envelope) => {
                    let id = match &envelope {
                        protocol::ResponseEnvelope::Ok(resp) => resp.id.clone(),
                        protocol::ResponseEnvelope::Error(resp) => resp.id.clone(),
                    };
                    if let Some(sender) = pending
                        .lock()
                        .expect("pending responses mutex poisoned")
                        .remove(&id)
                    {
                        let _ = sender.send(&cx, envelope);
                    }
                }
                protocol::MessageType::Observation(obs) => {
                    observations
                        .lock()
                        .expect("observations mutex poisoned")
                        .push(obs);
                }
                _ => {}
            }
        }
    }
}

async fn write_request_frame(
    write_half: &mut OwnedWriteHalf,
    message: &protocol::MessageType,
) -> Result<(), ChromeBridgeError> {
    let frame = protocol::encode_frame(message)?;
    write_half
        .write_all(&frame)
        .await
        .map_err(ChromeBridgeError::Io)
}

fn unix_time_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0));
    i64::try_from(now.as_millis()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    use asupersync::runtime::RuntimeBuilder;
    use futures::future;
    use serde_json::json;
    use std::io::{BufRead, Write};
    use std::os::unix::net::UnixListener as StdUnixListener;

    fn run_async<T>(future: impl std::future::Future<Output = T>) -> T {
        let runtime = RuntimeBuilder::current_thread()
            .build()
            .expect("runtime build");
        runtime.block_on(future)
    }

    fn write_discovery_record(path: &Path, record: &DiscoveryRecord) {
        std::fs::write(
            path,
            serde_json::to_vec(record).expect("serialize discovery record"),
        )
        .expect("write discovery record");
    }

    fn make_record(socket_path: &Path, host_id: &str) -> DiscoveryRecord {
        DiscoveryRecord {
            host_id: host_id.to_string(),
            host_epoch: format!("{host_id}-epoch"),
            socket_path: socket_path.to_path_buf(),
            token: "secret-token".to_string(),
            protocol_min: protocol::PROTOCOL_MIN_SUPPORTED,
            protocol_max: protocol::PROTOCOL_MAX_SUPPORTED,
            capabilities: vec!["browser_tools".to_string(), "observations".to_string()],
            claimed_by: None,
            lease_expires_at_ms: None,
            expires_at_ms: Some(unix_time_ms() + 60_000),
        }
    }

    fn spawn_mock_host(
        socket_path: PathBuf,
        response: protocol::MessageType,
    ) -> std::thread::JoinHandle<()> {
        let listener = StdUnixListener::bind(&socket_path).expect("bind mock unix listener");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept mock client");

            let mut reader = std::io::BufReader::new(
                stream
                    .try_clone()
                    .expect("clone accepted unix stream for buffered read"),
            );
            read_and_assert_auth_claim(&mut reader);
            send_frame(&mut stream, &response);
        })
    }

    fn spawn_mock_host_keepalive_after_auth_ok(
        socket_path: PathBuf,
    ) -> std::thread::JoinHandle<()> {
        let listener = StdUnixListener::bind(&socket_path).expect("bind mock unix listener");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept mock client");
            let mut reader = std::io::BufReader::new(
                stream
                    .try_clone()
                    .expect("clone accepted unix stream for buffered read"),
            );
            read_and_assert_auth_claim(&mut reader);
            send_frame(
                &mut stream,
                &protocol::MessageType::AuthOk(protocol::AuthOk {
                    version: protocol::PROTOCOL_VERSION_V1,
                    host_id: "host-1".to_string(),
                    claimed_by: protocol::ClaimedBy {
                        pi_session_id: "session-1".to_string(),
                        client_instance_id: "client-1".to_string(),
                    },
                    host_epoch: "epoch-1".to_string(),
                    protocol: protocol::PROTOCOL_VERSION_V1,
                    capabilities: vec!["browser_tools".to_string()],
                    lease_ttl_ms: 30_000,
                }),
            );

            // Stay alive until the client disconnects so connect_success remains deterministic.
            let mut buf = Vec::new();
            loop {
                buf.clear();
                let bytes = reader.read_until(b'\n', &mut buf).expect("keepalive read");
                if bytes == 0 {
                    break;
                }
            }
        })
    }

    fn spawn_mock_host_request_echo(
        socket_path: PathBuf,
        expected_requests: usize,
        emit_observation_before_responses: bool,
    ) -> std::thread::JoinHandle<()> {
        let listener = StdUnixListener::bind(&socket_path).expect("bind mock unix listener");
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept mock client");
            let mut reader = std::io::BufReader::new(
                stream
                    .try_clone()
                    .expect("clone accepted unix stream for buffered read"),
            );
            read_and_assert_auth_claim(&mut reader);
            send_frame(
                &mut stream,
                &protocol::MessageType::AuthOk(protocol::AuthOk {
                    version: protocol::PROTOCOL_VERSION_V1,
                    host_id: "host-echo".to_string(),
                    claimed_by: protocol::ClaimedBy {
                        pi_session_id: "session-1".to_string(),
                        client_instance_id: "client-1".to_string(),
                    },
                    host_epoch: "epoch-echo".to_string(),
                    protocol: protocol::PROTOCOL_VERSION_V1,
                    capabilities: vec!["browser_tools".to_string(), "observations".to_string()],
                    lease_ttl_ms: 30_000,
                }),
            );

            let mut requests = Vec::with_capacity(expected_requests);
            for _ in 0..expected_requests {
                let mut line = Vec::new();
                let bytes_read = reader
                    .read_until(b'\n', &mut line)
                    .expect("read request frame");
                assert!(bytes_read > 0, "mock host must receive request frames");
                let (message, consumed) = protocol::decode_frame::<protocol::MessageType>(&line)
                    .expect("decode request frame")
                    .expect("complete request frame");
                assert_eq!(
                    consumed,
                    line.len(),
                    "mock host must consume one request frame"
                );
                match message {
                    protocol::MessageType::Request(request) => requests.push(request),
                    other => panic!("expected request frame, got {other:?}"),
                }
            }

            if emit_observation_before_responses {
                send_frame(
                    &mut stream,
                    &protocol::MessageType::Observation(protocol::ObservationEvent {
                        version: protocol::PROTOCOL_VERSION_V1,
                        observer_id: "observer-1".to_string(),
                        events: vec![protocol::ObservationEntry {
                            kind: "console".to_string(),
                            message: Some("navigated".to_string()),
                            source: Some("page".to_string()),
                            url: Some("https://example.test".to_string()),
                            ts: unix_time_ms(),
                        }],
                    }),
                );
            }

            for request in requests.into_iter().rev() {
                send_frame(
                    &mut stream,
                    &protocol::MessageType::Response(protocol::ResponseEnvelope::Ok(
                        protocol::Response {
                            version: protocol::PROTOCOL_VERSION_V1,
                            id: request.id,
                            ok: true,
                            result: json!({
                                "echo": request.payload,
                                "op": request.op,
                            }),
                        },
                    )),
                );
            }
        })
    }

    fn spawn_mock_host_reconnect_two_sessions(socket_path: PathBuf) -> std::thread::JoinHandle<()> {
        let listener = StdUnixListener::bind(&socket_path).expect("bind mock unix listener");
        std::thread::spawn(move || {
            for (epoch, expected_n) in [("epoch-1", 1_i64), ("epoch-2", 2_i64)] {
                let (mut stream, _) = listener.accept().expect("accept mock client");
                let mut reader = std::io::BufReader::new(
                    stream
                        .try_clone()
                        .expect("clone accepted unix stream for buffered read"),
                );
                read_and_assert_auth_claim(&mut reader);
                send_frame(
                    &mut stream,
                    &protocol::MessageType::AuthOk(protocol::AuthOk {
                        version: protocol::PROTOCOL_VERSION_V1,
                        host_id: "host-reconnect".to_string(),
                        claimed_by: protocol::ClaimedBy {
                            pi_session_id: "session-1".to_string(),
                            client_instance_id: "client-1".to_string(),
                        },
                        host_epoch: epoch.to_string(),
                        protocol: protocol::PROTOCOL_VERSION_V1,
                        capabilities: vec!["browser_tools".to_string()],
                        lease_ttl_ms: 30_000,
                    }),
                );

                let mut line = Vec::new();
                let bytes_read = reader
                    .read_until(b'\n', &mut line)
                    .expect("read request frame");
                assert!(bytes_read > 0, "mock host must receive request frame");
                let (message, consumed) = protocol::decode_frame::<protocol::MessageType>(&line)
                    .expect("decode request frame")
                    .expect("complete request frame");
                assert_eq!(
                    consumed,
                    line.len(),
                    "mock host must consume one request frame"
                );

                let request = match message {
                    protocol::MessageType::Request(request) => request,
                    other => panic!("expected request frame, got {other:?}"),
                };
                assert_eq!(
                    request.payload["n"],
                    json!(expected_n),
                    "reconnect session request payload must match expected sequence"
                );

                send_frame(
                    &mut stream,
                    &protocol::MessageType::Response(protocol::ResponseEnvelope::Ok(
                        protocol::Response {
                            version: protocol::PROTOCOL_VERSION_V1,
                            id: request.id,
                            ok: true,
                            result: json!({ "epoch": epoch, "n": expected_n }),
                        },
                    )),
                );
                // Drop this connection to force connection-loss path before the next accept.
            }
        })
    }

    fn read_and_assert_auth_claim(reader: &mut std::io::BufReader<std::os::unix::net::UnixStream>) {
        let mut line = Vec::new();
        let bytes_read = reader
            .read_until(b'\n', &mut line)
            .expect("read auth_claim frame");
        assert!(bytes_read > 0, "mock host must receive an auth_claim frame");

        let (message, consumed) = protocol::decode_frame::<protocol::MessageType>(&line)
            .expect("decode auth_claim frame")
            .expect("complete auth_claim frame");
        assert_eq!(
            consumed,
            line.len(),
            "mock host must consume exactly one frame"
        );

        match message {
            protocol::MessageType::AuthClaim(auth) => {
                assert_eq!(auth.version, protocol::PROTOCOL_VERSION_V1, "auth version");
                assert_eq!(
                    auth.token, "secret-token",
                    "auth token forwarded from discovery"
                );
            }
            other => panic!("expected auth_claim, got {other:?}"),
        }
    }

    fn send_frame(stream: &mut std::os::unix::net::UnixStream, message: &protocol::MessageType) {
        let frame = protocol::encode_frame(message).expect("encode mock frame");
        stream
            .write_all(&frame)
            .expect("write mock frame to unix stream");
    }

    #[test]
    fn test_discover_hosts_filters_expired_and_prefers_pinned_host() {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket_a = dir.path().join("sock-a");
        let socket_b = dir.path().join("sock-b");
        let socket_c = dir.path().join("sock-c");
        std::fs::write(&socket_a, []).expect("create placeholder socket_a");
        std::fs::write(&socket_b, []).expect("create placeholder socket_b");
        std::fs::write(&socket_c, []).expect("create placeholder socket_c");

        let mut record_a = make_record(&socket_a, "host-a");
        let record_b = make_record(&socket_b, "host-b");
        let mut record_c = make_record(&socket_c, "host-c");
        record_a.expires_at_ms = Some(unix_time_ms() - 1); // expired -> ignored
        record_c.expires_at_ms = Some(unix_time_ms() + 10_000);

        write_discovery_record(
            &dir.path().join("pi-chrome-host-host-a.discovery.json"),
            &record_a,
        );
        write_discovery_record(
            &dir.path().join("pi-chrome-host-host-b.discovery.json"),
            &record_b,
        );
        write_discovery_record(
            &dir.path().join("pi-chrome-host-host-c.discovery.json"),
            &record_c,
        );

        let discovered = discover_hosts_in_dir(dir.path(), unix_time_ms(), Some("host-c"))
            .expect("discover hosts");

        let discovered_ids: Vec<_> = discovered.iter().map(|r| r.host_id.as_str()).collect();
        assert_eq!(
            discovered_ids,
            vec!["host-c", "host-b"],
            "expired records must be filtered and pinned host preferred first"
        );
    }

    #[test]
    fn test_chrome_bridge_connect_success_and_disconnect() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let socket_path = tempdir.path().join("host.sock");
            let record = make_record(&socket_path, "host-1");

            let server = spawn_mock_host_keepalive_after_auth_ok(socket_path.clone());

            let bridge = ChromeBridge::new(ChromeBridgeConfig {
                pi_session_id: "session-1".to_string(),
                client_instance_id: "client-1".to_string(),
                discovery_dir: tempdir.path().to_path_buf(),
                want_capabilities: vec!["browser_tools".to_string()],
                max_reconnect_attempts: 3,
                reconnect_backoff_ms: 1,
            });

            assert_eq!(
                bridge.status().state,
                ConnectionState::Disconnected,
                "bridge starts disconnected"
            );
            bridge
                .connect_to_record(&record)
                .await
                .expect("connect/auth handshake should succeed");

            let status = bridge.status();
            assert_eq!(
                status.state,
                ConnectionState::Connected,
                "state after connect"
            );
            assert_eq!(
                status.pinned_host_id.as_deref(),
                Some("host-1"),
                "pinned host cached"
            );
            assert_eq!(
                status.host_epoch.as_deref(),
                Some("epoch-1"),
                "host epoch cached"
            );

            bridge.disconnect().expect("disconnect should succeed");
            assert_eq!(
                bridge.status().state,
                ConnectionState::Disconnected,
                "state after disconnect"
            );

            server.join().expect("mock host thread join");
        });
    }

    #[test]
    fn test_chrome_bridge_send_request_roundtrip_and_observation_dispatch() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let socket_path = tempdir.path().join("echo.sock");
            let record = make_record(&socket_path, "host-echo");
            let server = spawn_mock_host_request_echo(socket_path.clone(), 1, true);

            let bridge = ChromeBridge::new(ChromeBridgeConfig {
                pi_session_id: "session-1".to_string(),
                client_instance_id: "client-1".to_string(),
                discovery_dir: tempdir.path().to_path_buf(),
                want_capabilities: vec!["browser_tools".to_string(), "observations".to_string()],
                max_reconnect_attempts: 3,
                reconnect_backoff_ms: 1,
            });

            bridge
                .connect_to_record(&record)
                .await
                .expect("connect/auth handshake should succeed");

            let envelope = bridge
                .send_request("browser.navigate", json!({ "url": "https://example.test" }))
                .await
                .expect("request/response roundtrip must succeed");
            match envelope {
                protocol::ResponseEnvelope::Ok(response) => {
                    assert_eq!(response.ok, true, "host response must be ok");
                    assert_eq!(
                        response.result["op"],
                        json!("browser.navigate"),
                        "response must echo op"
                    );
                    assert_eq!(
                        response.result["echo"]["url"],
                        json!("https://example.test"),
                        "response must echo payload"
                    );
                }
                other => panic!("expected successful response, got {other:?}"),
            }

            let observations = bridge.take_observations();
            assert_eq!(
                observations.len(),
                1,
                "reader loop must buffer pushed observations"
            );
            assert_eq!(
                observations[0].events[0].kind, "console",
                "observation event kind must roundtrip"
            );
            assert_eq!(
                bridge.pending_response_count(),
                0,
                "pending map must be empty after request completes"
            );

            server.join().expect("mock host thread join");
        });
    }

    #[test]
    fn test_chrome_bridge_concurrent_requests_are_dispatched_by_id() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let socket_path = tempdir.path().join("echo-concurrent.sock");
            let record = make_record(&socket_path, "host-echo");
            let server = spawn_mock_host_request_echo(socket_path.clone(), 8, false);

            let bridge = ChromeBridge::new(ChromeBridgeConfig {
                pi_session_id: "session-1".to_string(),
                client_instance_id: "client-1".to_string(),
                discovery_dir: tempdir.path().to_path_buf(),
                want_capabilities: vec!["browser_tools".to_string()],
                max_reconnect_attempts: 3,
                reconnect_backoff_ms: 1,
            });

            bridge
                .connect_to_record(&record)
                .await
                .expect("connect/auth handshake should succeed");

            let responses =
                future::join_all((0..8).map(|n| bridge.send_request("echo", json!({ "n": n }))))
                    .await;

            for (n, response) in (0..8).zip(responses) {
                let envelope = response.expect("request must complete");
                match envelope {
                    protocol::ResponseEnvelope::Ok(ok) => {
                        assert_eq!(ok.result["echo"]["n"], json!(n), "response id routing");
                    }
                    other => panic!("expected ok response, got {other:?}"),
                }
            }

            assert_eq!(
                bridge.pending_response_count(),
                0,
                "pending map must drain after concurrent request completion"
            );
            server.join().expect("mock host thread join");
        });
    }

    #[test]
    fn test_chrome_bridge_auth_busy_is_rejected() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let socket_path = tempdir.path().join("busy.sock");
            let mut record = make_record(&socket_path, "host-busy");
            record.claimed_by = Some(protocol::ClaimedBy {
                pi_session_id: "other-session".to_string(),
                client_instance_id: "other-client".to_string(),
            });

            let response = protocol::MessageType::AuthBusy(protocol::AuthBusy {
                version: protocol::PROTOCOL_VERSION_V1,
                host_id: "host-busy".to_string(),
                claimed_by: protocol::ClaimedBy {
                    pi_session_id: "other-session".to_string(),
                    client_instance_id: "other-client".to_string(),
                },
            });
            let server = spawn_mock_host(socket_path.clone(), response);

            let bridge = ChromeBridge::new(ChromeBridgeConfig {
                pi_session_id: "session-1".to_string(),
                client_instance_id: "client-1".to_string(),
                discovery_dir: tempdir.path().to_path_buf(),
                want_capabilities: vec!["browser_tools".to_string()],
                max_reconnect_attempts: 3,
                reconnect_backoff_ms: 1,
            });

            let err = bridge
                .connect_to_record(&record)
                .await
                .expect_err("auth_busy must reject claim");

            assert!(
                matches!(err, ChromeBridgeError::AuthBusy { .. }),
                "expected AuthBusy error, got {err:?}"
            );
            assert_eq!(
                bridge.status().state,
                ConnectionState::Disconnected,
                "failed direct auth handshake should return bridge to disconnected state"
            );

            server.join().expect("mock host thread join");
        });
    }

    #[test]
    fn test_chrome_bridge_protocol_mismatch_error_response() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let socket_path = tempdir.path().join("mismatch.sock");
            let record = make_record(&socket_path, "host-mismatch");

            let response = protocol::MessageType::Response(protocol::ResponseEnvelope::Error(
                protocol::ErrorResponse {
                    version: protocol::PROTOCOL_VERSION_V1,
                    id: "handshake".to_string(),
                    ok: false,
                    error: protocol::ProtocolErrorDetail {
                        code: protocol::ProtocolErrorCode::ChromeBridgeProtocolMismatch,
                        message: "protocol range unsupported".to_string(),
                        retryable: false,
                    },
                },
            ));
            let server = spawn_mock_host(socket_path.clone(), response);

            let bridge = ChromeBridge::new(ChromeBridgeConfig {
                pi_session_id: "session-1".to_string(),
                client_instance_id: "client-1".to_string(),
                discovery_dir: tempdir.path().to_path_buf(),
                want_capabilities: vec!["browser_tools".to_string()],
                max_reconnect_attempts: 3,
                reconnect_backoff_ms: 1,
            });

            let err = bridge
                .connect_to_record(&record)
                .await
                .expect_err("protocol mismatch error response must fail handshake");

            assert!(
                matches!(err, ChromeBridgeError::ProtocolMismatch(_)),
                "expected protocol mismatch, got {err:?}"
            );

            server.join().expect("mock host thread join");
        });
    }

    #[test]
    fn test_chrome_bridge_auth_reject_error_response() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let socket_path = tempdir.path().join("auth-reject.sock");
            let record = make_record(&socket_path, "host-auth-reject");

            let response = protocol::MessageType::Response(protocol::ResponseEnvelope::Error(
                protocol::ErrorResponse {
                    version: protocol::PROTOCOL_VERSION_V1,
                    id: "handshake".to_string(),
                    ok: false,
                    error: protocol::ProtocolErrorDetail {
                        code: protocol::ProtocolErrorCode::ChromeBridgeAuthFailed,
                        message: "token mismatch".to_string(),
                        retryable: false,
                    },
                },
            ));
            let server = spawn_mock_host(socket_path.clone(), response);

            let bridge = ChromeBridge::new(ChromeBridgeConfig {
                pi_session_id: "session-1".to_string(),
                client_instance_id: "client-1".to_string(),
                discovery_dir: tempdir.path().to_path_buf(),
                want_capabilities: vec!["browser_tools".to_string()],
                max_reconnect_attempts: 3,
                reconnect_backoff_ms: 1,
            });

            let err = bridge
                .connect_to_record(&record)
                .await
                .expect_err("auth reject error response must fail handshake");
            assert!(
                matches!(err, ChromeBridgeError::AuthRejected(_)),
                "expected auth rejected, got {err:?}"
            );

            server.join().expect("mock host thread join");
        });
    }

    #[test]
    fn test_chrome_bridge_connect_retries_and_disables_after_three_failures() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let missing_socket = tempdir.path().join("missing.sock");
            let record = make_record(&missing_socket, "host-missing");

            write_discovery_record(
                &tempdir
                    .path()
                    .join("pi-chrome-host-host-missing.discovery.json"),
                &record,
            );

            let bridge = ChromeBridge::new(ChromeBridgeConfig {
                pi_session_id: "session-1".to_string(),
                client_instance_id: "client-1".to_string(),
                discovery_dir: tempdir.path().to_path_buf(),
                want_capabilities: vec!["browser_tools".to_string()],
                max_reconnect_attempts: 3,
                reconnect_backoff_ms: 1,
            });

            let err = bridge
                .connect()
                .await
                .expect_err("connect must fail when no valid socket paths exist");
            assert!(
                matches!(err, ChromeBridgeError::NoHostsFound),
                "expected no hosts found when socket path missing, got {err:?}"
            );

            let status = bridge.status();
            assert_eq!(
                status.consecutive_failures, 1,
                "one connect() failure increments session failure streak once"
            );

            // Two more failing connect() calls should trip disable-on-fail policy.
            let _ = bridge.connect().await;
            let _ = bridge.connect().await;
            let status = bridge.status();
            assert!(
                status.browser_tools_disabled,
                "browser tools must disable after 3 consecutive connect failures"
            );
            assert_eq!(
                status.state,
                ConnectionState::Disabled,
                "state must move to Disabled after failure threshold"
            );
        });
    }

    #[test]
    fn test_chrome_bridge_connection_loss_recovery_updates_host_epoch() {
        run_async(async {
            let tempdir = tempfile::tempdir().expect("tempdir");
            let socket_path = tempdir.path().join("reconnect.sock");
            let record = DiscoveryRecord {
                host_id: "host-reconnect".to_string(),
                host_epoch: "ignored-by-host".to_string(),
                socket_path: socket_path.clone(),
                token: "secret-token".to_string(),
                protocol_min: protocol::PROTOCOL_MIN_SUPPORTED,
                protocol_max: protocol::PROTOCOL_MAX_SUPPORTED,
                capabilities: vec!["browser_tools".to_string()],
                claimed_by: None,
                lease_expires_at_ms: None,
                expires_at_ms: Some(unix_time_ms() + 60_000),
            };
            let server = spawn_mock_host_reconnect_two_sessions(socket_path.clone());
            write_discovery_record(
                &tempdir
                    .path()
                    .join("pi-chrome-host-host-reconnect.discovery.json"),
                &record,
            );

            let bridge = ChromeBridge::new(ChromeBridgeConfig {
                pi_session_id: "session-1".to_string(),
                client_instance_id: "client-1".to_string(),
                discovery_dir: tempdir.path().to_path_buf(),
                want_capabilities: vec!["browser_tools".to_string()],
                max_reconnect_attempts: 3,
                reconnect_backoff_ms: 1,
            });

            bridge
                .connect()
                .await
                .expect("initial connect should succeed");
            assert_eq!(
                bridge.status().host_epoch.as_deref(),
                Some("epoch-1"),
                "first handshake should cache initial host epoch"
            );

            let first = bridge
                .send_request("echo", json!({ "n": 1 }))
                .await
                .expect("first request must succeed");
            match first {
                protocol::ResponseEnvelope::Ok(resp) => {
                    assert_eq!(resp.result["epoch"], json!("epoch-1"), "first epoch echoed");
                }
                other => panic!("expected ok response, got {other:?}"),
            }

            // Server closes conn1 after response; reconnect should re-pin same host and update epoch.
            bridge
                .connect()
                .await
                .expect("reconnect after connection loss should succeed");
            let status = bridge.status();
            assert_eq!(
                status.pinned_host_id.as_deref(),
                Some("host-reconnect"),
                "reconnect must retain pinned host id"
            );
            assert_eq!(
                status.host_epoch.as_deref(),
                Some("epoch-2"),
                "reconnect handshake must refresh host epoch"
            );

            let second = bridge
                .send_request("echo", json!({ "n": 2 }))
                .await
                .expect("second request after reconnect must succeed");
            match second {
                protocol::ResponseEnvelope::Ok(resp) => {
                    assert_eq!(
                        resp.result["epoch"],
                        json!("epoch-2"),
                        "second epoch echoed"
                    );
                }
                other => panic!("expected ok response, got {other:?}"),
            }

            server.join().expect("mock host thread join");
        });
    }

    #[test]
    fn test_next_request_id_monotonic() {
        let bridge = ChromeBridge::new(ChromeBridgeConfig::default());
        let a = bridge.next_request_id();
        let b = bridge.next_request_id();
        assert_ne!(a, b, "request ids must be unique and monotonic");
        assert_eq!(a, "chrome-1");
        assert_eq!(b, "chrome-2");
        assert_eq!(bridge.pending_response_count(), 0);
        assert_eq!(bridge.observation_buffer_len(), 0);
        assert_eq!(
            bridge.take_observations(),
            Vec::<protocol::ObservationEvent>::new()
        );
        assert_eq!(
            json!({"ok": true})["ok"],
            true,
            "serde_json smoke for test module"
        );
    }
}
