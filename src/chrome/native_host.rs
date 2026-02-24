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
}

impl NativeHost {
    pub fn new(config: NativeHostConfig) -> Result<Self, NativeHostError> {
        let host_id = config.host_id.clone().unwrap_or_else(random_id);
        let host_epoch = config.host_epoch.clone().unwrap_or_else(random_id);
        let token = config.token.clone().unwrap_or_else(random_token);
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

        let relay_result = relay_until_disconnect(&mut agent_stream, chrome_reader, chrome_writer);
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
) -> Result<(), NativeHostError> {
    loop {
        match relay_one_agent_message_to_chrome(agent_stream, chrome_writer) {
            Ok(_message) => {}
            Err(err) if is_clean_disconnect_error(&err) => return Ok(()),
            Err(err) => return Err(err),
        }

        match relay_chrome_messages_until_response(chrome_reader, agent_stream) {
            Ok(_forwarded) => {}
            Err(err) if is_clean_disconnect_error(&err) => return Ok(()),
            Err(err) => return Err(err),
        }
    }
}

fn relay_chrome_messages_until_response<R: IoRead, W: IoWrite>(
    chrome_reader: &mut R,
    agent_writer: &mut W,
) -> Result<usize, NativeHostError> {
    let mut forwarded = 0_usize;
    loop {
        let message = relay_one_chrome_message_to_agent(chrome_reader, agent_writer)?;
        forwarded = forwarded.saturating_add(1);
        if matches!(message, protocol::MessageType::Response(_)) {
            return Ok(forwarded);
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

    fn sample_request() -> protocol::MessageType {
        protocol::MessageType::Request(protocol::Request {
            version: protocol::PROTOCOL_VERSION_V1,
            id: "req-e2e-1".to_string(),
            op: "tabs_context".to_string(),
            payload: serde_json::json!({"tabId": 123}),
        })
    }

    fn sample_response_for(id: &str) -> protocol::MessageType {
        protocol::MessageType::Response(protocol::ResponseEnvelope::Ok(protocol::Response {
            version: protocol::PROTOCOL_VERSION_V1,
            id: id.to_string(),
            ok: true,
            result: serde_json::json!({"tabs": [{"id": 123, "url": "https://example.test"}]}),
        }))
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
}
