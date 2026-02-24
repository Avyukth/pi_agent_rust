use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    pub async fn run_until_idle_for_test(&mut self) -> Result<NativeHostRunOutcome, NativeHostError> {
        self.startup().await?;
        let listener = self.listener.as_ref().expect("listener initialized by startup");
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

    fn write_discovery_record(&self) -> Result<(), NativeHostError> {
        let now_ms = unix_time_ms();
        let lease_expiry = now_ms.saturating_add(
            i64::try_from(self.config.lease_ttl_ms).unwrap_or(i64::MAX),
        );
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
            claimed_by: None,
            lease_expires_at_ms: Some(lease_expiry),
            expires_at_ms: Some(discovery_expiry),
        };
        let bytes = serde_json::to_vec(&record).map_err(|source| NativeHostError::DiscoverySerialize {
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

            host.startup().await.expect("startup should bind and publish");

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
}
