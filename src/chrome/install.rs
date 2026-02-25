//! Chrome extension install/setup CLI — manifest writer + path discovery.
//!
//! Implements `pi --setup-chrome` which:
//! 1. Discovers Chrome installation path
//! 2. Writes native messaging host manifest JSON
//! 3. Generates a shell wrapper script for the native host
//! 4. Verifies the installation

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

/// Chrome native messaging host name (reverse-domain, point-of-no-return decision per PLAN §5.3).
pub const NATIVE_HOST_NAME: &str = "com.franken.pi_rust_browser_extension";

/// Manifest filename derived from host name.
pub const MANIFEST_FILENAME: &str = "com.franken.pi_rust_browser_extension.json";

/// Wrapper script name.
pub const WRAPPER_SCRIPT_NAME: &str = "pi-chrome-native-host.sh";

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum InstallError {
    #[error("Chrome not detected at any known path. Install Chrome and run `pi --setup-chrome`.")]
    ChromeNotFound,

    #[error("failed to determine native messaging hosts directory for this platform")]
    HostsDirNotFound,

    #[error("home directory not found")]
    HomeDirNotFound,

    #[error("pi binary not found on PATH")]
    PiBinaryNotFound,

    #[error("failed to create directory {path}: {source}")]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to set permissions on {path}: {source}")]
    SetPermissions {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("verification failed: manifest not found at {0}")]
    ManifestNotFound(PathBuf),

    #[error("verification failed: wrapper script not found at {0}")]
    WrapperNotFound(PathBuf),
}

// ---------------------------------------------------------------------------
// Native messaging host manifest
// ---------------------------------------------------------------------------

/// Chrome native messaging host manifest (JSON).
/// See: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct NativeHostManifest {
    pub name: String,
    pub description: String,
    pub path: String,
    #[serde(rename = "type")]
    pub host_type: String,
    pub allowed_origins: Vec<String>,
}

impl NativeHostManifest {
    /// Create a manifest pointing to the given wrapper script path.
    /// `extension_id` is the Chrome extension ID for the allowed_origins field.
    /// Pass `None` to allow all origins (development mode).
    #[must_use]
    pub fn new(wrapper_path: &Path, extension_id: Option<&str>) -> Self {
        let allowed_origins = extension_id.map_or_else(
            || vec!["chrome-extension://*/*".to_string()],
            |id| vec![format!("chrome-extension://{id}/")],
        );

        Self {
            name: NATIVE_HOST_NAME.to_string(),
            description: "Pi Agent Browser Automation Host".to_string(),
            path: wrapper_path.to_string_lossy().to_string(),
            host_type: "stdio".to_string(),
            allowed_origins,
        }
    }

    /// Serialize to pretty-printed JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec_pretty(self)
    }
}

// ---------------------------------------------------------------------------
// Platform path discovery
// ---------------------------------------------------------------------------

/// Known Chrome binary paths per platform.
#[cfg(target_os = "macos")]
const CHROME_BINARY_PATHS: &[&str] = &[
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
];

#[cfg(target_os = "linux")]
const CHROME_BINARY_PATHS: &[&str] = &[
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/snap/bin/chromium",
];

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const CHROME_BINARY_PATHS: &[&str] = &[];

/// Discover Chrome binary path by checking known locations.
pub fn discover_chrome_path() -> Result<PathBuf, InstallError> {
    for path_str in CHROME_BINARY_PATHS {
        let path = Path::new(path_str);
        if path.exists() {
            return Ok(path.to_path_buf());
        }
    }
    Err(InstallError::ChromeNotFound)
}

/// Return the platform-specific native messaging hosts directory.
///
/// macOS: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`
/// Linux: `~/.config/google-chrome/NativeMessagingHosts/`
pub fn native_messaging_hosts_dir() -> Result<PathBuf, InstallError> {
    let home = home_dir()?;

    #[cfg(target_os = "macos")]
    let dir = home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts");

    #[cfg(target_os = "linux")]
    let dir = home.join(".config/google-chrome/NativeMessagingHosts");

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let dir = {
        let _ = home;
        return Err(InstallError::HostsDirNotFound);
    };

    Ok(dir)
}

/// Return the platform-specific wrapper script directory.
///
/// macOS: `~/Library/Application Support/Pi/`
/// Linux: `~/.local/share/pi/`
pub fn wrapper_script_dir() -> Result<PathBuf, InstallError> {
    let home = home_dir()?;

    #[cfg(target_os = "macos")]
    let dir = home.join("Library/Application Support/Pi");

    #[cfg(target_os = "linux")]
    let dir = home.join(".local/share/pi");

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let dir = {
        let _ = home;
        return Err(InstallError::HostsDirNotFound);
    };

    Ok(dir)
}

/// Locate the `pi` binary on PATH.
pub fn find_pi_binary() -> Result<PathBuf, InstallError> {
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join("pi");
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(InstallError::PiBinaryNotFound)
}

fn home_dir() -> Result<PathBuf, InstallError> {
    dirs::home_dir().ok_or(InstallError::HomeDirNotFound)
}

// ---------------------------------------------------------------------------
// Wrapper script generation
// ---------------------------------------------------------------------------

/// Generate the shell wrapper script content.
/// The wrapper invokes `pi --mode chrome-native-host` and relays stdio.
#[must_use]
pub fn generate_wrapper_script(pi_binary_path: &Path) -> String {
    format!(
        r#"#!/bin/bash
# Pi Chrome Native Host Wrapper
# Generated by `pi --setup-chrome` — do not edit manually.
# This script is invoked by Chrome to start the native messaging host.

exec "{pi_binary}" --mode chrome-native-host "$@"
"#,
        pi_binary = pi_binary_path.display()
    )
}

// ---------------------------------------------------------------------------
// Installation
// ---------------------------------------------------------------------------

/// Result of a successful setup.
#[derive(Debug, Clone)]
pub struct SetupResult {
    pub manifest_path: PathBuf,
    pub wrapper_path: PathBuf,
    pub chrome_path: Option<PathBuf>,
}

/// Run the full setup: discover Chrome, write manifest, write wrapper, verify.
///
/// `extension_id`: Chrome extension ID for `allowed_origins`. Pass `None` for dev mode.
/// `pi_binary_override`: Override pi binary path (for testing). `None` to auto-discover.
pub fn setup_chrome(
    extension_id: Option<&str>,
    pi_binary_override: Option<&Path>,
) -> Result<SetupResult, InstallError> {
    // 1. Discover Chrome (non-fatal — Pi can be set up before Chrome is installed)
    let chrome_path = discover_chrome_path().ok();

    // 2. Find pi binary
    let pi_binary = match pi_binary_override {
        Some(path) => path.to_path_buf(),
        None => find_pi_binary()?,
    };

    // 3. Determine paths
    let hosts_dir = native_messaging_hosts_dir()?;
    let wrapper_dir = wrapper_script_dir()?;
    let manifest_path = hosts_dir.join(MANIFEST_FILENAME);
    let wrapper_path = wrapper_dir.join(WRAPPER_SCRIPT_NAME);

    // 4. Create directories
    ensure_dir(&hosts_dir)?;
    ensure_dir(&wrapper_dir)?;

    // 5. Write wrapper script
    let wrapper_content = generate_wrapper_script(&pi_binary);
    write_file(&wrapper_path, wrapper_content.as_bytes())?;
    set_executable(&wrapper_path)?;

    // 6. Write manifest
    let manifest = NativeHostManifest::new(&wrapper_path, extension_id);
    let manifest_bytes = manifest
        .to_json_bytes()
        .map_err(|e| InstallError::WriteFile {
            path: manifest_path.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, e),
        })?;
    write_file(&manifest_path, &manifest_bytes)?;

    // 7. Verify
    verify_installation(&manifest_path, &wrapper_path)?;

    Ok(SetupResult {
        manifest_path,
        wrapper_path,
        chrome_path,
    })
}

/// Verify that manifest and wrapper exist on disk.
pub fn verify_installation(manifest_path: &Path, wrapper_path: &Path) -> Result<(), InstallError> {
    if !manifest_path.exists() {
        return Err(InstallError::ManifestNotFound(manifest_path.to_path_buf()));
    }
    if !wrapper_path.exists() {
        return Err(InstallError::WrapperNotFound(wrapper_path.to_path_buf()));
    }
    Ok(())
}

fn ensure_dir(dir: &Path) -> Result<(), InstallError> {
    if !dir.exists() {
        fs::create_dir_all(dir).map_err(|source| InstallError::CreateDir {
            path: dir.to_path_buf(),
            source,
        })?;
    }
    Ok(())
}

fn write_file(path: &Path, content: &[u8]) -> Result<(), InstallError> {
    fs::write(path, content).map_err(|source| InstallError::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

fn set_executable(path: &Path) -> Result<(), InstallError> {
    let metadata = fs::metadata(path).map_err(|source| InstallError::SetPermissions {
        path: path.to_path_buf(),
        source,
    })?;
    let mut perms = metadata.permissions();
    perms.set_mode(perms.mode() | 0o755);
    fs::set_permissions(path, perms).map_err(|source| InstallError::SetPermissions {
        path: path.to_path_buf(),
        source,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manifest_generation_structure() {
        let wrapper_path = Path::new("/usr/local/bin/pi-chrome-native-host.sh");
        let manifest =
            NativeHostManifest::new(wrapper_path, Some("abcdefghijklmnopqrstuvwxyz012345"));

        assert_eq!(
            manifest.name, NATIVE_HOST_NAME,
            "manifest name must match host name constant"
        );
        assert_eq!(
            manifest.host_type, "stdio",
            "Chrome native hosts use stdio type"
        );
        assert_eq!(
            manifest.path, "/usr/local/bin/pi-chrome-native-host.sh",
            "manifest path must match wrapper script path"
        );
        assert_eq!(
            manifest.allowed_origins,
            vec!["chrome-extension://abcdefghijklmnopqrstuvwxyz012345/"],
            "allowed_origins must contain the extension ID"
        );

        // Verify JSON serialization is valid
        let json_bytes = manifest
            .to_json_bytes()
            .expect("manifest must serialize to JSON");
        let parsed: serde_json::Value =
            serde_json::from_slice(&json_bytes).expect("manifest JSON must be valid");
        assert_eq!(parsed["name"], NATIVE_HOST_NAME);
        assert_eq!(parsed["type"], "stdio");
        assert!(
            parsed.get("debugger").is_none(),
            "manifest must never include debugger permission (S4)"
        );
    }

    #[test]
    fn test_manifest_dev_mode_allows_all_origins() {
        let wrapper_path = Path::new("/tmp/wrapper.sh");
        let manifest = NativeHostManifest::new(wrapper_path, None);

        assert_eq!(
            manifest.allowed_origins,
            vec!["chrome-extension://*/*"],
            "dev mode must use wildcard origin pattern"
        );
    }

    #[test]
    fn test_wrapper_script_content() {
        let pi_binary = Path::new("/usr/local/bin/pi");
        let script = generate_wrapper_script(pi_binary);

        assert!(
            script.starts_with("#!/bin/bash"),
            "wrapper must have bash shebang"
        );
        assert!(
            script.contains("exec \"/usr/local/bin/pi\" --mode chrome-native-host"),
            "wrapper must exec pi with --mode chrome-native-host flag"
        );
        assert!(
            script.contains("\"$@\""),
            "wrapper must forward additional arguments"
        );
    }

    #[test]
    fn test_wrapper_script_handles_spaces_in_path() {
        let pi_binary = Path::new("/Users/user/My Programs/pi");
        let script = generate_wrapper_script(pi_binary);

        assert!(
            script.contains("exec \"/Users/user/My Programs/pi\" --mode chrome-native-host"),
            "wrapper must quote the pi binary path to handle spaces"
        );
    }

    #[test]
    fn test_setup_chrome_creates_manifest_and_wrapper() {
        let tempdir = tempfile::tempdir().expect("tempdir");

        // Override paths for testing
        let hosts_dir = tempdir.path().join("hosts");
        let wrapper_dir = tempdir.path().join("wrapper");
        let pi_binary = tempdir.path().join("pi");

        // Create fake pi binary
        fs::write(&pi_binary, "#!/bin/bash\necho pi").expect("write fake pi");

        let manifest_path = hosts_dir.join(MANIFEST_FILENAME);
        let wrapper_path = wrapper_dir.join(WRAPPER_SCRIPT_NAME);

        // Create directories
        fs::create_dir_all(&hosts_dir).expect("create hosts dir");
        fs::create_dir_all(&wrapper_dir).expect("create wrapper dir");

        // Write wrapper
        let wrapper_content = generate_wrapper_script(&pi_binary);
        fs::write(&wrapper_path, wrapper_content.as_bytes()).expect("write wrapper");
        set_executable(&wrapper_path).expect("set wrapper executable");

        // Write manifest
        let manifest = NativeHostManifest::new(&wrapper_path, None);
        let manifest_bytes = manifest.to_json_bytes().expect("serialize manifest");
        fs::write(&manifest_path, &manifest_bytes).expect("write manifest");

        // Verify
        verify_installation(&manifest_path, &wrapper_path)
            .expect("installation verification must pass");

        // Check manifest content
        let raw = fs::read(&manifest_path).expect("read manifest");
        let parsed: serde_json::Value = serde_json::from_slice(&raw).expect("parse manifest");
        assert_eq!(parsed["name"], NATIVE_HOST_NAME);
        assert_eq!(parsed["type"], "stdio");

        // Check wrapper is executable
        let perms = fs::metadata(&wrapper_path)
            .expect("wrapper metadata")
            .permissions();
        assert!(
            perms.mode() & 0o111 != 0,
            "wrapper script must be executable"
        );
    }

    #[test]
    fn test_verify_installation_fails_on_missing_manifest() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("nonexistent.json");
        let wrapper_path = tempdir.path().join("wrapper.sh");
        fs::write(&wrapper_path, "#!/bin/bash").expect("write wrapper");

        let result = verify_installation(&manifest_path, &wrapper_path);
        assert!(
            matches!(result, Err(InstallError::ManifestNotFound(_))),
            "must fail when manifest is missing"
        );
    }

    #[test]
    fn test_verify_installation_fails_on_missing_wrapper() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest_path = tempdir.path().join("manifest.json");
        let wrapper_path = tempdir.path().join("nonexistent.sh");
        fs::write(&manifest_path, "{}").expect("write manifest");

        let result = verify_installation(&manifest_path, &wrapper_path);
        assert!(
            matches!(result, Err(InstallError::WrapperNotFound(_))),
            "must fail when wrapper is missing"
        );
    }

    #[test]
    fn test_native_messaging_hosts_dir_returns_valid_path() {
        // This test verifies the function doesn't panic and returns a reasonable path
        match native_messaging_hosts_dir() {
            Ok(dir) => {
                let dir_str = dir.to_string_lossy();
                assert!(
                    dir_str.contains("NativeMessagingHosts"),
                    "hosts dir must contain NativeMessagingHosts: {dir_str}"
                );
            }
            Err(InstallError::HomeDirNotFound) => {
                // Acceptable in CI environments without $HOME
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_manifest_json_field_names() {
        let wrapper_path = Path::new("/tmp/wrapper.sh");
        let manifest = NativeHostManifest::new(wrapper_path, None);
        let json_bytes = manifest.to_json_bytes().expect("serialize");
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).expect("parse");

        // Chrome requires exact field names
        assert!(parsed.get("name").is_some(), "must have 'name' field");
        assert!(
            parsed.get("description").is_some(),
            "must have 'description' field"
        );
        assert!(parsed.get("path").is_some(), "must have 'path' field");
        assert!(
            parsed.get("type").is_some(),
            "must have 'type' field (not 'host_type')"
        );
        assert!(
            parsed.get("allowed_origins").is_some(),
            "must have 'allowed_origins' field"
        );
        // Ensure serde rename worked: "type" not "host_type"
        assert!(
            parsed.get("host_type").is_none(),
            "must use 'type' not 'host_type' in JSON output"
        );
    }

    #[test]
    fn test_constants_are_consistent() {
        assert!(
            NATIVE_HOST_NAME.contains('.'),
            "host name must be reverse-domain format"
        );
        assert!(
            MANIFEST_FILENAME.starts_with(NATIVE_HOST_NAME),
            "manifest filename must derive from host name"
        );
        assert!(
            Path::new(MANIFEST_FILENAME)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("json")),
            "manifest filename must end with .json"
        );
        assert!(
            Path::new(WRAPPER_SCRIPT_NAME)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("sh")),
            "wrapper script must end with .sh"
        );
    }

    #[test]
    fn test_manifest_equality_and_clone() {
        let wrapper_path = Path::new("/tmp/wrapper.sh");
        let m1 = NativeHostManifest::new(wrapper_path, Some("ext123"));
        let m2 = m1.clone();
        assert_eq!(m1, m2, "cloned manifest must equal original");

        let m3 = NativeHostManifest::new(wrapper_path, None);
        assert_ne!(m1, m3, "different allowed_origins must not be equal");
    }

    #[test]
    fn test_manifest_description_is_nonempty() {
        let manifest = NativeHostManifest::new(Path::new("/tmp/w.sh"), None);
        assert!(
            !manifest.description.is_empty(),
            "manifest description must be non-empty"
        );
    }

    #[test]
    fn test_wrapper_script_dir_returns_valid_path() {
        match wrapper_script_dir() {
            Ok(dir) => {
                let dir_str = dir.to_string_lossy();
                // On macOS it should contain "Pi", on Linux ".local/share/pi"
                assert!(
                    dir_str.contains("Pi") || dir_str.contains("pi"),
                    "wrapper script dir must reference pi: {dir_str}"
                );
            }
            Err(InstallError::HomeDirNotFound) => {
                // Acceptable in CI environments without $HOME
            }
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[test]
    fn test_error_display_messages() {
        let err = InstallError::ChromeNotFound;
        let msg = format!("{err}");
        assert!(msg.contains("Chrome"), "ChromeNotFound display: {msg}");

        let err = InstallError::HomeDirNotFound;
        let msg = format!("{err}");
        assert!(
            msg.contains("home directory"),
            "HomeDirNotFound display: {msg}"
        );

        let err = InstallError::PiBinaryNotFound;
        let msg = format!("{err}");
        assert!(msg.contains("pi binary"), "PiBinaryNotFound display: {msg}");

        let err = InstallError::ManifestNotFound(PathBuf::from("/tmp/x.json"));
        let msg = format!("{err}");
        assert!(
            msg.contains("/tmp/x.json"),
            "ManifestNotFound must include path: {msg}"
        );

        let err = InstallError::WrapperNotFound(PathBuf::from("/tmp/w.sh"));
        let msg = format!("{err}");
        assert!(
            msg.contains("/tmp/w.sh"),
            "WrapperNotFound must include path: {msg}"
        );
    }

    #[test]
    fn test_error_display_io_variants() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err = InstallError::CreateDir {
            path: PathBuf::from("/tmp/dir"),
            source: io_err,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("/tmp/dir") && msg.contains("denied"),
            "CreateDir display: {msg}"
        );

        let io_err = std::io::Error::other("disk full");
        let err = InstallError::WriteFile {
            path: PathBuf::from("/tmp/file"),
            source: io_err,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("/tmp/file") && msg.contains("disk full"),
            "WriteFile display: {msg}"
        );

        let io_err = std::io::Error::other("bad perms");
        let err = InstallError::SetPermissions {
            path: PathBuf::from("/tmp/script"),
            source: io_err,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("/tmp/script") && msg.contains("bad perms"),
            "SetPermissions display: {msg}"
        );
    }

    #[test]
    fn test_verify_installation_success_both_present() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let manifest = tempdir.path().join("manifest.json");
        let wrapper = tempdir.path().join("wrapper.sh");
        fs::write(&manifest, "{}").expect("write manifest");
        fs::write(&wrapper, "#!/bin/bash").expect("write wrapper");

        verify_installation(&manifest, &wrapper)
            .expect("verification must pass when both files exist");
    }

    #[test]
    fn test_ensure_dir_creates_nested() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let nested = tempdir.path().join("a").join("b").join("c");
        ensure_dir(&nested).expect("ensure_dir must create nested dirs");
        assert!(nested.exists(), "nested dir must exist after ensure_dir");
    }

    #[test]
    fn test_ensure_dir_idempotent() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let dir = tempdir.path().join("existing");
        fs::create_dir_all(&dir).expect("pre-create");
        ensure_dir(&dir).expect("ensure_dir on existing dir must succeed");
    }

    #[test]
    fn test_set_executable_makes_file_executable() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let file = tempdir.path().join("script.sh");
        fs::write(&file, "#!/bin/bash").expect("write file");

        set_executable(&file).expect("set_executable must succeed");

        let perms = fs::metadata(&file).expect("metadata").permissions();
        assert!(perms.mode() & 0o111 != 0, "file must have execute bits set");
    }

    #[test]
    fn test_manifest_json_serializes_allowed_origins_as_array() {
        let manifest = NativeHostManifest::new(Path::new("/tmp/w.sh"), Some("testid"));
        let json_bytes = manifest.to_json_bytes().expect("serialize");
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).expect("parse");

        let origins = parsed["allowed_origins"].as_array().expect("must be array");
        assert_eq!(origins.len(), 1, "single extension ID = single origin");
        assert!(
            origins[0]
                .as_str()
                .unwrap()
                .starts_with("chrome-extension://"),
            "origin must use chrome-extension:// scheme"
        );
    }

    #[test]
    fn test_wrapper_script_contains_comment_header() {
        let script = generate_wrapper_script(Path::new("/usr/local/bin/pi"));
        assert!(
            script.contains("Pi Chrome Native Host"),
            "wrapper must contain identifying comment"
        );
        assert!(
            script.contains("do not edit manually"),
            "wrapper must warn against manual editing"
        );
    }
}
