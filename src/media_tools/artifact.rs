//! Publish complete media artifacts without replacing existing user files.

use super::transport;
use crate::agent_cx::AgentCx;
use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// Check the requested destination before making a billable provider call.
/// Publication repeats this check and uses no-clobber persistence for races.
pub(super) fn preflight(cwd: &Path, requested: Option<&str>, tool: &str) -> Result<()> {
    if let Some(requested) = requested {
        if requested.trim().is_empty() || requested.len() > 4096 {
            return Err(Error::tool(
                tool,
                "output_path must be nonempty and at most 4096 bytes",
            ));
        }
        crate::artifact_output::resolve_new(cwd, requested, tool)?;
    }
    Ok(())
}

pub(super) fn publish(
    cwd: &Path,
    requested: Option<&str>,
    prefix: &str,
    extension: &str,
    bytes: &[u8],
    owner: Option<&AgentCx>,
    tool: &str,
) -> Result<PathBuf> {
    if let Some(owner) = owner {
        transport::check_owner(tool, owner)?;
    }
    if bytes.is_empty() {
        return Err(Error::tool(
            tool,
            "refusing to publish an empty media artifact",
        ));
    }
    preflight(cwd, requested, tool)?;
    let requested = requested.map_or_else(
        || format!("{prefix}_{}.{extension}", uuid::Uuid::new_v4().simple()),
        ToString::to_string,
    );
    let target = crate::artifact_output::resolve_new(cwd, &requested, tool)?;
    let path = target.path();
    let actual_extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    let matches = actual_extension.eq_ignore_ascii_case(extension)
        || (extension == "jpg" && actual_extension.eq_ignore_ascii_case("jpeg"));
    if !matches {
        return Err(Error::tool(
            tool,
            format!(
                "provider returned {extension} data, but output_path has a different extension; use .{extension} or omit output_path"
            ),
        ));
    }
    if let Some(owner) = owner {
        transport::check_owner(tool, owner)?;
    }
    crate::artifact_output::publish(&target, bytes, tool)?;
    Ok(target.path().to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_never_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = publish(
            dir.path(),
            Some("result.png"),
            "images/result",
            "png",
            b"original",
            None,
            "generate_image",
        )
        .unwrap();
        assert!(
            publish(
                dir.path(),
                Some("result.png"),
                "images/result",
                "png",
                b"replacement",
                None,
                "generate_image"
            )
            .is_err()
        );
        assert_eq!(std::fs::read(path).unwrap(), b"original");
    }

    #[test]
    fn wrong_extension_and_empty_bytes_do_not_create_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            publish(
                dir.path(),
                Some("result.png"),
                "image",
                "jpg",
                b"jpeg",
                None,
                "generate_image"
            )
            .is_err()
        );
        assert!(
            publish(
                dir.path(),
                Some("result.wav"),
                "audio",
                "wav",
                b"",
                None,
                "tts"
            )
            .is_err()
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn requested_paths_cannot_escape_workspace_or_use_linked_parents() {
        let dir = tempfile::tempdir().unwrap();
        for path in ["../escape.png", "/tmp/escape.png", "a/../../escape.png", "a\\escape.png"] {
            assert!(preflight(dir.path(), Some(path), "generate_image").is_err(), "{path}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outside = tempfile::tempdir().unwrap();
            symlink(outside.path(), dir.path().join("linked")).unwrap();
            assert!(preflight(dir.path(), Some("linked/result.png"), "generate_image").is_err());
        }
    }

    #[test]
    fn generated_filenames_use_the_received_format() {
        let dir = tempfile::tempdir().unwrap();
        let path = publish(
            dir.path(),
            None,
            "images/generated",
            "jpg",
            b"jpeg",
            None,
            "generate_image",
        )
        .unwrap();
        assert_eq!(path.extension().unwrap(), "jpg");
        assert_eq!(std::fs::read(path).unwrap(), b"jpeg");
    }
}
