//! Native source review and lockfile dependency inspection (bd-cv653.2.6).
//!
//! Source rule packs remain local. Dependency inventory is also offline and
//! reports unsupported origins instead of guessing a public package identity.

pub mod dependencies;
mod source;

pub use source::{
    CompareReport, Disposition, Finding, Rule, RulePack, SARIF_SCHEMA_URI, SARIF_VERSION,
    SCAN_SCHEMA, compare, findings_from_sarif, fingerprint, load_dispositions, load_rule_packs,
    partition_by_disposition, run_scan, save_dispositions, to_sarif,
};

use crate::agent_cx::AgentCx;
use crate::error::{Error, Result};
use crate::model::{ContentBlock, TextContent};
use crate::tools::{Tool, ToolEffects, ToolOutput, ToolUpdate};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

/// One agent-facing security surface, with independent source and dependency engines.
pub struct SecurityScanTool {
    cwd: PathBuf,
    source: source::SecurityScanTool,
}

impl SecurityScanTool {
    #[must_use]
    pub fn new(cwd: &Path) -> Self {
        Self { cwd: cwd.to_path_buf(), source: source::SecurityScanTool::new(cwd) }
    }
}

#[async_trait::async_trait]
impl Tool for SecurityScanTool {
    fn name(&self) -> &'static str { "security_scan" }
    fn label(&self) -> &'static str { "security scan" }
    fn description(&self) -> &'static str {
        "Review local source with plan/run/disposition/compare, or use dependency_plan to inventory exact public-registry packages in Cargo.lock and npm lockfiles without network access. Dependency paths select lockfiles, not source directories. Local, git, private-registry and unresolved entries are reported separately; an inventory is not a vulnerability verdict."
    }
    fn parameters(&self) -> Value {
        let mut schema = self.source.parameters();
        schema["properties"]["op"]["enum"] = json!([
            "plan", "run", "disposition", "compare", "dependency_plan"
        ]);
        schema["properties"]["op"]["description"] = json!(
            "Source review: plan/run/disposition/compare. dependency_plan: offline lockfile inventory."
        );
        schema["properties"]["paths"]["description"] = json!(
            "Source ops: relative files/directories. Dependency ops: up to 32 relative Cargo.lock or package-lock.json/npm-shrinkwrap.json files; default root Cargo.lock and package-lock.json only."
        );
        schema
    }
    fn effects(&self) -> ToolEffects { self.source.effects() }

    async fn execute(&self, call_id: &str, input: Value,
        on_update: Option<Box<dyn Fn(ToolUpdate) + Send + Sync>>) -> Result<ToolOutput>
    {
        let op = input.get("op").and_then(Value::as_str).unwrap_or("").trim().to_ascii_lowercase();
        if op != "dependency_plan" {
            return self.source.execute(call_id, input, on_update).await;
        }
        let owner = AgentCx::for_current_or_request();
        if !owner.capabilities().io {
            return Err(Error::tool("security_scan", "dependency inventory requires I/O capability"));
        }
        owner.checkpoint().map_err(|_| Error::tool("security_scan", "dependency inventory cancelled"))?;
        let input: dependencies::Input = serde_json::from_value(input)
            .map_err(|_| Error::tool("security_scan", "invalid dependency_plan arguments"))?;
        let cwd = self.cwd.clone();
        let inventory = asupersync::runtime::spawn_blocking(move || {
            dependencies::inventory(&cwd, &input.paths)
        }).await?;
        owner.checkpoint().map_err(|_| Error::tool("security_scan", "dependency inventory cancelled"))?;
        let text = format!(
            "Dependency inventory: {} exact public-registry package/version pairs in {} lockfile(s); {} excluded entries. No vulnerability service was queried. Scope is selected lockfiles, not every workspace dependency.",
            inventory.packages.len(), inventory.lockfiles.len(), inventory.excluded.len()
        );
        Ok(ToolOutput {
            content: vec![ContentBlock::Text(TextContent::new(text))],
            details: Some(serde_json::to_value(inventory)?), is_error: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dependency_inventory_preserves_the_source_tool_schema() {
        let tool = SecurityScanTool::new(Path::new("."));
        let schema = tool.parameters();
        for op in ["plan", "run", "disposition", "compare", "dependency_plan"] {
            assert!(schema["properties"]["op"]["enum"].as_array().unwrap().contains(&json!(op)));
        }
        assert!(schema["properties"]["baseline"].is_object());
        assert!(schema["properties"]["fingerprint"].is_object());
        assert!(tool.effects().writes());
    }
}
