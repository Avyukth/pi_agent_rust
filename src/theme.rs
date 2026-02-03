//! JSON theme file format and loader.
//!
//! This module defines a Pi-specific theme schema and discovery rules:
//! - Global themes: `~/.pi/agent/themes/*.json`
//! - Project themes: `<cwd>/.pi/themes/*.json`

use crate::config::Config;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Theme {
    pub name: String,
    pub version: String,
    pub colors: ThemeColors,
    pub syntax: SyntaxColors,
    pub ui: UiColors,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ThemeColors {
    pub foreground: String,
    pub background: String,
    pub accent: String,
    pub success: String,
    pub warning: String,
    pub error: String,
    pub muted: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SyntaxColors {
    pub keyword: String,
    pub string: String,
    pub number: String,
    pub comment: String,
    pub function: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UiColors {
    pub border: String,
    pub selection: String,
    pub cursor: String,
}

/// Explicit roots for theme discovery.
#[derive(Debug, Clone)]
pub struct ThemeRoots {
    pub global_dir: PathBuf,
    pub project_dir: PathBuf,
}

impl ThemeRoots {
    #[must_use]
    pub fn from_cwd(cwd: &Path) -> Self {
        Self {
            global_dir: Config::global_dir(),
            project_dir: cwd.join(Config::project_dir()),
        }
    }
}

impl Theme {
    /// Discover available theme JSON files.
    #[must_use]
    pub fn discover_themes(cwd: &Path) -> Vec<PathBuf> {
        Self::discover_themes_with_roots(&ThemeRoots::from_cwd(cwd))
    }

    /// Discover available theme JSON files using explicit roots.
    #[must_use]
    pub fn discover_themes_with_roots(roots: &ThemeRoots) -> Vec<PathBuf> {
        let mut paths = Vec::new();
        paths.extend(glob_json(&roots.global_dir.join("themes")));
        paths.extend(glob_json(&roots.project_dir.join("themes")));
        paths.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
        paths
    }

    /// Load a theme from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let theme: Self = serde_json::from_str(&content)?;
        theme.validate()?;
        Ok(theme)
    }

    /// Load a theme by name, searching global and project theme directories.
    pub fn load_by_name(name: &str, cwd: &Path) -> Result<Self> {
        Self::load_by_name_with_roots(name, &ThemeRoots::from_cwd(cwd))
    }

    /// Load a theme by name using explicit roots.
    pub fn load_by_name_with_roots(name: &str, roots: &ThemeRoots) -> Result<Self> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::validation("Theme name is empty"));
        }

        for path in Self::discover_themes_with_roots(roots) {
            if let Ok(theme) = Self::load(&path) {
                if theme.name.eq_ignore_ascii_case(name) {
                    return Ok(theme);
                }
            }
        }

        Err(Error::config(format!("Theme not found: {name}")))
    }

    /// Default dark theme.
    #[must_use]
    pub fn dark() -> Self {
        Self {
            name: "dark".to_string(),
            version: "1.0".to_string(),
            colors: ThemeColors {
                foreground: "#d4d4d4".to_string(),
                background: "#1e1e1e".to_string(),
                accent: "#007acc".to_string(),
                success: "#4ec9b0".to_string(),
                warning: "#ce9178".to_string(),
                error: "#f44747".to_string(),
                muted: "#6a6a6a".to_string(),
            },
            syntax: SyntaxColors {
                keyword: "#569cd6".to_string(),
                string: "#ce9178".to_string(),
                number: "#b5cea8".to_string(),
                comment: "#6a9955".to_string(),
                function: "#dcdcaa".to_string(),
            },
            ui: UiColors {
                border: "#3c3c3c".to_string(),
                selection: "#264f78".to_string(),
                cursor: "#aeafad".to_string(),
            },
        }
    }

    /// Default light theme.
    #[must_use]
    pub fn light() -> Self {
        Self {
            name: "light".to_string(),
            version: "1.0".to_string(),
            colors: ThemeColors {
                foreground: "#2d2d2d".to_string(),
                background: "#ffffff".to_string(),
                accent: "#0066bf".to_string(),
                success: "#2e8b57".to_string(),
                warning: "#b36200".to_string(),
                error: "#c62828".to_string(),
                muted: "#7a7a7a".to_string(),
            },
            syntax: SyntaxColors {
                keyword: "#0000ff".to_string(),
                string: "#a31515".to_string(),
                number: "#098658".to_string(),
                comment: "#008000".to_string(),
                function: "#795e26".to_string(),
            },
            ui: UiColors {
                border: "#c8c8c8".to_string(),
                selection: "#cce7ff".to_string(),
                cursor: "#000000".to_string(),
            },
        }
    }

    fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::validation("Theme name is empty"));
        }
        if self.version.trim().is_empty() {
            return Err(Error::validation("Theme version is empty"));
        }

        Self::validate_color("colors.foreground", &self.colors.foreground)?;
        Self::validate_color("colors.background", &self.colors.background)?;
        Self::validate_color("colors.accent", &self.colors.accent)?;
        Self::validate_color("colors.success", &self.colors.success)?;
        Self::validate_color("colors.warning", &self.colors.warning)?;
        Self::validate_color("colors.error", &self.colors.error)?;
        Self::validate_color("colors.muted", &self.colors.muted)?;

        Self::validate_color("syntax.keyword", &self.syntax.keyword)?;
        Self::validate_color("syntax.string", &self.syntax.string)?;
        Self::validate_color("syntax.number", &self.syntax.number)?;
        Self::validate_color("syntax.comment", &self.syntax.comment)?;
        Self::validate_color("syntax.function", &self.syntax.function)?;

        Self::validate_color("ui.border", &self.ui.border)?;
        Self::validate_color("ui.selection", &self.ui.selection)?;
        Self::validate_color("ui.cursor", &self.ui.cursor)?;

        Ok(())
    }

    fn validate_color(field: &str, value: &str) -> Result<()> {
        let value = value.trim();
        if !value.starts_with('#') || value.len() != 7 {
            return Err(Error::validation(format!(
                "Invalid color for {field}: {value}"
            )));
        }
        if !value[1..].chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::validation(format!(
                "Invalid color for {field}: {value}"
            )));
        }
        Ok(())
    }
}

fn glob_json(dir: &Path) -> Vec<PathBuf> {
    if !dir.exists() {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            out.push(path);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_valid_theme_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("dark.json");
        let json = serde_json::json!({
            "name": "test-dark",
            "version": "1.0",
            "colors": {
                "foreground": "#ffffff",
                "background": "#000000",
                "accent": "#123456",
                "success": "#00ff00",
                "warning": "#ffcc00",
                "error": "#ff0000",
                "muted": "#888888"
            },
            "syntax": {
                "keyword": "#111111",
                "string": "#222222",
                "number": "#333333",
                "comment": "#444444",
                "function": "#555555"
            },
            "ui": {
                "border": "#666666",
                "selection": "#777777",
                "cursor": "#888888"
            }
        });
        fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

        let theme = Theme::load(&path).expect("load theme");
        assert_eq!(theme.name, "test-dark");
        assert_eq!(theme.version, "1.0");
    }

    #[test]
    fn rejects_invalid_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("broken.json");
        fs::write(&path, "{this is not json").unwrap();
        let err = Theme::load(&path).unwrap_err();
        match err {
            Error::Json(_) => {}
            other => panic!("expected json error, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_colors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.json");
        let json = serde_json::json!({
            "name": "bad",
            "version": "1.0",
            "colors": {
                "foreground": "red",
                "background": "#000000",
                "accent": "#123456",
                "success": "#00ff00",
                "warning": "#ffcc00",
                "error": "#ff0000",
                "muted": "#888888"
            },
            "syntax": {
                "keyword": "#111111",
                "string": "#222222",
                "number": "#333333",
                "comment": "#444444",
                "function": "#555555"
            },
            "ui": {
                "border": "#666666",
                "selection": "#777777",
                "cursor": "#888888"
            }
        });
        fs::write(&path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

        let err = Theme::load(&path).unwrap_err();
        match err {
            Error::Validation(_) => {}
            other => panic!("expected validation error, got {other:?}"),
        }
    }

    #[test]
    fn discover_themes_from_roots() {
        let dir = tempfile::tempdir().expect("tempdir");
        let global = dir.path().join("global");
        let project = dir.path().join("project");
        let global_theme_dir = global.join("themes");
        let project_theme_dir = project.join("themes");
        fs::create_dir_all(&global_theme_dir).unwrap();
        fs::create_dir_all(&project_theme_dir).unwrap();
        fs::write(global_theme_dir.join("g.json"), "{}").unwrap();
        fs::write(project_theme_dir.join("p.json"), "{}").unwrap();

        let roots = ThemeRoots {
            global_dir: global,
            project_dir: project,
        };
        let themes = Theme::discover_themes_with_roots(&roots);
        assert_eq!(themes.len(), 2);
    }

    #[test]
    fn default_themes_validate() {
        Theme::dark().validate().expect("dark theme valid");
        Theme::light().validate().expect("light theme valid");
    }
}
