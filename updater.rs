//! Update-Prüfung: Fragt bei jedem Programmstart bei GitHub nach der
//! neuesten Version. Nur wenn es eine neuere Version gibt,
//! meldet sie sich - sonst bleibt alles still (auch bei Fehlern/ohne Internet).
//!
//! Die Abfrage läuft über `curl` (ist in Windows 10/11 enthalten), damit keine
//! zusätzliche Bibliothek nötig ist.

use serde::Deserialize;
use std::process::{Command, Stdio};

/// GitHub-Repository im Format "benutzer/repository", z. B. "max/abk-wingetapp".
/// Solange hier nichts steht, wird nie nach Updates gesucht.
pub const GITHUB_REPO: &str = "ChrzzTea-dev/Abk-WingetApp";

/// Eine verfügbare neuere Version.
#[derive(Clone, Debug, PartialEq)]
pub struct UpdateInfo {
    pub version: String,
    /// Direkter Download (Installer/ZIP), sonst die Release-Seite.
    pub download_url: String,
    /// Release-Seite auf GitHub.
    pub page_url: String,
}

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    html_url: String,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// "v0.6.1" -> [0, 6, 1]. `None`, wenn keine Zahl erkennbar ist.
fn parse_version(text: &str) -> Option<Vec<u64>> {
    // Alles vor der ersten Ziffer ignorieren ("v0.6.1", "v.0.6.1", "Version 0.6.1").
    let parts: Vec<u64> = text
        .trim()
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .split('.')
        .map_while(|p| {
            let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .collect();
    (!parts.is_empty()).then_some(parts)
}

/// Ist `remote` neuer als `local`? (fehlende Stellen zählen als 0)
fn is_newer(remote: &str, local: &str) -> bool {
    let (Some(mut r), Some(mut l)) = (parse_version(remote), parse_version(local)) else {
        return false;
    };
    let len = r.len().max(l.len());
    r.resize(len, 0);
    l.resize(len, 0);
    r > l
}

/// Liest die neueste Release von GitHub.
fn fetch_latest(repo: &str) -> Result<UpdateInfo, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let mut cmd = Command::new("curl");
    cmd.args([
        "-s",
        "-S",
        "-f",
        "-L",
        "--max-time",
        "10",
        "-H",
        "User-Agent: Abk-WingetApp",
        "-H",
        "Accept: application/vnd.github+json",
        &url,
    ])
    .stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let output = cmd.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    parse_release(&String::from_utf8_lossy(&output.stdout))
}

fn parse_release(json: &str) -> Result<UpdateInfo, String> {
    let release: Release = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let wanted = [".exe", ".msi", ".zip"];
    let download_url = release
        .assets
        .iter()
        .find(|a| wanted.iter().any(|ext| a.name.to_lowercase().ends_with(ext)))
        .or_else(|| release.assets.first())
        .map(|a| a.browser_download_url.clone())
        .unwrap_or_else(|| release.html_url.clone());
    Ok(UpdateInfo {
        version: release
            .tag_name
            .trim_start_matches(|c: char| !c.is_ascii_digit())
            .to_string(),
        download_url,
        page_url: release.html_url,
    })
}

/// Prüft (bei jedem Aufruf), ob es eine neuere Version gibt.
/// Blockiert kurz - in einem Hintergrund-Thread aufrufen. Gibt nur dann
/// `Some` zurück, wenn wirklich eine neuere Version vorliegt.
pub fn check_if_due(current_version: &str) -> Option<UpdateInfo> {
    if GITHUB_REPO.is_empty() {
        return None;
    }
    let latest = fetch_latest(GITHUB_REPO).ok()?;
    is_newer(&latest.version, current_version).then_some(latest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_are_compared_numerically() {
        assert!(is_newer("0.6.1", "0.6.0"));
        assert!(is_newer("v0.10.0", "0.9.9"));
        assert!(is_newer("v.0.6.1", "0.6.0")); // Tippfehler im Tag ("v.0.6.1")
        assert!(is_newer("1.0", "0.6.0"));
        assert!(!is_newer("0.6.0", "0.6.0"));
        assert!(!is_newer("0.6.0.0", "0.6"));
        assert!(!is_newer("0.5.4", "0.6.0"));
        assert!(!is_newer("kaputt", "0.6.0"));
    }

    #[test]
    fn release_json_is_parsed() {
        let json = r#"{"tag_name":"v0.7.0","html_url":"https://github.com/a/b/releases/tag/v0.7.0",
            "assets":[{"name":"notes.txt","browser_download_url":"https://x/notes.txt"},
                      {"name":"Setup.exe","browser_download_url":"https://x/Setup.exe"}]}"#;
        let info = parse_release(json).unwrap();
        assert_eq!(info.version, "0.7.0");
        assert_eq!(info.download_url, "https://x/Setup.exe");
        let bare = parse_release(r#"{"tag_name":"0.7.0","html_url":"https://h"}"#).unwrap();
        assert_eq!(bare.download_url, "https://h");
    }
}
