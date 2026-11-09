//! Nachrichten-Protokoll zwischen WingetApp (Controller) und Agent (Ziel-PC).
//!
//! Jede Nachricht ist ein JSON-Objekt auf genau einer Zeile (NDJSON). Ab
//! Protokoll 4 (App 0.6.0) läuft der gesamte Nachrichtenstrom innerhalb einer
//! TLS-1.3-Verbindung (siehe `tls.rs`) - niemand im Netzwerk kann mitlesen
//! oder Nachrichten verändern.
//!
//! Anmeldung (gegenseitig, an das TLS-Zertifikat gebunden):
//! 1. Haupt-PC -> `Hello { client_nonce }`
//! 2. Ziel-PC  -> `Challenge { nonce }`
//! 3. Haupt-PC -> `Auth { response }` = HMAC(Code, "client" | Nonces | Fingerabdruck)
//! 4. Ziel-PC  -> `Hello { proof }`   = HMAC(Code, "agent"  | Nonces | Fingerabdruck)
//!
//! Der Code selbst wird nie übertragen. Weil der Fingerabdruck des
//! TLS-Zertifikats in beide Werte eingeht, scheitert ein Angreifer, der sich
//! mit eigenem Zertifikat dazwischenschaltet - auf beiden Seiten.
//!
//! Sicherheitsprinzip: Der Agent führt **nie** freien Text aus. Es gibt nur
//! die Befehle aus [`RemoteCommand`], Paket-IDs und Suchbegriffe werden
//! validiert und als einzelne Argumente an `winget` übergeben (keine Shell).

use hmac::{Hmac, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;
use std::io::{self, BufRead, Read, Write};
use std::path::{Path, PathBuf};

type HmacSha256 = Hmac<Sha256>;

/// Wird beim Handshake verglichen. Bei inkompatiblen Änderungen erhöhen.
/// Version 3: zusätzlich Netzwerk-Suche (Discover/DiscoverReply).
/// Version 4 (0.6.0): TLS 1.3, gegenseitige Anmeldung mit Channel Binding.
pub const PROTOCOL_VERSION: u32 = 4;

/// Standard-Port des Agents.
pub const DEFAULT_AGENT_PORT: u16 = 47800;

/// Ergänzt den Standard-Port, falls nur eine IP bzw. ein Rechnername
/// eingegeben wurde ("192.168.1.50" -> "192.168.1.50:47800").
/// IPv6-Adressen ohne Port werden in eckige Klammern gesetzt.
pub fn with_default_port(addr: &str) -> String {
    let addr = addr.trim();
    if addr.parse::<std::net::SocketAddr>().is_ok() {
        return addr.to_string();
    }
    if let Ok(ip) = addr.parse::<std::net::Ipv6Addr>() {
        return format!("[{ip}]:{DEFAULT_AGENT_PORT}");
    }
    match addr.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => addr.to_string(),
        _ => format!("{addr}:{DEFAULT_AGENT_PORT}"),
    }
}

/// Maximale Größe einer einzelnen Nachricht (eine JSON-Zeile).
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

/// Maximale Anzahl Pakete bei einem Mehrfach-Update.
const MAX_UPGRADE_IDS: usize = 100;

/// Länge der Zufalls-Nonce für den Passwort-Challenge (Bytes).
pub const NONCE_BYTES: usize = 32;

/// Optional: Feste Passwort-Vorgabe für den Agent. Ist die Variable gesetzt,
/// gilt dieses Passwort; sonst gilt der dauerhafte Verbindungscode des PCs
/// (einmal erzeugt und gespeichert, siehe [`generate_password`] und
/// [`own_code_path`]). Bewusst nicht
/// als CLI-Argument, damit es nicht in der Prozessliste (z. B.
/// `tasklist`/`ps`) für andere Benutzer sichtbar ist.
pub const PASSWORD_ENV_VAR: &str = "WINGET_AGENT_PASSWORD";

/// Alle Befehle, die ein Agent ausführen darf (Whitelist).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteCommand {
    /// `winget --version`
    Version,
    /// `winget list`
    ListInstalled,
    /// `winget upgrade` (nur anzeigen, was verfügbar ist)
    ListUpgrades,
    /// `winget upgrade --id <id>` für jede angegebene ID nacheinander
    UpgradeIds { ids: Vec<String> },
    /// `winget search <query>`
    Search { query: String },
    /// `winget show <query>`
    Show { query: String },
    /// `winget install --id <id> -e`
    Install { id: String },
    /// `winget uninstall --id <id> -e`
    Uninstall { id: String },
    /// `winget source list`
    SourceList,
    /// `winget source update`
    SourceUpdate,
}

/// Nachrichten vom Controller (GUI) an den Agent.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Hello {
        protocol: u32,
        #[serde(default)]
        name: Option<String>,
        /// Zufallswert des Haupt-PCs (Hex, 32 Bytes). Geht in beide
        /// Anmelde-Nachweise ein, damit der Ziel-PC seinen Nachweis
        /// ([`AgentMessage::Hello`] `proof`) nicht vorab berechnen kann.
        #[serde(default)]
        client_nonce: Option<String>,
    },
    /// Antwort auf die [`AgentMessage::Challenge`], siehe
    /// [`compute_auth_response`]. Das Passwort selbst wird nie übertragen.
    Auth { response: String },
    Run { job: u64, command: RemoteCommand },
    Ping,
    /// Netzwerk-Suche: Fragt nur, wer hier lauscht. Wird ohne Passwort
    /// beantwortet (nur Rechnername, Version und Belegt-Status - keine
    /// Steuerung möglich).
    Discover,
}

/// Nachrichten vom Agent an den Controller.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AgentMessage {
    /// Zufalls-Nonce (Hex-String) für den Passwort-Nachweis. Wird direkt
    /// nach einem gültigen `Hello` geschickt, noch vor der Authentifizierung.
    Challenge { nonce: String },
    /// Erfolgreich authentifiziert.
    Hello {
        protocol: u32,
        agent_version: String,
        hostname: String,
        /// Läuft die App auf dem Ziel-PC mit Administratorrechten? `None` bei
        /// älteren Versionen (Feld optional, daher kompatibel mit 0.5.1).
        #[serde(default)]
        admin: Option<bool>,
        /// Nachweis, dass auch der Ziel-PC den Code kennt (siehe
        /// [`compute_agent_proof`]). Der Haupt-PC bricht ab, wenn er fehlt
        /// oder falsch ist.
        #[serde(default)]
        proof: Option<String>,
    },
    /// Passwort falsch oder Antwort ungültig - Verbindung wird danach
    /// vom Agent beendet.
    AuthFailed { message: String },
    /// Ein winget-Aufruf beginnt (`display` z. B. "$ winget list").
    Started { job: u64, display: String },
    /// Eine Zeile Live-Ausgabe (stdout/stderr).
    Line { job: u64, text: String },
    /// Ergebnis eines einzelnen winget-Aufrufs innerhalb eines Auftrags.
    StepFinished {
        job: u64,
        index: usize,
        success: bool,
        exit_code: Option<i32>,
    },
    /// Der Job ist komplett abgearbeitet.
    Finished {
        job: u64,
        success: bool,
        exit_code: Option<i32>,
    },
    /// Der Agent führt den Befehl nicht aus (z. B. ungültige Paket-ID).
    Rejected { job: u64, reason: String },
    /// Antwort auf [`ClientMessage::Discover`]: Kennung dieses PCs für die
    /// Geräteliste im Remote-Fenster. Danach wird die Verbindung beendet.
    DiscoverReply {
        agent_version: String,
        hostname: String,
        /// `true`, wenn dieser PC gerade von einem anderen PC ferngesteuert wird.
        #[serde(default)]
        busy: bool,
    },
    /// Allgemeiner Protokollfehler (nach dem Senden wird die Verbindung beendet).
    Error { message: String },
    Pong,
}

/// Erlaubt sind nur Zeichen, wie sie in winget-Paket-IDs vorkommen.
/// Ein führendes `-` ist verboten, damit eine ID nie als winget-Option
/// interpretiert werden kann.
pub fn is_valid_package_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && !id.starts_with('-')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+'))
}

/// Suchbegriffe: nicht leer, kurz, keine Steuerzeichen, kein führendes `-`.
pub fn is_valid_query(query: &str) -> bool {
    let q = query.trim();
    !q.is_empty() && q.len() <= 100 && !q.starts_with('-') && !q.chars().any(|c| c.is_control())
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

impl RemoteCommand {
    /// Übersetzt den Befehl in eine oder mehrere winget-Argumentlisten
    /// (ohne das Programm `winget` selbst). `Err` = Befehl wird abgelehnt.
    pub fn to_invocations(&self) -> Result<Vec<Vec<String>>, String> {
        match self {
            RemoteCommand::Version => Ok(vec![args(&["--version"])]),
            RemoteCommand::ListInstalled => {
                Ok(vec![args(&["list", "--accept-source-agreements"])])
            }
            RemoteCommand::ListUpgrades => {
                Ok(vec![args(&["upgrade", "--accept-source-agreements"])])
            }
            RemoteCommand::UpgradeIds { ids } => {
                if ids.is_empty() {
                    return Err("Keine Paket-IDs angegeben.".into());
                }
                if ids.len() > MAX_UPGRADE_IDS {
                    return Err(format!("Zu viele Pakete (max. {MAX_UPGRADE_IDS})."));
                }
                if let Some(bad) = ids.iter().find(|id| !is_valid_package_id(id)) {
                    return Err(format!("Ungültige Paket-ID: {bad:?}"));
                }
                Ok(ids
                    .iter()
                    .map(|id| {
                        args(&[
                            "upgrade",
                            "--id",
                            id,
                            "-e",
                            "--silent",
                            "--accept-package-agreements",
                            "--accept-source-agreements",
                            "--disable-interactivity",
                        ])
                    })
                    .collect())
            }
            RemoteCommand::Search { query } => {
                if !is_valid_query(query) {
                    return Err("Ungültiger Suchbegriff.".into());
                }
                Ok(vec![args(&[
                    "search",
                    query.trim(),
                    "--accept-source-agreements",
                ])])
            }
            RemoteCommand::Show { query } => {
                if !is_valid_query(query) {
                    return Err("Ungültiger Suchbegriff.".into());
                }
                Ok(vec![args(&[
                    "show",
                    query.trim(),
                    "--accept-source-agreements",
                ])])
            }
            RemoteCommand::Install { id } => {
                if !is_valid_package_id(id) {
                    return Err(format!("Ungültige Paket-ID: {id:?}"));
                }
                Ok(vec![args(&[
                    "install",
                    "--id",
                    id,
                    "-e",
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                    "--disable-interactivity",
                ])])
            }
            RemoteCommand::Uninstall { id } => {
                if !is_valid_package_id(id) {
                    return Err(format!("Ungültige Paket-ID: {id:?}"));
                }
                Ok(vec![args(&[
                    "uninstall",
                    "--id",
                    id,
                    "-e",
                    "--silent",
                    "--accept-source-agreements",
                    "--disable-interactivity",
                ])])
            }
            RemoteCommand::SourceList => Ok(vec![args(&["source", "list"])]),
            RemoteCommand::SourceUpdate => Ok(vec![args(&["source", "update"])]),
        }
    }
}

/// Menschliche Beschreibung, was ein Befehl auf dem Ziel-PC bewirkt -
/// damit am Ziel-PC sichtbar ist, was der Haupt-PC gerade vorhat.
pub fn describe_command(command: &RemoteCommand) -> String {
    match command {
        RemoteCommand::Version => "winget-Version abfragen".to_string(),
        RemoteCommand::ListInstalled => "installierte Programme auflisten".to_string(),
        RemoteCommand::ListUpgrades => "nach verfügbaren Updates suchen".to_string(),
        RemoteCommand::UpgradeIds { ids } => {
            format!("{} Update(s) installieren: {}", ids.len(), ids.join(", "))
        }
        RemoteCommand::Search { query } => format!("nach \"{query}\" suchen"),
        RemoteCommand::Show { query } => format!("Details zu \"{query}\" anzeigen"),
        RemoteCommand::Install { id } => format!("{id} INSTALLIEREN"),
        RemoteCommand::Uninstall { id } => format!("{id} DEINSTALLIEREN"),
        RemoteCommand::SourceList => "Paketquellen auflisten".to_string(),
        RemoteCommand::SourceUpdate => "Paketquellen aktualisieren".to_string(),
    }
}

/// Ergebnis eines einzelnen winget-Aufrufs, aus Erfolg + Exitcode abgeleitet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Hat geklappt.
    Ok,
    /// Hat geklappt, wird aber erst nach einem Neustart wirksam.
    OkNeedsRestart,
    /// Fehlgeschlagen.
    Failed,
}

/// Neustart-Codes zählen als Erfolg: Die Installation ist durch, Windows
/// braucht nur noch einen Neustart (MSI 3010/1641, winget 0x8A150109/0x8A15010B).
pub fn classify_exit(success: bool, code: Option<i32>) -> Outcome {
    if success {
        return Outcome::Ok;
    }
    match code.map(|c| c as u32) {
        Some(3010 | 1641 | 0x8A15_0109 | 0x8A15_010B) => Outcome::OkNeedsRestart,
        _ => Outcome::Failed,
    }
}

/// Exitcode als lesbarer Text, z. B.
/// "Fehlercode 0x8A150014: Kein passendes Paket gefunden".
/// Deckt die häufigen winget-Codes (0x8A15xxxx) sowie typische MSI- und
/// Windows-Codes ab; unbekannte Codes werden trotzdem mit Nummer angezeigt.
pub fn describe_exit_code(code: Option<i32>) -> String {
    let Some(code) = code else {
        return "winget konnte nicht gestartet werden (kein Exitcode)".to_string();
    };
    let hex = code as u32;
    let text = match hex {
        0 => "Erfolgreich",
        // --- winget allgemein ---
        0x8A15_0001 => "Interner Fehler von winget",
        0x8A15_0002 => "Ungültige Befehlszeilen-Argumente",
        0x8A15_0003 => "Befehl fehlgeschlagen",
        0x8A15_0004 => "Manifest konnte nicht geöffnet werden",
        0x8A15_0005 => "Abgebrochen",
        0x8A15_0007 => "Manifest ist für diese winget-Version zu neu - winget aktualisieren",
        0x8A15_0008 => "Download des Installers fehlgeschlagen (Internetverbindung?)",
        0x8A15_000A => "winget-Index ist beschädigt - \"Quellen aktualisieren\" ausführen",
        0x8A15_000B => "Quellen-Konfiguration ist beschädigt",
        0x8A15_000F => "Daten der Paketquelle fehlen - \"Quellen aktualisieren\" ausführen",
        0x8A15_0010 => "Kein passender Installer für dieses System",
        0x8A15_0011 => "Installer-Prüfsumme stimmt nicht (Paket wurde vom Hersteller geändert - später erneut versuchen)",
        0x8A15_0012 => "Paketquelle existiert nicht",
        0x8A15_0014 => "Kein passendes Paket gefunden",
        0x8A15_0015 => "Keine Paketquellen eingerichtet",
        0x8A15_0016 => "Mehrere Pakete passen auf diese Angabe",
        0x8A15_0017 => "Kein passendes Manifest gefunden",
        0x8A15_0019 => "Administratorrechte erforderlich",
        0x8A15_001A => "Paketquelle ist nicht sicher",
        0x8A15_001B => "Microsoft Store ist per Richtlinie gesperrt",
        0x8A15_001C => "Store-App ist per Richtlinie gesperrt",
        0x8A15_001E => "Installation der Store-App fehlgeschlagen",
        0x8A15_002B => "Kein anwendbares Update gefunden (Version schon aktuell oder Installer-Typ passt nicht)",
        0x8A15_002C => "Update aller Pakete mit Fehlern beendet",
        0x8A15_002D => "Installer hat die Sicherheitsprüfung nicht bestanden",
        0x8A15_002E => "Downloadgröße stimmt nicht",
        0x8A15_002F => "Deinstallationsbefehl nicht gefunden",
        0x8A15_0030 => "Deinstallationsbefehl fehlgeschlagen",
        0x8A15_003A => "Per Gruppenrichtlinie gesperrt",
        0x8A15_0041 => "Paket-Vereinbarungen wurden nicht akzeptiert",
        0x8A15_0046 => "Quellen-Vereinbarungen wurden nicht akzeptiert",
        0x8A15_0049 => "MSI-Installation fehlgeschlagen",
        0x8A15_004F => "Update-Version ist nicht neuer als die installierte",
        0x8A15_0050 => "Update-Version ist unbekannt",
        0x8A15_0056 => "Installer darf nicht mit Administratorrechten laufen",
        0x8A15_0061 => "Paket ist bereits installiert",
        0x8A15_0068 => "Paket ist angeheftet (Pin) - Update gesperrt",
        0x8A15_006D => "Dienst ist ausgelastet - später erneut versuchen",
        // --- Installation (vom Installer gemeldet) ---
        0x8A15_0101 => "Programm läuft gerade - auf dem Ziel-PC schließen und erneut versuchen",
        0x8A15_0102 => "Es läuft bereits eine andere Installation - später erneut versuchen",
        0x8A15_0103 => "Dateien sind in Benutzung - Programm schließen und erneut versuchen",
        0x8A15_0104 => "Eine benötigte Abhängigkeit fehlt",
        0x8A15_0105 => "Nicht genug Speicherplatz",
        0x8A15_0106 => "Nicht genug Arbeitsspeicher",
        0x8A15_0107 => "Internetverbindung erforderlich",
        0x8A15_0108 => "Fehler während der Installation",
        0x8A15_0109 => "Installiert - Neustart nötig, um abzuschließen",
        0x8A15_010A => "Installation fehlgeschlagen - PC neu starten und erneut versuchen",
        0x8A15_010B => "Installiert - PC wird zum Abschließen neu gestartet",
        0x8A15_010C => "Installation abgebrochen (z. B. UAC-Abfrage auf dem Ziel-PC abgelehnt oder nicht bestätigt)",
        0x8A15_010D => "Eine andere Version ist bereits installiert",
        0x8A15_010E => "Eine höhere Version ist bereits installiert",
        0x8A15_010F => "Per Richtlinie der Organisation gesperrt",
        0x8A15_0110 => "Abhängigkeiten konnten nicht installiert werden",
        0x8A15_0111 => "Programm wird von einem anderen Programm verwendet",
        0x8A15_0112 => "Ungültiger Parameter",
        0x8A15_0113 => "Paket wird von diesem System nicht unterstützt",
        0x8A15_0114 => "Installer unterstützt kein Update einer bestehenden Installation",
        0x8A15_0115 => "Installer meldet einen eigenen Fehler",
        // --- MSI / Windows ---
        1602 => "Vom Benutzer abgebrochen",
        1603 => "Schwerer Fehler während der Installation (MSI)",
        1618 => "Es läuft bereits eine andere Installation",
        1638 => "Eine andere Version dieses Produkts ist bereits installiert",
        1641 => "Installiert - Neustart wurde eingeleitet",
        3010 => "Installiert - Neustart nötig",
        5 | 0x8007_0005 => "Zugriff verweigert (Administratorrechte nötig)",
        1223 | 0x8007_04C7 => "Abgebrochen (UAC-Abfrage abgelehnt oder nicht bestätigt)",
        0x8007_0002 => "Datei nicht gefunden",
        0x8007_2EE7 | 0x8007_2EFD => "Server nicht erreichbar (Internetverbindung?)",
        0x8007_3D02 => "App wird gerade verwendet - auf dem Ziel-PC schließen",
        _ => "Unbekannter Fehler",
    };
    if (0..=0xFFFF).contains(&code) {
        format!("Fehlercode {code}: {text}")
    } else {
        format!("Fehlercode 0x{hex:08X}: {text}")
    }
}

/// Läuft dieses Programm mit Administratorrechten? Viele Updates (z. B.
/// Visual C++ Redistributable, .NET Runtime) installieren systemweit. Ohne
/// Adminrechte erscheint auf dem Ziel-PC eine UAC-Abfrage - wird sie nicht
/// bestätigt, schlägt das Update fehl.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    #[link(name = "shell32")]
    unsafe extern "system" {
        fn IsUserAnAdmin() -> i32;
    }
    // SAFETY: IsUserAnAdmin hat keine Parameter und keine Vorbedingungen.
    unsafe { IsUserAnAdmin() != 0 }
}

/// Außerhalb von Windows gibt es keine UAC-Abfrage.
#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    true
}

/// IPv4-Adresse dieses PCs im lokalen Netzwerk (für die Netzwerk-Suche).
/// Trick: Ein UDP-Socket wird zu einer externen Adresse "verbunden" (ohne ein
/// Paket zu senden); das Betriebssystem wählt dabei die passende Netzwerk-
/// karte, deren Adresse wir auslesen.
pub fn local_ipv4() -> Option<std::net::Ipv4Addr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip),
        _ => None,
    }
}

/// Erzeugt eine kryptographisch zufällige Nonce für den Passwort-Challenge.
pub fn random_nonce() -> [u8; NONCE_BYTES] {
    use rand::RngCore;
    let mut nonce = [0u8; NONCE_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    nonce
}

/// Anzahl der Zeichen eines erzeugten Verbindungscodes (ohne Bindestriche).
/// 20 Hex-Zeichen = 80 Bit (bis 0.5.x: 16 Zeichen = 64 Bit; solche älteren
/// Codes bleiben gültig).
pub const GENERATED_PASSWORD_CHARS: usize = 20;

/// Mindestlänge für ein selbst gewähltes Passwort (Umgebungsvariable
/// [`PASSWORD_ENV_VAR`]). Kürzere Passwörter lehnt der Ziel-PC beim Start ab.
pub const MIN_CUSTOM_PASSWORD_CHARS: usize = 12;

/// Prüft ein selbst gewähltes Passwort. `Err` enthält einen verständlichen
/// Hinweis für den Benutzer.
pub fn check_custom_password(password: &str) -> Result<(), String> {
    let len = password.trim().chars().count();
    if len < MIN_CUSTOM_PASSWORD_CHARS {
        return Err(format!(
            "Das Passwort in {PASSWORD_ENV_VAR} ist zu kurz ({len} Zeichen). \
             Bitte mindestens {MIN_CUSTOM_PASSWORD_CHARS} Zeichen verwenden \
             oder die Variable entfernen - dann gilt der sichere Verbindungscode der App."
        ));
    }
    Ok(())
}

/// Erzeugt einen zufälligen Verbindungscode wie `3FA9-27BC-91D4-E0A1-5C7E`:
/// 32 Bytes aus dem Zufallsgenerator des Betriebssystems plus Zeitstempel
/// werden mit SHA-256 gehasht, die ersten 20 Hex-Zeichen in Vierergruppen
/// ergeben den Code. Die eigentliche Zufälligkeit kommt vom Betriebssystem
/// (OsRng); SHA-256 mischt nur durch und liefert ein gleichmäßiges,
/// gut abtippbares Format ohne Sonderzeichen.
pub fn generate_password() -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(random_nonce());
    if let Ok(t) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        hasher.update(t.as_nanos().to_le_bytes());
    }
    let hex = hex_encode(&hasher.finalize()).to_uppercase();
    hex.as_bytes()[..GENERATED_PASSWORD_CHARS]
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Vereinheitlicht ein Passwort vor dem Vergleich - auf BEIDEN PCs. Sieht die
/// Eingabe wie ein Verbindungscode aus (nur Hex-Zeichen, Bindestriche und
/// Leerzeichen), werden Bindestriche/Leerzeichen entfernt und Buchstaben groß
/// geschrieben; so ist `3fa9 27bc ...` dasselbe wie `3FA9-27BC-...`. Alles
/// andere (eigene Passwörter) wird nur von Leerzeichen am Rand befreit.
pub fn normalize_password(input: &str) -> String {
    let t = input.trim();
    let code_like =
        !t.is_empty() && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-' || c == ' ');
    if code_like {
        t.chars()
            .filter(|c| c.is_ascii_hexdigit())
            .map(|c| c.to_ascii_uppercase())
            .collect()
    } else {
        t.to_string()
    }
}

// ---------------------------------------------------------------------------
// Dauerhaft gespeicherte Verbindungscodes
// ---------------------------------------------------------------------------
//
// Ziel-PC: Sein Code bleibt über Neustarts gleich (Datei `verbindungscode.dat`).
// Haupt-PC: Merkt sich pro PC den zuletzt funktionierenden Code (in der Liste
// "Bereits verbunden"). Beide werden unter Windows mit DPAPI verschlüsselt:
// Nur derselbe Windows-Benutzer auf demselben PC kann sie wieder lesen.

/// Ordner für gespeicherte Daten: `%APPDATA%\WingetApp` (Windows), sonst
/// `~/.config/WingetApp`. Der Ordnername bleibt bewusst "WingetApp", damit
/// die Liste "Bereits verbunden" aus älteren Versionen erhalten bleibt.
pub fn app_data_dir() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(base.join("WingetApp"))
}

/// Datei, in der der Ziel-PC seinen eigenen Verbindungscode aufbewahrt.
pub fn own_code_path() -> Option<PathBuf> {
    app_data_dir().map(|d| d.join("verbindungscode.dat"))
}

/// Windows-Datenschutz-API (DPAPI). Außerhalb von Windows gibt es in
/// Test- und Debug-Builds gleich aufgebaute Ersatzfunktionen (nur damit der
/// Code dort kompiliert und getestet werden kann); in Release-Builds außerhalb
/// von Windows wird gar nichts gespeichert.
#[cfg(any(windows, test, debug_assertions))]
#[allow(non_snake_case)] // Namen wie in der Windows-API
mod dpapi {
    use std::ffi::c_void;

    /// `DATA_BLOB` aus der Windows-API.
    #[repr(C)]
    pub struct DataBlob {
        pub cb_data: u32,
        pub pb_data: *mut u8,
    }

    /// Niemals ein Dialogfenster anzeigen.
    pub const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    #[cfg(windows)]
    #[link(name = "crypt32")]
    unsafe extern "system" {
        pub fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
        pub fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            ppsz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[cfg(windows)]
    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
    }

    // ----- Ersatz außerhalb von Windows (nur Tests/Debug) -----
    // Format: "STANDIN" | Länge Entropie (u32) | Entropie | Daten.
    // Wie echtes DPAPI scheitert das Öffnen mit falscher Entropie.

    #[cfg(not(windows))]
    const MAGIC: &[u8] = b"STANDIN";

    #[cfg(not(windows))]
    unsafe fn blob_bytes<'a>(blob: *const DataBlob) -> &'a [u8] {
        // SAFETY: Aufrufer übergibt NULL oder einen gültigen Blob.
        unsafe {
            if blob.is_null() || (*blob).pb_data.is_null() {
                return &[];
            }
            std::slice::from_raw_parts((*blob).pb_data, (*blob).cb_data as usize)
        }
    }

    #[cfg(not(windows))]
    unsafe fn give(output: *mut DataBlob, data: Vec<u8>) -> i32 {
        let copy: Box<[u8]> = data.into_boxed_slice();
        // SAFETY: `output` ist gültig (Aufrufer).
        unsafe {
            (*output).cb_data = copy.len() as u32;
            (*output).pb_data = Box::into_raw(copy) as *mut u8;
        }
        1
    }

    #[cfg(not(windows))]
    pub unsafe extern "system" fn CryptProtectData(
        p_data_in: *const DataBlob,
        _sz_data_descr: *const u16,
        p_optional_entropy: *const DataBlob,
        _pv_reserved: *mut c_void,
        _p_prompt_struct: *mut c_void,
        _dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32 {
        // SAFETY: wie bei der echten Funktion gibt der Aufrufer gültige Zeiger.
        unsafe {
            let entropy = blob_bytes(p_optional_entropy);
            let mut out = MAGIC.to_vec();
            out.extend_from_slice(&(entropy.len() as u32).to_le_bytes());
            out.extend_from_slice(entropy);
            out.extend_from_slice(blob_bytes(p_data_in));
            give(p_data_out, out)
        }
    }

    #[cfg(not(windows))]
    pub unsafe extern "system" fn CryptUnprotectData(
        p_data_in: *const DataBlob,
        _ppsz_data_descr: *mut *mut u16,
        p_optional_entropy: *const DataBlob,
        _pv_reserved: *mut c_void,
        _p_prompt_struct: *mut c_void,
        _dw_flags: u32,
        p_data_out: *mut DataBlob,
    ) -> i32 {
        // SAFETY: wie bei der echten Funktion gibt der Aufrufer gültige Zeiger.
        unsafe {
            let data = blob_bytes(p_data_in);
            let entropy = blob_bytes(p_optional_entropy);
            let Some(rest) = data.strip_prefix(MAGIC) else {
                return 0;
            };
            if rest.len() < 4 {
                return 0;
            }
            let len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]) as usize;
            let rest = &rest[4..];
            if rest.len() < len || &rest[..len] != entropy {
                return 0;
            }
            give(p_data_out, rest[len..].to_vec())
        }
    }

    /// Ersatz: Der Speicher der Ersatzfunktionen wird nicht freigegeben
    /// (nur in Tests unter Linux, winzige Mengen).
    #[cfg(not(windows))]
    pub unsafe extern "system" fn LocalFree(_h_mem: *mut c_void) -> *mut c_void {
        std::ptr::null_mut()
    }
}

/// Zusätzlicher, fester Schlüsselanteil für DPAPI ("optional entropy"): Andere
/// Programme desselben Windows-Benutzers können unsere Dateien damit nicht
/// einfach per `CryptUnprotectData` ohne dieses Wissen öffnen.
const DPAPI_ENTROPY: &[u8] = b"Abk-WingetApp/DPAPI/v1";

/// Liest einen von DPAPI gelieferten Puffer aus und gibt ihn danach frei.
#[cfg(any(windows, test, debug_assertions))]
fn take_blob(blob: dpapi::DataBlob) -> Vec<u8> {
    if blob.pb_data.is_null() {
        return Vec::new();
    }
    // SAFETY: DPAPI hat `cb_data` Bytes an `pb_data` angelegt; danach wird der
    // Puffer genau einmal mit LocalFree freigegeben.
    unsafe {
        let out = std::slice::from_raw_parts(blob.pb_data, blob.cb_data as usize).to_vec();
        dpapi::LocalFree(blob.pb_data.cast());
        out
    }
}

/// Verschlüsselt mit oder ohne Zusatz-Entropie (ohne nur für Tests der
/// Abwärtskompatibilität).
#[cfg(any(windows, test, debug_assertions))]
fn protect_with(data: &[u8], entropy: Option<&[u8]>) -> Option<Vec<u8>> {
    let mut input = data.to_vec();
    let blob_in = dpapi::DataBlob {
        cb_data: u32::try_from(input.len()).ok()?,
        pb_data: input.as_mut_ptr(),
    };
    let mut entropy_buf = entropy.map(<[u8]>::to_vec);
    let entropy_blob = entropy_buf.as_mut().map(|e| dpapi::DataBlob {
        cb_data: e.len() as u32,
        pb_data: e.as_mut_ptr(),
    });
    let entropy_ptr = entropy_blob
        .as_ref()
        .map_or(std::ptr::null(), |b| b as *const dpapi::DataBlob);
    let mut blob_out = dpapi::DataBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };
    let description: Vec<u16> = "Abk-WingetApp".encode_utf16().chain(Some(0)).collect();
    // SAFETY: Alle Zeiger zeigen auf gültige, lebende Daten bzw. sind NULL, wo
    // die API das erlaubt.
    let ok = unsafe {
        dpapi::CryptProtectData(
            &blob_in,
            description.as_ptr(),
            entropy_ptr,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dpapi::CRYPTPROTECT_UI_FORBIDDEN,
            &mut blob_out,
        )
    };
    (ok != 0).then(|| take_blob(blob_out))
}

#[cfg(any(windows, test, debug_assertions))]
fn unprotect_with(data: &[u8], entropy: Option<&[u8]>) -> Option<Vec<u8>> {
    let mut input = data.to_vec();
    let blob_in = dpapi::DataBlob {
        cb_data: u32::try_from(input.len()).ok()?,
        pb_data: input.as_mut_ptr(),
    };
    let mut entropy_buf = entropy.map(<[u8]>::to_vec);
    let entropy_blob = entropy_buf.as_mut().map(|e| dpapi::DataBlob {
        cb_data: e.len() as u32,
        pb_data: e.as_mut_ptr(),
    });
    let entropy_ptr = entropy_blob
        .as_ref()
        .map_or(std::ptr::null(), |b| b as *const dpapi::DataBlob);
    let mut blob_out = dpapi::DataBlob {
        cb_data: 0,
        pb_data: std::ptr::null_mut(),
    };
    // SAFETY: wie bei `protect_with`.
    let ok = unsafe {
        dpapi::CryptUnprotectData(
            &blob_in,
            std::ptr::null_mut(),
            entropy_ptr,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dpapi::CRYPTPROTECT_UI_FORBIDDEN,
            &mut blob_out,
        )
    };
    (ok != 0).then(|| take_blob(blob_out))
}

/// Release-Build außerhalb von Windows: keine sichere Ablage verfügbar, also
/// wird nichts gespeichert (lieber jedes Mal neu als im Klartext).
#[cfg(not(any(windows, test, debug_assertions)))]
fn protect_with(_data: &[u8], _entropy: Option<&[u8]>) -> Option<Vec<u8>> {
    None
}

#[cfg(not(any(windows, test, debug_assertions)))]
fn unprotect_with(_data: &[u8], _entropy: Option<&[u8]>) -> Option<Vec<u8>> {
    None
}

/// Nur für Tests: verschlüsselt im alten Format (ohne Zusatz-Entropie).
#[cfg(test)]
pub fn protect_with_legacy_for_tests(data: &[u8]) -> Vec<u8> {
    protect_with(data, None).expect("Ersatz-DPAPI")
}

/// Verschlüsselt Daten für den angemeldeten Windows-Benutzer (DPAPI mit
/// Zusatz-Entropie).
pub fn protect(data: &[u8]) -> Option<Vec<u8>> {
    protect_with(data, Some(DPAPI_ENTROPY))
}

/// Entschlüsselt Daten. Liefert zusätzlich `true`, wenn sie noch im alten
/// Format (bis 0.5.x, ohne Zusatz-Entropie) vorlagen und neu verschlüsselt
/// werden sollten. `None`, wenn die Daten beschädigt sind oder von einem
/// anderen Benutzer/PC stammen.
pub fn unprotect_ext(data: &[u8]) -> Option<(Vec<u8>, bool)> {
    if let Some(plain) = unprotect_with(data, Some(DPAPI_ENTROPY)) {
        return Some((plain, false));
    }
    unprotect_with(data, None).map(|plain| (plain, true))
}

/// Wie [`unprotect_ext`], ohne den Hinweis auf das alte Format.
pub fn unprotect(data: &[u8]) -> Option<Vec<u8>> {
    unprotect_ext(data).map(|(plain, _)| plain)
}

/// Verschlüsselt beliebige Daten und liefert sie als Text (Hex) zum Speichern.
pub fn seal_secret(data: &[u8]) -> Option<String> {
    protect(data).map(|bytes| hex_encode(&bytes))
}

/// Gegenstück zu [`seal_secret`].
pub fn open_secret(sealed: &str) -> Option<Vec<u8>> {
    unprotect(&hex_decode(sealed.trim())?)
}

/// Verschlüsselt einen Code und liefert ihn als Text (Hex) zum Speichern.
pub fn seal_code(code: &str) -> Option<String> {
    seal_secret(code.as_bytes())
}

/// Gegenstück zu [`seal_code`].
pub fn open_code(sealed: &str) -> Option<String> {
    open_code_ext(sealed).map(|(code, _)| code)
}

/// Wie [`open_code`]; `true` = lag im alten Format vor (neu speichern).
pub fn open_code_ext(sealed: &str) -> Option<(String, bool)> {
    let (bytes, legacy) = unprotect_ext(&hex_decode(sealed.trim())?)?;
    let code = String::from_utf8(bytes).ok().filter(|c| !c.trim().is_empty())?;
    Some((code, legacy))
}

/// Liest den gespeicherten eigenen Code (fehlt/kaputt -> `None`). Liegt er
/// noch im alten Format vor, wird er gleich im neuen Format gespeichert.
pub fn load_own_code(path: &Path) -> Option<String> {
    let (code, legacy) = open_code_ext(&std::fs::read_to_string(path).ok()?)?;
    if legacy {
        let _ = save_own_code(path, &code);
    }
    Some(code)
}

/// Speichert den eigenen Code verschlüsselt.
pub fn save_own_code(path: &Path, code: &str) -> io::Result<()> {
    let sealed = seal_code(code)
        .ok_or_else(|| io::Error::other("Code konnte nicht verschlüsselt werden"))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(path, sealed)
}

/// HMAC-SHA256 über Bezeichner + beide Zufallswerte + Zertifikats-
/// Fingerabdruck. Alle Teile haben feste Länge bzw. sind durch `|` getrennt
/// und enthalten selbst kein `|` - die Eingabe ist also eindeutig.
fn bound_mac(password: &str, label: &str, client_nonce: &[u8], nonce: &[u8], fingerprint: &str) -> String {
    // HMAC akzeptiert Schlüssel beliebiger Länge, daher kein unwrap-Risiko.
    let mut mac = <HmacSha256 as Mac>::new_from_slice(password.as_bytes())
        .expect("HMAC-SHA256 akzeptiert Schlüssel jeder Länge");
    mac.update(label.as_bytes());
    mac.update(b"|");
    mac.update(client_nonce);
    mac.update(b"|");
    mac.update(nonce);
    mac.update(b"|");
    mac.update(fingerprint.to_ascii_lowercase().as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

/// Anmelde-Nachweis des Haupt-PCs. Gebunden an beide Zufallswerte und an den
/// Fingerabdruck des TLS-Zertifikats, das der Haupt-PC gesehen hat (Channel
/// Binding): Sitzt jemand mit eigenem Zertifikat dazwischen, passt der Wert
/// beim echten Ziel-PC nicht.
pub fn compute_auth_response(password: &str, client_nonce: &[u8], nonce: &[u8], fingerprint: &str) -> String {
    bound_mac(password, "abk-wingetapp/v4/client", client_nonce, nonce, fingerprint)
}

/// Nachweis des Ziel-PCs, dass er den Code ebenfalls kennt (gegenseitige
/// Anmeldung). Anderer Bezeichner als [`compute_auth_response`], damit ein
/// Wert nie als der andere wiederverwendet werden kann.
pub fn compute_agent_proof(password: &str, client_nonce: &[u8], nonce: &[u8], fingerprint: &str) -> String {
    bound_mac(password, "abk-wingetapp/v4/agent", client_nonce, nonce, fingerprint)
}

/// Vergleicht zwei Hex-Strings in konstanter Zeit (verhindert, dass ein
/// Timing-Unterschied beim Vergleich Rückschlüsse auf das Passwort erlaubt).
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

/// Schreibt eine Nachricht als eine JSON-Zeile und flusht.
pub fn write_msg<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> io::Result<()> {
    let mut line = serde_json::to_string(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    line.push('\n');
    writer.write_all(line.as_bytes())?;
    writer.flush()
}

/// Liest die nächste Nachricht. `Ok(None)` = Gegenseite hat die Verbindung
/// sauber beendet. Zu lange oder ungültige Zeilen ergeben `InvalidData`.
pub fn read_msg<R: BufRead, T: DeserializeOwned>(reader: &mut R) -> io::Result<Option<T>> {
    let mut line = String::new();
    let mut limited = (&mut *reader).take(MAX_MESSAGE_BYTES as u64 + 1);
    let n = limited.read_line(&mut line)?;
    if n == 0 {
        return Ok(None);
    }
    if n > MAX_MESSAGE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Nachricht ist zu groß",
        ));
    }
    serde_json::from_str(line.trim_end())
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn describe_command_is_human_readable() {
        assert_eq!(
            describe_command(&RemoteCommand::Install { id: "Git.Git".into() }),
            "Git.Git INSTALLIEREN"
        );
        assert_eq!(
            describe_command(&RemoteCommand::ListUpgrades),
            "nach verfügbaren Updates suchen"
        );
        assert!(describe_command(&RemoteCommand::UpgradeIds {
            ids: vec!["A".into(), "B".into()]
        })
        .contains("2 Update(s)"));
    }

    #[test]
    fn exit_codes_are_explained_with_number() {
        let not_found = describe_exit_code(Some(0x8A15_0014_u32 as i32));
        assert!(not_found.contains("0x8A150014"), "{not_found}");
        assert!(not_found.contains("Kein passendes Paket"), "{not_found}");
        assert_eq!(describe_exit_code(Some(1603)), "Fehlercode 1603: Schwerer Fehler während der Installation (MSI)");
        assert!(describe_exit_code(Some(0x8A15_0999_u32 as i32)).starts_with("Fehlercode 0x8A150999: Unbekannter"));
        assert!(describe_exit_code(None).contains("nicht gestartet"));
    }

    #[test]
    fn restart_codes_count_as_success() {
        assert_eq!(classify_exit(true, Some(0)), Outcome::Ok);
        assert_eq!(classify_exit(false, Some(3010)), Outcome::OkNeedsRestart);
        assert_eq!(classify_exit(false, Some(0x8A15_0109_u32 as i32)), Outcome::OkNeedsRestart);
        assert_eq!(classify_exit(false, Some(0x8A15_0014_u32 as i32)), Outcome::Failed);
        assert_eq!(classify_exit(false, None), Outcome::Failed);
    }

    /// 0.5.1 kennt das Feld `admin` noch nicht - beide Richtungen müssen gehen.
    #[test]
    fn hello_admin_field_is_optional() {
        let old: AgentMessage = serde_json::from_str(
            r#"{"type":"hello","protocol":3,"agent_version":"0.5.1","hostname":"PC1"}"#,
        )
        .unwrap();
        assert!(matches!(old, AgentMessage::Hello { admin: None, .. }));
    }

    #[test]
    fn discover_messages_roundtrip() {
        let mut buf = Vec::new();
        write_msg(&mut buf, &ClientMessage::Discover).unwrap();
        assert!(String::from_utf8(buf.clone()).unwrap().contains("\"type\":\"discover\""));
        let back: ClientMessage = read_msg(&mut Cursor::new(buf)).unwrap().unwrap();
        assert!(matches!(back, ClientMessage::Discover));

        // `busy` ist optional (ältere Agents kennen das Feld nicht).
        let reply: AgentMessage = serde_json::from_str(
            r#"{"type":"discover_reply","agent_version":"0.5.0","hostname":"PC1"}"#,
        )
        .unwrap();
        assert!(matches!(reply, AgentMessage::DiscoverReply { busy: false, .. }));
    }

    #[test]
    fn package_ids() {
        assert!(is_valid_package_id("Microsoft.VisualStudioCode"));
        assert!(is_valid_package_id("7zip.7zip"));
        assert!(is_valid_package_id("XP9KHM4BK9FZ7Q"));
        assert!(!is_valid_package_id(""));
        assert!(!is_valid_package_id("--force"));
        assert!(!is_valid_package_id("a b"));
        assert!(!is_valid_package_id("a&calc"));
        assert!(!is_valid_package_id("a;b"));
        assert!(!is_valid_package_id(&"a".repeat(129)));
    }

    #[test]
    fn default_port_is_added() {
        assert_eq!(with_default_port("192.168.1.50"), "192.168.1.50:47800");
        assert_eq!(with_default_port(" 192.168.1.50:1234 "), "192.168.1.50:1234");
        assert_eq!(with_default_port("buero-pc"), "buero-pc:47800");
        assert_eq!(with_default_port("buero-pc:47801"), "buero-pc:47801");
        assert_eq!(with_default_port("fe80::1"), "[fe80::1]:47800");
        assert_eq!(with_default_port("[fe80::1]:5"), "[fe80::1]:5");
    }

    #[test]
    fn queries() {
        assert!(is_valid_query("visual studio"));
        assert!(!is_valid_query("   "));
        assert!(!is_valid_query("-h"));
        assert!(!is_valid_query("a\nb"));
    }

    #[test]
    fn invocations() {
        let inv = RemoteCommand::Install { id: "Git.Git".into() }
            .to_invocations()
            .unwrap();
        assert_eq!(inv.len(), 1);
        assert_eq!(&inv[0][..4], &["install", "--id", "Git.Git", "-e"]);

        let inv = RemoteCommand::UpgradeIds {
            ids: vec!["A.B".into(), "C.D".into()],
        }
        .to_invocations()
        .unwrap();
        assert_eq!(inv.len(), 2);

        // Ferngesteuerte Änderungen dürfen am Ziel-PC nie auf eine Eingabe warten.
        for cmd in [
            RemoteCommand::Install { id: "Git.Git".into() },
            RemoteCommand::Uninstall { id: "Git.Git".into() },
            RemoteCommand::UpgradeIds { ids: vec!["Git.Git".into()] },
        ] {
            for inv in cmd.to_invocations().unwrap() {
                assert!(inv.iter().any(|a| a == "--silent"), "{inv:?}");
                assert!(inv.iter().any(|a| a == "--disable-interactivity"), "{inv:?}");
            }
        }

        assert!(RemoteCommand::Install { id: "--x".into() }
            .to_invocations()
            .is_err());
        assert!(RemoteCommand::UpgradeIds { ids: vec![] }
            .to_invocations()
            .is_err());
    }

    #[test]
    fn json_roundtrip() {
        let msg = ClientMessage::Run {
            job: 7,
            command: RemoteCommand::Search { query: "git".into() },
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &msg).unwrap();
        assert!(buf.ends_with(b"\n"));
        let text = String::from_utf8(buf.clone()).unwrap();
        assert!(text.contains("\"type\":\"run\""));
        assert!(text.contains("\"type\":\"search\""));

        let mut reader = Cursor::new(buf);
        let back: ClientMessage = read_msg(&mut reader).unwrap().unwrap();
        match back {
            ClientMessage::Run { job, command } => {
                assert_eq!(job, 7);
                assert_eq!(command, RemoteCommand::Search { query: "git".into() });
            }
            _ => panic!("falsche Nachricht"),
        }
        assert!(read_msg::<_, ClientMessage>(&mut reader).unwrap().is_none());
    }

    #[test]
    fn handshake_and_step_messages_roundtrip() {
        let hello: ClientMessage =
            serde_json::from_str(r#"{"type":"hello","protocol":3}"#).unwrap();
        assert!(matches!(
            hello,
            ClientMessage::Hello {
                protocol: 3,
                name: None,
                client_nonce: None,
            }
        ));

        let step = AgentMessage::StepFinished {
            job: 7,
            index: 1,
            success: false,
            exit_code: Some(1),
        };
        let encoded = serde_json::to_vec(&step).unwrap();
        assert!(matches!(
            serde_json::from_slice::<AgentMessage>(&encoded).unwrap(),
            AgentMessage::StepFinished {
                job: 7,
                index: 1,
                success: false,
                exit_code: Some(1)
            }
        ));
    }

    #[test]
    fn unknown_command_is_rejected() {
        let mut reader = Cursor::new(
            b"{\"type\":\"run\",\"job\":1,\"command\":{\"type\":\"shell\",\"cmd\":\"calc\"}}\n"
                .to_vec(),
        );
        assert!(read_msg::<_, ClientMessage>(&mut reader).is_err());
    }

    #[test]
    fn auth_response_matches_only_for_correct_password() {
        let (cn, nonce) = (random_nonce(), random_nonce());
        let fp = "ab".repeat(32);
        let correct = compute_auth_response("geheim123", &cn, &nonce, &fp);
        let wrong = compute_auth_response("falsch", &cn, &nonce, &fp);
        assert!(constant_time_eq(&correct, &correct));
        assert!(!constant_time_eq(&correct, &wrong));
    }

    /// Channel Binding: Anderes Zertifikat (Angreifer dazwischen) -> anderer
    /// Wert. Und der Nachweis des Ziel-PCs ist nie gleich der Antwort des
    /// Haupt-PCs (kein "Zurückspiegeln" möglich).
    #[test]
    fn auth_is_bound_to_certificate_and_direction() {
        let (cn, nonce) = (random_nonce(), random_nonce());
        let real = "ab".repeat(32);
        let attacker = "cd".repeat(32);
        let a = compute_auth_response("CODE", &cn, &nonce, &real);
        assert_ne!(a, compute_auth_response("CODE", &cn, &nonce, &attacker));
        assert_ne!(a, compute_agent_proof("CODE", &cn, &nonce, &real));
        assert_ne!(a, compute_auth_response("CODE", &random_nonce(), &nonce, &real));
        // Groß-/Kleinschreibung des Fingerabdrucks spielt keine Rolle.
        assert_eq!(a, compute_auth_response("CODE", &cn, &nonce, &real.to_uppercase()));
    }

    #[test]
    fn custom_passwords_need_minimum_length() {
        assert!(check_custom_password("hallo12345").is_err());
        assert!(check_custom_password("  kurz  ").is_err());
        assert!(check_custom_password("ein-langes-Passwort").is_ok());
        let msg = check_custom_password("abc").unwrap_err();
        assert!(msg.contains("mindestens 12"), "{msg}");
    }

    /// Codes aus 0.5.x (ohne Zusatz-Entropie gespeichert) lassen sich weiter
    /// öffnen und werden beim Laden ins neue Format übernommen.
    #[test]
    fn legacy_dpapi_blobs_are_upgraded() {
        let legacy = hex_encode(&protect_with(b"AAAA-BBBB-CCCC-DDDD", None).unwrap());
        assert_eq!(open_code_ext(&legacy), Some(("AAAA-BBBB-CCCC-DDDD".into(), true)));
        let fresh = seal_code("AAAA-BBBB-CCCC-DDDD").unwrap();
        assert_eq!(open_code_ext(&fresh), Some(("AAAA-BBBB-CCCC-DDDD".into(), false)));
        // Neue Daten lassen sich OHNE die Entropie nicht öffnen.
        assert!(unprotect_with(&hex_decode(&fresh).unwrap(), None).is_none());

        let dir = std::env::temp_dir().join(format!("abk-legacy-{}", std::process::id()));
        let path = dir.join("verbindungscode.dat");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, &legacy).unwrap();
        assert_eq!(load_own_code(&path).as_deref(), Some("AAAA-BBBB-CCCC-DDDD"));
        let rewritten = std::fs::read_to_string(&path).unwrap();
        assert_eq!(open_code_ext(&rewritten).map(|(_, l)| l), Some(false));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generated_passwords_look_like_codes_and_differ() {
        let a = generate_password();
        let b = generate_password();
        assert_eq!(a.len(), GENERATED_PASSWORD_CHARS + 4);
        assert_eq!(a.matches('-').count(), 4);
        assert!(a.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        assert_ne!(a, b);
        // Der Code übersteht Abtipp-Varianten.
        assert_eq!(normalize_password(&a), normalize_password(&a.to_lowercase().replace('-', " ")));
        assert_eq!(normalize_password(&a).len(), GENERATED_PASSWORD_CHARS);
    }

    #[test]
    fn normalize_keeps_custom_passwords() {
        assert_eq!(normalize_password("  Geheim-123  "), "Geheim-123");
        assert_eq!(normalize_password("3fa9-27bc"), "3FA927BC");
        assert_eq!(normalize_password(""), "");
    }

    #[test]
    fn sealed_codes_roundtrip() {
        let sealed = seal_code("3FA9-27BC-91D4-E0A1").unwrap();
        assert_eq!(open_code(&sealed).as_deref(), Some("3FA9-27BC-91D4-E0A1"));
        assert_eq!(open_code("kein-hex"), None);
        assert_eq!(open_code(""), None);
    }

    #[test]
    fn own_code_is_stored_and_read_back() {
        let dir = std::env::temp_dir().join(format!("abk-code-{}", std::process::id()));
        let path = dir.join("verbindungscode.dat");
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(load_own_code(&path), None); // Datei fehlt
        save_own_code(&path, "AAAA-BBBB-CCCC-DDDD").unwrap();
        assert_eq!(load_own_code(&path).as_deref(), Some("AAAA-BBBB-CCCC-DDDD"));
        std::fs::write(&path, "zz-kaputt").unwrap();
        assert_eq!(load_own_code(&path), None); // kaputte Datei
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = [0u8, 1, 255, 16, 17];
        let hex = hex_encode(&bytes);
        assert_eq!(hex_decode(&hex).unwrap(), bytes.to_vec());
        assert!(hex_decode("abc").is_none()); // ungerade Länge
        assert!(hex_decode("zz").is_none()); // keine Hex-Ziffern
    }

    #[test]
    fn oversized_message_is_rejected() {
        let mut data = vec![b'x'; MAX_MESSAGE_BYTES + 10];
        data.push(b'\n');
        let mut reader = Cursor::new(data);
        assert!(read_msg::<_, ClientMessage>(&mut reader).is_err());
    }
}
