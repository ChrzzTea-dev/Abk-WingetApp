//! "Remote"-Fenster der WingetApp: verbindet sich mit einem Ziel-PC, auf dem
//! ebenfalls die WingetApp läuft (der Agent startet dort automatisch), und
//! bedient dort winget über drei Reiter:
//!
//! - **Updates auswählen**: verfügbare Updates mit Häkchen, ausgewählte werden
//!   auf dem Ziel-PC installiert.
//! - **Paket installieren**: Suchfeld mit automatischen Vorschlägen aus den
//!   winget-Quellen des Ziel-PCs.
//! - **Paket deinstallieren**: filterbare Liste der installierten Programme.
//!
//! **Netzwerk-Suche**: Beim Programmstart (und danach regelmäßig, solange das
//! Fenster offen und nichts verbunden ist) werden alle PCs im eigenen /24-Netz
//! angeklopft. Wer die WingetApp laufen hat, antwortet - ganz ohne Passwort -
//! mit Gerätename und Version. Die Treffer erscheinen als Liste mit
//! "Verbinden"-Knopf; eine IP von Hand einzutippen ist nicht mehr nötig.
//!
//! **Bereits verbunden**: Jeder PC, mit dem erfolgreich verbunden wurde, wird
//! (Name, IPv4, MAC, Zeitpunkt) in einer eigenen Liste gemerkt und in einer
//! kleinen Datei im Profil-Ordner gespeichert. So sieht man auch nach einem
//! Neustart, mit wem man schon verbunden war - mit Verbinden-Knopf. Der
//! Verbindungscode wird dabei mit DPAPI verschlüsselt gespeichert.
//!
//! **Sicherheit (0.6.0)**: Alle Verbindungen laufen über TLS 1.3. Der
//! Fingerabdruck des Zertifikats jedes Ziel-PCs wird bei der ersten
//! Verbindung gemerkt ("Trust on first use"). Ändert er sich später, bricht
//! die App ab, BEVOR ein Anmelde-Nachweis gesendet wird, und zeigt eine
//! Warnung mit "Zertifikat neu vertrauen". Zusätzlich muss der Ziel-PC selbst
//! nachweisen, dass er den Code kennt (gegenseitige Anmeldung).
//!
//! Die Ausgabe unten fasst zusammen, was passiert ist (z. B. welche Programme
//! aktualisiert wurden). Die rohe winget-Ausgabe lässt sich bei Bedarf
//! einblenden.

use crate::agent::is_progress_line;
use crate::protocol::*;
use crate::tls;
use crate::{parse_package_table, parse_upgrade_output, PackageItem, UpgradeItem};
use eframe::egui::{self, Color32, RichText};
use serde::{Deserialize, Serialize};
use std::io::{self, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Wie viele PCs gleichzeitig angefragt werden (Netzwerk-Suche).
const SCAN_WORKERS: usize = 64;
/// Zeitlimit beim Anklopfen an einen einzelnen PC.
const SCAN_CONNECT_TIMEOUT: Duration = Duration::from_millis(400);
const SCAN_READ_TIMEOUT: Duration = Duration::from_millis(1200);
/// Letztes Oktett 1..=254 wird durchprobiert.
const SCAN_HOSTS: usize = 254;
/// So oft wird bei offenem Fenster (und ohne Verbindung) automatisch neu gesucht.
const SCAN_REFRESH: Duration = Duration::from_secs(20);

/// Ein im Netzwerk gefundener PC, auf dem die App läuft.
#[derive(Clone)]
pub struct DiscoveredPc {
    pub ip: Ipv4Addr,
    pub hostname: String,
    pub mac: String,
    pub version: String,
    /// Passt die Protokoll-Version? Sonst: gefunden, aber andere App-Version.
    pub compatible: bool,
    /// Wird dieser PC gerade von einem anderen PC ferngesteuert?
    pub busy: bool,
    /// Fingerabdruck des TLS-Zertifikats (`None` bei älteren Versionen).
    pub fingerprint: Option<String>,
}

/// Erste drei Oktette des eigenen /24-Netzes (für die Suche). Über die
/// Umgebungsvariable ABK_SCAN_BASE (z. B. "127.0.0") überschreibbar - nur
/// zum Testen.
fn scan_base() -> Option<(u8, u8, u8)> {
    if let Ok(base) = std::env::var("ABK_SCAN_BASE") {
        let p: Vec<&str> = base.split('.').collect();
        if let [a, b, c] = p[..] {
            return Some((a.parse().ok()?, b.parse().ok()?, c.parse().ok()?));
        }
    }
    let o = local_ipv4()?.octets();
    Some((o[0], o[1], o[2]))
}

fn scan_port() -> u16 {
    std::env::var("ABK_SCAN_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_AGENT_PORT)
}

/// Rechnername dieses PCs (wird dem Ziel-PC beim Anmelden mitgeteilt).
fn own_name() -> Option<String> {
    ["COMPUTERNAME", "HOSTNAME"].iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .filter(|name| !name.trim().is_empty())
    })
}

/// Fragt einen einzelnen PC ab: Läuft dort die App? Liefert Kennung + MAC.
/// Die Abfrage läuft verschlüsselt (TLS) und liefert auch den Fingerabdruck
/// des Zertifikats - so fällt ein geändertes Zertifikat schon in der Liste auf.
fn probe_host(ip: Ipv4Addr, port: u16) -> Option<DiscoveredPc> {
    let addr = SocketAddr::from((ip, port));
    let stream = TcpStream::connect_timeout(&addr, SCAN_CONNECT_TIMEOUT).ok()?;
    let _ = stream.set_read_timeout(Some(SCAN_READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SCAN_READ_TIMEOUT));

    let (hostname, version, compatible, busy, fingerprint) = match tls::connect(stream) {
        Ok((mut tls, fp)) => {
            let mut lines = tls::LineReader::default();
            send_raw(
                &mut tls,
                &ClientMessage::Hello {
                    protocol: PROTOCOL_VERSION,
                    name: own_name(),
                    client_nonce: Some(hex_encode(&random_nonce())),
                },
            )
            .ok()?;
            let reply = match read_agent(&mut tls, &mut lines) {
                Ok(Some(AgentMessage::Challenge { .. })) => {
                    send_raw(&mut tls, &ClientMessage::Discover).ok()?;
                    match read_agent(&mut tls, &mut lines) {
                        Ok(Some(AgentMessage::DiscoverReply {
                            agent_version,
                            hostname,
                            busy,
                        })) => (hostname, agent_version, true, busy, Some(fp)),
                        _ => return None,
                    }
                }
                // Neuere App-Version mit anderem Protokoll.
                Ok(Some(AgentMessage::Error { .. })) => (
                    "(andere App-Version)".to_string(),
                    String::new(),
                    false,
                    false,
                    Some(fp),
                ),
                _ => return None,
            };
            tls.conn.send_close_notify();
            let _ = tls.flush();
            reply
        }
        // Kein TLS: evtl. eine ältere App-Version (bis 0.5.x, unverschlüsselt).
        Err(_) => {
            if !probe_old_version(addr) {
                return None;
            }
            (
                "(ältere App-Version)".to_string(),
                String::new(),
                false,
                false,
                None,
            )
        }
    };

    Some(DiscoveredPc {
        ip,
        hostname,
        mac: mac_for_ip(ip).unwrap_or_else(|| NO_MAC.to_string()),
        version,
        compatible,
        busy,
        fingerprint,
    })
}

/// Antwortet hier eine App bis 0.5.x (unverschlüsselt)? Es wird nur ein
/// Hello geschickt - weder Code noch sonst etwas Vertrauliches.
fn probe_old_version(addr: SocketAddr) -> bool {
    let Ok(stream) = TcpStream::connect_timeout(&addr, SCAN_CONNECT_TIMEOUT) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(SCAN_READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(SCAN_READ_TIMEOUT));
    let Ok(clone) = stream.try_clone() else {
        return false;
    };
    let mut reader = BufReader::new(clone);
    let mut writer = stream;
    let hello = ClientMessage::Hello {
        protocol: PROTOCOL_VERSION,
        name: None,
        client_nonce: None,
    };
    let found = write_msg(&mut writer, &hello).is_ok()
        && matches!(
            read_msg::<_, AgentMessage>(&mut reader),
            Ok(Some(AgentMessage::Challenge { .. } | AgentMessage::Error { .. }))
        );
    let _ = writer.shutdown(Shutdown::Both);
    found
}

/// Schreibt eine Nachricht in die TLS-Verbindung.
fn send_raw(tls: &mut tls::ClientTls, msg: &ClientMessage) -> io::Result<()> {
    write_msg(tls, msg)
}

/// Liest die nächste Nachricht (blockierend bis zum Zeitlimit des Sockets).
/// `Ok(None)` = Verbindung beendet.
fn read_agent(tls: &mut tls::ClientTls, lines: &mut tls::LineReader) -> io::Result<Option<AgentMessage>> {
    match lines.poll_line(tls, MAX_MESSAGE_BYTES)? {
        tls::Polled::Line(line) => serde_json::from_str(line.trim_end())
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        tls::Polled::Closed => Ok(None),
        tls::Polled::Pending => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "Zeitüberschreitung - keine Antwort vom Ziel-PC",
        )),
    }
}

/// Liest die MAC-Adresse zu einer IP aus der ARP-Tabelle des Betriebssystems.
/// Funktioniert nur im selben Netz-Segment (genau unser Fall).
fn mac_for_ip(ip: Ipv4Addr) -> Option<String> {
    let ip = ip.to_string();
    let output = {
        let mut cmd = Command::new(if cfg!(windows) { "arp" } else { "ip" });
        if cfg!(windows) {
            cmd.args(["-a", &ip]);
        } else {
            cmd.args(["neigh", "show", &ip]);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        cmd.output().ok()?
    };
    let text = String::from_utf8_lossy(&output.stdout);
    parse_mac(&text)
}

/// Sucht in einer ARP/neigh-Ausgabe das erste MAC-ähnliche Feld.
fn parse_mac(text: &str) -> Option<String> {
    for token in text.split([' ', '\t', '\n', '\r']) {
        if looks_like_mac(token) {
            return Some(token.to_uppercase().replace('-', ":"));
        }
    }
    None
}

fn looks_like_mac(token: &str) -> bool {
    let parts: Vec<&str> = if token.contains(':') {
        token.split(':').collect()
    } else if token.contains('-') {
        token.split('-').collect()
    } else {
        return false;
    };
    parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
        // Platzhalter-MAC (alle Nullen) ignorieren, egal welches Trennzeichen.
        && !parts.iter().all(|p| *p == "00")
}

const MAX_LINES: usize = 5000;

/// Platzhalter, wenn keine MAC-Adresse ermittelt werden konnte.
const NO_MAC: &str = "–";
/// So viele PCs merkt sich die Liste "Bereits verbunden" höchstens.
const MAX_KNOWN_PCS: usize = 50;

/// Ein PC, mit dem schon einmal erfolgreich verbunden wurde.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct KnownPc {
    pub hostname: String,
    pub ip: String,
    pub mac: String,
    /// Zeitpunkt der letzten Verbindung (Sekunden seit 1970).
    pub last_connected: u64,
    /// Zuletzt funktionierender Verbindungscode dieses PCs, mit DPAPI
    /// verschlüsselt (siehe [`seal_code`]). Fehlt bei Einträgen aus älteren
    /// Versionen und bei PCs, deren Code nicht mehr stimmt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Fingerabdruck (SHA-256) des TLS-Zertifikats dieses PCs, gemerkt bei
    /// der ersten verschlüsselten Verbindung (Pinning). Nicht geheim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// "gerade eben", "vor 5 Min.", "vor 3 Std.", "vor 2 Tagen".
fn format_ago(secs: u64) -> String {
    match secs {
        0..=59 => "gerade eben".to_string(),
        60..=3599 => format!("vor {} Min.", secs / 60),
        3600..=86399 => format!("vor {} Std.", secs / 3600),
        _ => match secs / 86400 {
            1 => "vor 1 Tag".to_string(),
            d => format!("vor {d} Tagen"),
        },
    }
}

/// Derselbe PC? Gleiche MAC-Adresse (falls bekannt) oder gleicher Name.
/// Die IP allein taugt nicht, sie kann sich per DHCP ändern.
fn is_same_pc(host_a: &str, mac_a: &str, host_b: &str, mac_b: &str) -> bool {
    (mac_a != NO_MAC && mac_b != NO_MAC && mac_a.eq_ignore_ascii_case(mac_b))
        || host_a.eq_ignore_ascii_case(host_b)
}

/// Trägt einen PC in die Liste ein oder aktualisiert ihn; der neueste steht oben.
fn upsert_known(list: &mut Vec<KnownPc>, hostname: &str, ip: &str, mac: &str, now: u64) {
    let mac = mac.to_uppercase();
    let mac = mac.as_str();
    if let Some(k) = list
        .iter_mut()
        .find(|k| is_same_pc(&k.hostname, &k.mac, hostname, mac))
    {
        k.hostname = hostname.to_string();
        k.ip = ip.to_string();
        if mac != NO_MAC {
            k.mac = mac.to_string();
        }
        k.last_connected = now;
    } else {
        list.push(KnownPc {
            hostname: hostname.to_string(),
            ip: ip.to_string(),
            mac: mac.to_string(),
            last_connected: now,
            code: None,
            fingerprint: None,
        });
    }
    list.sort_by(|a, b| b.last_connected.cmp(&a.last_connected));
    list.truncate(MAX_KNOWN_PCS);
}

/// Speicherort der Liste: `%APPDATA%\WingetApp\bekannte-pcs.json` (Windows),
/// sonst `~/.config/WingetApp/bekannte-pcs.json`.
fn history_path() -> Option<PathBuf> {
    app_data_dir().map(|d| d.join("bekannte-pcs.json"))
}

/// Fehlermeldung bei falschem Code - wird auch erkannt, um einen nicht mehr
/// gültigen gespeicherten Code zu vergessen.
const WRONG_CODE_ERROR: &str = "Falscher Verbindungscode. Bitte den Code prüfen, der auf dem \
     Ziel-PC angezeigt wird (er ändert sich nur, wenn dort \"Neu erzeugen\" gedrückt wird).";

/// Mit welchem Code der laufende Verbindungsversuch arbeitet.
struct Attempt {
    conn: u64,
    /// Vereinheitlichter Code; wird nach erfolgreicher Anmeldung für den PC
    /// gespeichert.
    code: String,
    /// `Some(Name)`, wenn der gespeicherte Code dieses PCs benutzt wurde.
    saved_for: Option<String>,
    /// Eintrag in "Bereits verbunden", gegen dessen Fingerabdruck geprüft wird.
    known: Option<usize>,
}

/// Liest die Liste; fehlt die Datei oder ist sie kaputt, ist die Liste leer.
/// Codes, die noch im alten Format (bis 0.5.x) gespeichert sind, werden
/// gleich im neuen Format (DPAPI mit Zusatz-Entropie) zurückgeschrieben.
fn load_known(path: &Path) -> Vec<KnownPc> {
    let mut list: Vec<KnownPc> = std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default();
    if upgrade_sealed_codes(&mut list) {
        let _ = save_known(path, &list);
    }
    list
}

/// Verschlüsselt Codes im alten Format neu. `true` = etwas geändert.
fn upgrade_sealed_codes(list: &mut [KnownPc]) -> bool {
    let mut changed = false;
    for k in list.iter_mut() {
        let Some(sealed) = k.code.as_deref() else { continue };
        if let Some((code, true)) = open_code_ext(sealed) {
            if let Some(resealed) = seal_code(&code) {
                k.code = Some(resealed);
                changed = true;
            }
        }
    }
    changed
}

/// Hinweis: Das Zertifikat eines bekannten PCs hat sich geändert.
struct CertAlert {
    /// Index in "Bereits verbunden".
    known: usize,
    hostname: String,
    old: String,
    new: String,
}

fn save_known(path: &Path, list: &[KnownPc]) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let text = serde_json::to_string_pretty(list)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    std::fs::write(path, text)
}

/// Im Leerlauf wird in diesem Abstand ein Ping geschickt. Das hält die
/// Verbindung am Leben (der Agent trennt nach 120 s ohne Lebenszeichen) und
/// bemerkt eine abgerissene Verbindung schnell.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
/// So lange nach dem letzten Tastendruck wird gewartet, bevor die
/// Vorschläge vom Ziel-PC geholt werden.
const SEARCH_DEBOUNCE: Duration = Duration::from_millis(650);
const MIN_SEARCH_LEN: usize = 2;

const GREEN: Color32 = Color32::from_rgb(46, 160, 90);
const RED: Color32 = Color32::from_rgb(205, 65, 65);
const AMBER: Color32 = Color32::from_rgb(220, 150, 30);
const TERM_BG: Color32 = Color32::from_rgb(24, 26, 31);

/// Ereignisse aus den Hintergrund-Threads. `conn` ist die ID der Verbindung,
/// damit verspätete Ereignisse einer alten Verbindung ignoriert werden.
enum UiEvent {
    Connected {
        conn: u64,
        link: Link,
        /// Fingerabdruck des Zertifikats, das der Ziel-PC vorgezeigt hat.
        fingerprint: String,
        hostname: String,
        agent_version: String,
        /// Adminrechte auf dem Ziel-PC (`None` = ältere Version, unbekannt).
        admin: Option<bool>,
        /// Gegenstelle der Verbindung (für die Liste "Bereits verbunden").
        peer_ip: Option<IpAddr>,
        /// MAC-Adresse der Gegenstelle ("–", wenn nicht ermittelbar).
        mac: String,
    },
    ConnectFailed {
        conn: u64,
        error: String,
    },
    /// Zertifikat passt nicht zum gespeicherten Fingerabdruck.
    CertChanged {
        conn: u64,
        fingerprint: String,
    },
    Agent {
        conn: u64,
        msg: AgentMessage,
    },
    Disconnected {
        conn: u64,
        reason: String,
    },
}

enum ConnState {
    Disconnected,
    Connecting,
    Connected {
        hostname: String,
        agent_version: String,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Updates,
    Install,
    Uninstall,
}

/// Was der gerade laufende Auftrag ist - bestimmt, wohin seine Ausgabe geht
/// und welche Zusammenfassung am Ende in der Ausgabe erscheint.
enum JobKind {
    ListUpgrades,
    InstallUpgrades {
        items: Vec<UpgradeItem>,
        ok: Vec<String>,
        failed: Vec<String>,
    },
    Search {
        query: String,
    },
    Install {
        item: PackageItem,
    },
    ListInstalled,
    Uninstall {
        item: PackageItem,
    },
}

struct RunningJob {
    id: u64,
    kind: JobKind,
    /// Gesammelte winget-Ausgabe (für Listen, die geparst werden).
    raw: Vec<String>,
    /// Wie viele einzelne winget-Aufrufe schon fertig sind.
    steps_done: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum LogKind {
    Info,
    Success,
    Error,
    Warning,
    /// "$ winget ..." - nur bei eingeschalteten Details sichtbar.
    Command,
    /// Rohe winget-Ausgabe - nur bei eingeschalteten Details sichtbar.
    Raw,
}

impl LogKind {
    fn color(self) -> Color32 {
        match self {
            LogKind::Info => Color32::from_rgb(214, 218, 224),
            LogKind::Success => Color32::from_rgb(110, 210, 140),
            LogKind::Error => Color32::from_rgb(240, 110, 110),
            LogKind::Warning => Color32::from_rgb(240, 190, 90),
            LogKind::Command => Color32::from_rgb(120, 170, 255),
            LogKind::Raw => Color32::from_rgb(140, 146, 156),
        }
    }

    fn is_detail(self) -> bool {
        matches!(self, LogKind::Command | LogKind::Raw)
    }
}

struct LogLine {
    kind: LogKind,
    text: String,
}

pub struct RemotePanel {
    /// Fenster sichtbar? (wird vom Remote-Button gesetzt)
    pub open: bool,
    address: String,
    /// Eingetippter Verbindungscode. Wird nur für die erste Verbindung mit
    /// einem PC gebraucht: Danach merkt sich die App den Code pro PC
    /// (verschlüsselt) und das Feld wird wieder geleert.
    password: String,
    /// Laufender Verbindungsversuch (welcher Code, woher).
    attempt: Option<Attempt>,
    show_password: bool,
    /// PCs, mit denen schon verbunden wurde (neueste zuerst).
    known: Vec<KnownPc>,
    state: ConnState,
    link: Option<Link>,
    /// Offene Warnung "Zertifikat geändert".
    cert_alert: Option<CertAlert>,
    tx: Sender<UiEvent>,
    rx: Receiver<UiEvent>,
    conn_id: u64,
    next_job: u64,
    running: Option<RunningJob>,
    last_sent: Instant,
    tab: Tab,

    // --- Ausgabe ---
    lines: Vec<LogLine>,
    show_details: bool,

    // --- Updates ---
    upgrade_items: Vec<UpgradeItem>,
    upgrades_loaded: bool,

    // --- Installieren (Suche mit Vorschlägen) ---
    search_text: String,
    search_edited_at: Instant,
    /// Für welchen Begriff die aktuellen Vorschläge gelten.
    searched_for: String,
    search_results: Vec<PackageItem>,

    // --- Deinstallieren ---
    installed: Vec<PackageItem>,
    installed_loaded: bool,
    uninstall_filter: String,
    confirm_uninstall: Option<PackageItem>,

    // --- Netzwerk-Suche ---
    scanning: bool,
    /// Läuft die aktuelle Suche automatisch (ohne Knopfdruck)?
    scan_quiet: bool,
    /// Ergebnis der letzten abgeschlossenen Suche.
    scan_results: Vec<DiscoveredPc>,
    /// Treffer der laufenden Suche (wird am Ende zu `scan_results`).
    scan_new: Vec<DiscoveredPc>,
    scan_rx: Option<Receiver<DiscoveredPc>>,
    scan_progress: Arc<AtomicUsize>,
    /// Wann die letzte Suche gestartet wurde (`None` = noch nie / neu suchen).
    last_scan: Option<Instant>,
    /// Wie viele PCs zuletzt im Ausgabe-Protokoll gemeldet wurden.
    last_logged_found: usize,
}

impl Default for RemotePanel {
    fn default() -> Self {
        let (tx, rx) = channel();
        Self {
            open: false,
            address: String::new(),
            password: String::new(),
            attempt: None,
            show_password: false,
            known: history_path().map(|p| load_known(&p)).unwrap_or_default(),
            state: ConnState::Disconnected,
            link: None,
            cert_alert: None,
            tx,
            rx,
            conn_id: 0,
            next_job: 1,
            running: None,
            last_sent: Instant::now(),
            tab: Tab::Updates,

            lines: Vec::new(),
            show_details: false,

            upgrade_items: Vec::new(),
            upgrades_loaded: false,

            search_text: String::new(),
            search_edited_at: Instant::now(),
            searched_for: String::new(),
            search_results: Vec::new(),

            installed: Vec::new(),
            installed_loaded: false,
            uninstall_filter: String::new(),
            confirm_uninstall: None,

            scanning: false,
            scan_quiet: true,
            scan_results: Vec::new(),
            scan_new: Vec::new(),
            scan_rx: None,
            scan_progress: Arc::new(AtomicUsize::new(0)),
            last_scan: None,
            last_logged_found: 0,
        }
    }
}

/// Verbindung zum Ziel-PC aus Sicht der Oberfläche: Nachrichten gehen über
/// einen Kanal an den Verbindungs-Thread (der allein die TLS-Verbindung
/// besitzt); `raw` dient nur zum sofortigen Trennen.
struct Link {
    tx: Sender<ClientMessage>,
    raw: TcpStream,
}

impl Link {
    fn close(&self) {
        let _ = self.raw.shutdown(Shutdown::Both);
    }
}

/// Fertig angemeldete Verbindung (Ergebnis von [`handshake`]).
struct Session {
    tls: tls::ClientTls,
    lines: tls::LineReader,
    raw: TcpStream,
    hostname: String,
    agent_version: String,
    admin: Option<bool>,
    fingerprint: String,
}

/// Warum der Verbindungsaufbau gescheitert ist.
enum HandshakeError {
    Failed(String),
    /// Der Ziel-PC zeigt ein anderes Zertifikat als beim letzten Mal. Es
    /// wurde NICHTS gesendet (auch kein Anmelde-Nachweis).
    CertChanged { fingerprint: String },
}

impl From<String> for HandshakeError {
    fn from(s: String) -> Self {
        HandshakeError::Failed(s)
    }
}

/// Zeitlimit für Verbindungsaufbau und Anmeldung.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Wie lange der Verbindungs-Thread höchstens auf Daten wartet, bevor er
/// nachsieht, ob etwas zu senden ist.
const IO_POLL: Duration = Duration::from_millis(40);

/// Verbindet (TLS 1.3), prüft das Zertifikat gegen den gespeicherten
/// Fingerabdruck und führt die gegenseitige Anmeldung durch. Der Code selbst
/// wird nie gesendet - nur ein an Zertifikat und Zufallswerte gebundener
/// HMAC-Nachweis; umgekehrt muss der Ziel-PC beweisen, dass er den Code kennt.
fn handshake(addr: &str, password: &str, pinned: Option<&str>) -> Result<Session, HandshakeError> {
    let sock = addr
        .to_socket_addrs()
        .map_err(|e| format!("Adresse ungültig: {e}"))?
        .next()
        .ok_or_else(|| "Adresse konnte nicht aufgelöst werden.".to_string())?;
    let stream = TcpStream::connect_timeout(&sock, Duration::from_secs(5)).map_err(|e| {
        format!(
            "Keine Verbindung zu {addr} ({e}). Ist die Abk-WingetApp auf dem Ziel-PC geöffnet \
             und Port {DEFAULT_AGENT_PORT} in dessen Firewall freigegeben?"
        )
    })?;
    let _ = stream.set_nodelay(true);
    let set = |e: io::Error| e.to_string();
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(set)?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(set)?;
    let raw = stream.try_clone().map_err(set)?;

    let (mut tls, fingerprint) = tls::connect(stream).map_err(|e| {
        format!(
            "Keine verschlüsselte Verbindung möglich ({e}). Läuft auf dem Ziel-PC noch eine \
             ältere Abk-WingetApp? Bitte dort Version 0.6.0 installieren."
        )
    })?;

    // Pinning: Zertifikat anders als beim letzten Mal -> sofort abbrechen,
    // BEVOR irgendein Anmelde-Nachweis den PC verlässt.
    if let Some(expected) = pinned {
        if !expected.eq_ignore_ascii_case(&fingerprint) {
            let _ = raw.shutdown(Shutdown::Both);
            return Err(HandshakeError::CertChanged { fingerprint });
        }
    }

    let mut lines = tls::LineReader::default();
    let client_nonce = random_nonce();
    send_raw(
        &mut tls,
        &ClientMessage::Hello {
            protocol: PROTOCOL_VERSION,
            name: own_name(),
            client_nonce: Some(hex_encode(&client_nonce)),
        },
    )
    .map_err(set)?;

    let nonce = match read_agent(&mut tls, &mut lines) {
        Ok(Some(AgentMessage::Challenge { nonce })) => match hex_decode(&nonce) {
            Some(n) if n.len() == NONCE_BYTES => n,
            _ => return Err("Ziel-PC schickte eine ungültige Nonce.".to_string().into()),
        },
        Ok(Some(AgentMessage::Error { message })) => return Err(message.into()),
        Ok(None) => {
            return Err("Ziel-PC hat die Verbindung sofort beendet (evtl. nach zu vielen \
                 Fehlversuchen für 5 Minuten gesperrt)."
                .to_string()
                .into())
        }
        Ok(_) => return Err("Unerwartete Antwort vom Ziel-PC.".to_string().into()),
        Err(e) => {
            return Err(format!(
                "Anmeldung fehlgeschlagen: {e}. Läuft auf dem Ziel-PC dieselbe Abk-WingetApp-Version?"
            )
            .into())
        }
    };

    let response = compute_auth_response(password, &client_nonce, &nonce, &fingerprint);
    send_raw(&mut tls, &ClientMessage::Auth { response }).map_err(set)?;

    match read_agent(&mut tls, &mut lines) {
        Ok(Some(AgentMessage::Hello {
            protocol,
            agent_version,
            hostname,
            admin,
            proof,
        })) => {
            if protocol != PROTOCOL_VERSION {
                return Err(format!(
                    "Ziel-PC nutzt Protokoll {protocol}, erwartet {PROTOCOL_VERSION} - bitte \
                     auf beiden PCs dieselbe Abk-WingetApp-Version verwenden."
                )
                .into());
            }
            // Gegenseitige Anmeldung: Auch der Ziel-PC muss den Code kennen.
            let expected = compute_agent_proof(password, &client_nonce, &nonce, &fingerprint);
            if !proof.as_deref().is_some_and(|p| constant_time_eq(p, &expected)) {
                let _ = raw.shutdown(Shutdown::Both);
                return Err("⚠ Der Ziel-PC konnte nicht nachweisen, dass er den Verbindungscode \
                     kennt. Verbindung aus Sicherheitsgründen abgebrochen (möglicherweise gibt \
                     sich ein anderes Gerät als dieser PC aus)."
                    .to_string()
                    .into());
            }
            Ok(Session {
                tls,
                lines,
                raw,
                hostname,
                agent_version,
                admin,
                fingerprint,
            })
        }
        Ok(Some(AgentMessage::AuthFailed { message })) if message.contains("gesperrt") => {
            Err(message.into())
        }
        Ok(Some(AgentMessage::AuthFailed { .. })) => Err(WRONG_CODE_ERROR.to_string().into()),
        Ok(Some(AgentMessage::Error { message })) => Err(message.into()),
        Ok(_) => Err("Unerwartete Antwort vom Ziel-PC.".to_string().into()),
        Err(e) => Err(format!("Anmeldung fehlgeschlagen: {e}").into()),
    }
}

/// Verbindungs-Thread: besitzt die TLS-Verbindung, schickt Nachrichten aus
/// dem Kanal ab und reicht empfangene Nachrichten an die Oberfläche weiter.
fn io_loop(
    conn: u64,
    mut tls: tls::ClientTls,
    mut lines: tls::LineReader,
    outgoing: Receiver<ClientMessage>,
    tx: Sender<UiEvent>,
) {
    // Kurzes Zeitlimit: zwischendurch nachsehen, ob etwas zu senden ist. Halb
    // gelesene Zeilen gehen dabei nicht verloren (LineReader).
    if tls.sock.set_read_timeout(Some(IO_POLL)).is_err() {
        let _ = tx.send(UiEvent::Disconnected {
            conn,
            reason: "Verbindung konnte nicht eingerichtet werden.".into(),
        });
        return;
    }
    let _ = tls.sock.set_write_timeout(Some(Duration::from_secs(30)));
    let disconnected = |reason: String| {
        let _ = tx.send(UiEvent::Disconnected { conn, reason });
    };
    loop {
        loop {
            match outgoing.try_recv() {
                Ok(msg) => {
                    if let Err(e) = write_msg(&mut tls, &msg) {
                        disconnected(format!("Senden fehlgeschlagen - Verbindung verloren ({e})."));
                        return;
                    }
                }
                Err(TryRecvError::Empty) => break,
                // Oberfläche hat getrennt.
                Err(TryRecvError::Disconnected) => {
                    tls.conn.send_close_notify();
                    let _ = tls.flush();
                    return;
                }
            }
        }
        match lines.poll_line(&mut tls, MAX_MESSAGE_BYTES) {
            Ok(tls::Polled::Line(line)) => match serde_json::from_str::<AgentMessage>(line.trim_end()) {
                Ok(msg) => {
                    if tx.send(UiEvent::Agent { conn, msg }).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    disconnected(format!("Ungültige Nachricht vom Ziel-PC: {e}"));
                    return;
                }
            },
            Ok(tls::Polled::Pending) => {}
            Ok(tls::Polled::Closed) => {
                disconnected("Der Ziel-PC hat die Verbindung beendet.".into());
                return;
            }
            Err(e) => {
                disconnected(format!("Verbindung abgebrochen: {e}"));
                return;
            }
        }
    }
}

/// Sortiert Vorschläge: Namen, die mit dem Suchbegriff beginnen, zuerst,
/// danach alphabetisch.
fn sort_suggestions(items: &mut [PackageItem], query: &str) {
    let q = query.trim().to_lowercase();
    items.sort_by(|a, b| {
        let (an, bn) = (a.name.to_lowercase(), b.name.to_lowercase());
        let (a_starts, b_starts) = (an.starts_with(&q), bn.starts_with(&q));
        b_starts.cmp(&a_starts).then(an.cmp(&bn))
    });
}

/// Ein großes, deutlich umrandetes Eingabefeld (gut sichtbar in hell und dunkel).
fn big_input(ui: &mut egui::Ui, text: &mut String, icon: &str, hint: &str, accent: Color32) -> egui::Response {
    egui::Frame::none()
        .fill(ui.visuals().extreme_bg_color)
        .stroke(egui::Stroke::new(2.0_f32, accent))
        .rounding(8.0)
        .inner_margin(egui::Margin::symmetric(10.0, 4.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(icon).size(20.0).color(accent));
                ui.add(
                    egui::TextEdit::singleline(text)
                        .hint_text(hint)
                        .font(egui::FontId::proportional(19.0))
                        .frame(false)
                        .margin(egui::vec2(4.0, 6.0))
                        .desired_width(f32::INFINITY),
                )
            })
            .inner
        })
        .inner
}

/// Gefüllter Kreis als Statuspunkt (das Zeichen "●" fehlt in der Schrift).
pub fn status_dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 4.5, color);
}

/// Farbige "Pille" mit Statuspunkt.
fn pill(ui: &mut egui::Ui, color: Color32, text: impl Into<String>) {
    egui::Frame::none()
        .fill(color.gamma_multiply(0.18))
        .stroke(egui::Stroke::new(1.0_f32, color))
        .rounding(12.0)
        .inner_margin(egui::Margin::symmetric(10.0, 3.0))
        .show(ui, |ui| {
            // Immer links->rechts, auch wenn die Pille rechtsbündig sitzt.
            ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                status_dot(ui, color);
                ui.label(RichText::new(text.into()).color(color).strong());
            });
        });
}

fn primary_button(text: impl Into<String>, fill: Color32) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.into()).strong().size(15.0).color(Color32::WHITE))
        .fill(fill)
        .min_size(egui::vec2(0.0, 32.0))
}

fn placeholder(ui: &mut egui::Ui, text: &str) {
    ui.add_space(30.0);
    ui.vertical_centered(|ui| {
        ui.label(RichText::new(text).size(16.0).weak());
    });
}

impl RemotePanel {
    // ------------------------------------------------------------------
    // Zustand
    // ------------------------------------------------------------------

    /// Name des Ziel-PCs, solange eine Verbindung besteht.
    pub fn connected_to(&self) -> Option<&str> {
        match &self.state {
            ConnState::Connected { hostname, .. } => Some(hostname),
            _ => None,
        }
    }

    /// Anzahl der zuletzt gefundenen, verbindbaren PCs im Netzwerk (für die
    /// Statusleiste).
    pub fn found_pcs(&self) -> usize {
        self.scan_results.iter().filter(|p| p.compatible).count()
    }

    fn is_connected(&self) -> bool {
        matches!(self.state, ConnState::Connected { .. })
    }

    fn hostname(&self) -> String {
        self.connected_to().unwrap_or("Ziel-PC").to_string()
    }

    fn is_busy(&self) -> bool {
        self.running.is_some()
    }

    fn log(&mut self, kind: LogKind, text: impl Into<String>) {
        self.lines.push(LogLine {
            kind,
            text: text.into(),
        });
        if self.lines.len() > MAX_LINES {
            let excess = self.lines.len() - MAX_LINES;
            self.lines.drain(..excess);
        }
    }

    // ------------------------------------------------------------------
    // Verbindung
    // ------------------------------------------------------------------

    /// Eintrag in "Bereits verbunden" zu diesem PC (gleiche MAC oder Name).
    fn known_for(&self, hostname: &str, mac: &str) -> Option<usize> {
        self.known
            .iter()
            .position(|k| is_same_pc(&k.hostname, &k.mac, hostname, mac))
    }

    /// Eintrag in "Bereits verbunden" mit dieser IP-Adresse.
    fn known_by_ip(&self, ip: &str) -> Option<usize> {
        let ip = ip.trim();
        let ip = ip.strip_suffix(&format!(":{DEFAULT_AGENT_PORT}")).unwrap_or(ip);
        self.known.iter().position(|k| k.ip == ip)
    }

    /// Gibt es für diesen PC einen Code (eingetippt oder gespeichert)?
    fn has_code(&self, known: Option<usize>) -> bool {
        !self.password.trim().is_empty()
            || known.is_some_and(|i| self.known.get(i).is_some_and(|k| k.code.is_some()))
    }

    /// Hat dieser PC einen gespeicherten Code (und ist nichts eingetippt)?
    fn uses_saved_code(&self, known: Option<usize>) -> bool {
        self.password.trim().is_empty()
            && known.is_some_and(|i| self.known.get(i).is_some_and(|k| k.code.is_some()))
    }

    /// Verbindet mit `self.address`. Ein eingetippter Code hat Vorrang (z. B.
    /// nachdem auf dem Ziel-PC "Neu erzeugen" gedrückt wurde), sonst wird der
    /// für diesen PC gespeicherte Code benutzt - ganz ohne Eingabe.
    fn connect_known(&mut self, known: Option<usize>) {
        let typed = normalize_password(&self.password);
        if !typed.is_empty() {
            self.connect(typed, None, known);
            return;
        }
        let saved = known.and_then(|i| self.known.get(i)).and_then(|k| {
            let code = open_code(k.code.as_deref()?)?;
            Some((normalize_password(&code), k.hostname.clone()))
        });
        match saved {
            Some((code, host)) => self.connect(code, Some(host), known),
            None => self.log(
                LogKind::Warning,
                "⚠ Für diesen PC ist kein Code gespeichert. Bitte oben den Verbindungscode \
                 eintragen, der auf dem Ziel-PC angezeigt wird.",
            ),
        }
    }

    fn connect(&mut self, code: String, saved_for: Option<String>, known: Option<usize>) {
        self.conn_id += 1;
        let conn = self.conn_id;
        self.state = ConnState::Connecting;
        self.cert_alert = None;
        let pinned = known
            .and_then(|i| self.known.get(i))
            .and_then(|k| k.fingerprint.clone());
        self.attempt = Some(Attempt {
            conn,
            code: code.clone(),
            saved_for: saved_for.clone(),
            known,
        });
        let addr = with_default_port(&self.address);
        // Im Feld nur die IP stehen lassen, wenn der Standard-Port gilt.
        let shown = addr
            .strip_suffix(&format!(":{DEFAULT_AGENT_PORT}"))
            .unwrap_or(&addr)
            .to_string();
        self.address = shown.clone();
        let password = code;
        match &saved_for {
            Some(host) => self.log(
                LogKind::Info,
                format!("Verbinde mit {host} ({shown}) mit dem gespeicherten Code ..."),
            ),
            None => self.log(LogKind::Info, format!("Verbinde mit {shown} ...")),
        }
        let tx = self.tx.clone();

        std::thread::spawn(move || match handshake(&addr, &password, pinned.as_deref()) {
            Ok(session) => {
                // Für die Liste "Bereits verbunden": Gegenstelle und MAC (aus
                // der ARP-Tabelle, die durch die Verbindung gerade gefüllt ist).
                let peer_ip = session.raw.peer_addr().ok().map(|a| a.ip());
                let mac = match peer_ip {
                    Some(IpAddr::V4(ip)) => mac_for_ip(ip),
                    _ => None,
                }
                .unwrap_or_else(|| NO_MAC.to_string());
                let (out_tx, out_rx) = channel();
                let Session {
                    tls,
                    lines,
                    raw,
                    hostname,
                    agent_version,
                    admin,
                    fingerprint,
                } = session;
                let _ = tx.send(UiEvent::Connected {
                    conn,
                    link: Link { tx: out_tx, raw },
                    fingerprint,
                    hostname,
                    agent_version,
                    admin,
                    peer_ip,
                    mac,
                });
                // Ab hier: Senden und Empfangen im Verbindungs-Thread.
                io_loop(conn, tls, lines, out_rx, tx);
            }
            Err(HandshakeError::CertChanged { fingerprint }) => {
                let _ = tx.send(UiEvent::CertChanged { conn, fingerprint });
            }
            Err(HandshakeError::Failed(error)) => {
                let _ = tx.send(UiEvent::ConnectFailed { conn, error });
            }
        });
    }

    fn mark_disconnected(&mut self) {
        if let Some(link) = self.link.take() {
            link.close();
        }
        self.state = ConnState::Disconnected;
        self.running = None;
        self.confirm_uninstall = None;
        // Nach dem Trennen die Liste der PCs gleich neu aufbauen.
        self.last_scan = None;
    }

    fn disconnect(&mut self) {
        if let Some(link) = self.link.take() {
            link.close();
        }
        // Spätere Ereignisse der alten Verbindung werden über die ID ignoriert.
        self.conn_id += 1;
        self.mark_disconnected();
        self.log(LogKind::Info, "Verbindung getrennt.");
    }

    // ------------------------------------------------------------------
    // Netzwerk-Suche
    // ------------------------------------------------------------------

    /// Startet die Netzwerk-Suche: Alle PCs im eigenen /24-Netz werden
    /// angeklopft; wer die App laufen hat, antwortet mit Name + Version.
    /// `quiet`: automatische Suche (nur Treffer werden protokolliert).
    fn start_scan(&mut self, quiet: bool) {
        if self.scanning {
            return;
        }
        // Auch bei Misserfolg merken, damit nicht jedes Frame neu versucht wird.
        self.last_scan = Some(Instant::now());
        let Some(base) = scan_base() else {
            if !quiet {
                self.log(
                    LogKind::Error,
                    "✖ Eigene IP-Adresse nicht gefunden - ist dieser PC mit dem Netzwerk (WLAN/LAN) verbunden?",
                );
            }
            return;
        };
        self.scan_new.clear();
        self.scanning = true;
        self.scan_quiet = quiet;
        self.scan_progress = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = channel::<DiscoveredPc>();
        self.scan_rx = Some(rx);
        if !quiet {
            self.log(
                LogKind::Info,
                format!(
                    "🔍 Suche PCs mit {} im Netzwerk {}.{}.{}.1-254 ...",
                    crate::APP_NAME,
                    base.0,
                    base.1,
                    base.2
                ),
            );
        }

        // Den eigenen PC überspringen - er ist ja kein Ziel.
        let own = local_ipv4();
        let next = Arc::new(AtomicUsize::new(1));
        let port = scan_port();
        for _ in 0..SCAN_WORKERS {
            let tx = tx.clone();
            let next = Arc::clone(&next);
            let progress = Arc::clone(&self.scan_progress);
            std::thread::spawn(move || loop {
                let host = next.fetch_add(1, Ordering::SeqCst);
                if host > SCAN_HOSTS {
                    break;
                }
                let ip = Ipv4Addr::new(base.0, base.1, base.2, host as u8);
                if Some(ip) != own {
                    if let Some(pc) = probe_host(ip, port) {
                        if tx.send(pc).is_err() {
                            break;
                        }
                    }
                }
                progress.fetch_add(1, Ordering::SeqCst);
            });
        }
        // Unser eigener Sender wird hier fallen gelassen; sind alle Worker
        // fertig, meldet der Kanal "Disconnected" -> Suche beendet.
    }

    /// Sammelt neu gefundene PCs ein und erkennt das Ende der Suche.
    fn poll_scan(&mut self) {
        let Some(rx) = self.scan_rx.take() else {
            return;
        };
        let mut finished = false;
        loop {
            match rx.try_recv() {
                Ok(pc) => self.scan_new.push(pc),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    finished = true;
                    break;
                }
            }
        }
        // Verbindbare PCs zuerst, dann nach Name sortieren.
        self.scan_new.sort_by(|a, b| {
            b.compatible
                .cmp(&a.compatible)
                .then_with(|| a.hostname.to_lowercase().cmp(&b.hostname.to_lowercase()))
        });
        if !finished {
            self.scan_rx = Some(rx);
            return;
        }

        self.scanning = false;
        self.scan_results = std::mem::take(&mut self.scan_new);
        let n = self.scan_results.len();
        if self.scan_quiet {
            // Automatische Suche: nur melden, wenn sich etwas geändert hat.
            if n != self.last_logged_found {
                if n > 0 {
                    self.log(LogKind::Info, format!("🔍 {n} PC(s) im Netzwerk gefunden."));
                }
                self.last_logged_found = n;
            }
        } else if n == 0 {
            self.log(
                LogKind::Warning,
                "⚠ Keine PCs gefunden. Läuft die Abk-WingetApp auf dem Ziel-PC und ist Port 47800 \
                 in dessen Firewall freigegeben?",
            );
            self.last_logged_found = 0;
        } else {
            self.log(LogKind::Success, format!("✔ Suche fertig: {n} PC(s) gefunden."));
            self.last_logged_found = n;
        }
    }

    /// Welche Treffer gerade angezeigt werden: Während einer Suche die neuen,
    /// sobald es welche gibt - sonst das Ergebnis der letzten Suche.
    fn shown_pcs(&self) -> &[DiscoveredPc] {
        if self.scanning && !self.scan_new.is_empty() {
            &self.scan_new
        } else {
            &self.scan_results
        }
    }

    /// Automatische Suche: einmal beim Programmstart, nach jedem Trennen und
    /// bei offenem Fenster regelmäßig - solange keine Verbindung besteht.
    fn auto_scan(&mut self, window_visible: bool) {
        if self.scanning || !matches!(self.state, ConnState::Disconnected) {
            return;
        }
        let due = match self.last_scan {
            None => true,
            Some(t) => window_visible && t.elapsed() >= SCAN_REFRESH,
        };
        if due {
            self.start_scan(true);
        }
    }

    fn send(&mut self, msg: &ClientMessage) -> bool {
        let failed = match self.link.as_ref() {
            Some(link) => link.tx.send(msg.clone()).is_err(),
            None => true,
        };
        if failed {
            self.conn_id += 1;
            self.mark_disconnected();
            self.log(LogKind::Error, "✖ Senden fehlgeschlagen - Verbindung verloren.");
            return false;
        }
        self.last_sent = Instant::now();
        true
    }

    fn start_job(&mut self, command: RemoteCommand, kind: JobKind) {
        if !self.is_connected() || self.is_busy() {
            return;
        }
        let id = self.next_job;
        self.next_job += 1;
        self.running = Some(RunningJob {
            id,
            kind,
            raw: Vec::new(),
            steps_done: 0,
        });
        self.send(&ClientMessage::Run { job: id, command });
    }

    // ------------------------------------------------------------------
    // Aufträge
    // ------------------------------------------------------------------

    fn load_upgrades(&mut self) {
        self.upgrades_loaded = true; // verhindert Mehrfach-Start
        self.log(LogKind::Info, format!("Suche Updates auf {} ...", self.hostname()));
        self.start_job(RemoteCommand::ListUpgrades, JobKind::ListUpgrades);
    }

    fn install_selected_upgrades(&mut self) {
        let items: Vec<UpgradeItem> = self
            .upgrade_items
            .iter()
            .filter(|i| i.selected)
            .cloned()
            .collect();
        if items.is_empty() {
            return;
        }
        // Eine einzige unbrauchbare Id darf nicht den ganzen Auftrag kippen
        // (der Ziel-PC lehnt sonst alles ab): solche Einträge überspringen.
        let (items, skipped): (Vec<UpgradeItem>, Vec<UpgradeItem>) =
            items.into_iter().partition(|i| is_valid_package_id(&i.id));
        for item in &skipped {
            self.log(
                LogKind::Warning,
                format!("⚠ {} übersprungen: Paket-Id {:?} ist nicht verwendbar.", item.name, item.id),
            );
        }
        if items.is_empty() {
            return;
        }
        let ids = items.iter().map(|i| i.id.clone()).collect();
        self.log(
            LogKind::Info,
            format!("⬆ Installiere {} Update(s) auf {} ...", items.len(), self.hostname()),
        );
        self.start_job(
            RemoteCommand::UpgradeIds { ids },
            JobKind::InstallUpgrades {
                items,
                ok: Vec::new(),
                failed: Vec::new(),
            },
        );
    }

    fn search(&mut self, query: String) {
        self.searched_for = query.clone();
        self.start_job(RemoteCommand::Search { query: query.clone() }, JobKind::Search { query });
    }

    fn install(&mut self, item: PackageItem) {
        self.log(
            LogKind::Info,
            format!("⬇ Installiere {} auf {} ...", item.name, self.hostname()),
        );
        self.start_job(RemoteCommand::Install { id: item.id.clone() }, JobKind::Install { item });
    }

    fn load_installed(&mut self) {
        self.installed_loaded = true;
        self.log(
            LogKind::Info,
            format!("Lade installierte Programme von {} ...", self.hostname()),
        );
        self.start_job(RemoteCommand::ListInstalled, JobKind::ListInstalled);
    }

    fn uninstall(&mut self, item: PackageItem) {
        self.log(
            LogKind::Info,
            format!("🗑 Deinstalliere {} auf {} ...", item.name, self.hostname()),
        );
        self.start_job(RemoteCommand::Uninstall { id: item.id.clone() }, JobKind::Uninstall { item });
    }

    /// Automatische Abläufe: Listen beim ersten Öffnen eines Reiters laden,
    /// Vorschläge nach dem Tippen holen, Keep-Alive.
    fn auto_actions(&mut self) {
        if !self.is_connected() {
            return;
        }
        if self.running.is_none() {
            match self.tab {
                Tab::Updates if !self.upgrades_loaded => self.load_upgrades(),
                Tab::Uninstall if !self.installed_loaded => self.load_installed(),
                Tab::Install => {
                    let q = self.search_text.trim().to_string();
                    if q.chars().count() >= MIN_SEARCH_LEN
                        && is_valid_query(&q)
                        && q != self.searched_for
                        && self.search_edited_at.elapsed() >= SEARCH_DEBOUNCE
                    {
                        self.search(q);
                    }
                }
                _ => {}
            }
        }
        // Keep-Alive: Im Leerlauf regelmäßig pingen. Während ein Auftrag
        // läuft, ist der Ziel-PC beschäftigt und liest nicht.
        if self.running.is_none() && self.last_sent.elapsed() >= KEEPALIVE_INTERVAL {
            self.send(&ClientMessage::Ping);
        }
    }

    // ------------------------------------------------------------------
    // Nachrichten vom Ziel-PC
    // ------------------------------------------------------------------

    fn poll(&mut self) {
        while let Ok(event) = self.rx.try_recv() {
            match event {
                UiEvent::Connected {
                    conn,
                    link,
                    fingerprint,
                    hostname,
                    agent_version,
                    admin,
                    peer_ip,
                    mac,
                } => {
                    if conn != self.conn_id {
                        link.close();
                        continue;
                    }
                    let attempt = self.attempt.take().filter(|a| a.conn == conn);
                    // Zweite Prüfung nach der Anmeldung: Ist der PC (laut Name/MAC)
                    // schon mit einem ANDEREN Zertifikat bekannt? Das deckt den
                    // Fall ab, dass von Hand eine neue IP eingetippt wurde.
                    if let Some(i) = self.known_for(&hostname, &mac) {
                        if let Some(old) = self.known[i].fingerprint.clone() {
                            if !old.eq_ignore_ascii_case(&fingerprint) {
                                link.close();
                                self.conn_id += 1;
                                self.mark_disconnected();
                                self.raise_cert_alert(i, fingerprint);
                                continue;
                            }
                        }
                    }
                    let code = attempt.map(|a| a.code);
                    self.remember_pc(&hostname, peer_ip, &mac, code.as_deref(), &fingerprint);
                    // Der Code ist jetzt für diesen PC gespeichert. Feld leeren,
                    // damit er nicht versehentlich für einen anderen PC gilt.
                    self.password.clear();
                    self.link = Some(link);
                    self.last_sent = Instant::now();
                    self.log(
                        LogKind::Success,
                        format!(
                            "✔ Verbunden mit {hostname} (Abk-WingetApp {agent_version}) - \
                             🔒 verschlüsselt, Zertifikat {}",
                            tls::short_fingerprint(&fingerprint)
                        ),
                    );
                    if admin == Some(false) {
                        self.log(
                            LogKind::Warning,
                            format!(
                                "⚠ Auf {hostname} läuft die App OHNE Administratorrechte. Updates wie \
                                 Visual C++ oder .NET brauchen dann dort einen Mausklick (Windows-\
                                 Abfrage) - sonst schlagen sie fehl. Abhilfe, einmalig an {hostname}: \
                                 Burgermenü ☰ -> \"🛡 Mit Adminrechten automatisch starten\". Danach \
                                 laufen Updates dort ohne jeden Klick."
                            ),
                        );
                    }
                    self.state = ConnState::Connected {
                        hostname,
                        agent_version,
                    };
                    // Frische Listen für den neuen Ziel-PC.
                    self.upgrades_loaded = false;
                    self.upgrade_items.clear();
                    self.installed_loaded = false;
                    self.installed.clear();
                    self.search_results.clear();
                    self.searched_for.clear();
                }
                UiEvent::ConnectFailed { conn, error } => {
                    if conn == self.conn_id {
                        self.state = ConnState::Disconnected;
                        let attempt = self.attempt.take().filter(|a| a.conn == conn);
                        match attempt.and_then(|a| a.saved_for) {
                            Some(host) if error == WRONG_CODE_ERROR => {
                                // Auf dem Ziel-PC wurde ein neuer Code erzeugt.
                                if let Some(k) = self
                                    .known
                                    .iter_mut()
                                    .find(|k| k.hostname.eq_ignore_ascii_case(&host))
                                {
                                    k.code = None;
                                }
                                self.persist_known();
                                self.log(
                                    LogKind::Error,
                                    format!(
                                        "✖ Der gespeicherte Code für {host} stimmt nicht mehr (dort wurde \
                                         \"Neu erzeugen\" gedrückt). Bitte den neuen Code oben eintragen \
                                         und erneut verbinden - danach ist er wieder gespeichert."
                                    ),
                                );
                            }
                            _ => self.log(LogKind::Error, format!("✖ {error}")),
                        }
                    }
                }
                UiEvent::CertChanged { conn, fingerprint } => {
                    if conn == self.conn_id {
                        self.state = ConnState::Disconnected;
                        let attempt = self.attempt.take().filter(|a| a.conn == conn);
                        if let Some(i) = attempt.and_then(|a| a.known) {
                            self.raise_cert_alert(i, fingerprint);
                        }
                    }
                }
                UiEvent::Disconnected { conn, reason } => {
                    if conn == self.conn_id {
                        self.mark_disconnected();
                        self.log(LogKind::Error, format!("✖ {reason}"));
                    }
                }
                UiEvent::Agent { conn, msg } => {
                    if conn == self.conn_id {
                        self.handle_agent_message(msg);
                    }
                }
            }
        }
    }

    fn handle_agent_message(&mut self, msg: AgentMessage) {
        // Nachrichten, die zu keinem laufenden Auftrag gehören.
        let job_id = match &msg {
            AgentMessage::Started { job, .. }
            | AgentMessage::Line { job, .. }
            | AgentMessage::StepFinished { job, .. }
            | AgentMessage::Finished { job, .. }
            | AgentMessage::Rejected { job, .. } => Some(*job),
            AgentMessage::Error { message } => {
                self.log(LogKind::Error, format!("⚠ Ziel-PC meldet: {message}"));
                self.running = None;
                return;
            }
            _ => None, // Pong, Hello, Challenge, AuthFailed
        };
        let Some(job_id) = job_id else { return };
        let Some(mut job) = self.running.take() else { return };
        if job.id != job_id {
            self.running = Some(job);
            return;
        }
        let host = self.hostname();

        match msg {
            AgentMessage::Started { display, .. } => {
                self.log(LogKind::Command, display);
                if let JobKind::InstallUpgrades { items, .. } = &job.kind {
                    if let Some(item) = items.get(job.steps_done) {
                        self.log(
                            LogKind::Info,
                            format!(
                                "→ Aktualisiere {} ({} von {}) ...",
                                item.name,
                                job.steps_done + 1,
                                items.len()
                            ),
                        );
                    }
                }
            }
            AgentMessage::Line { text, .. } => {
                if !is_progress_line(&text) {
                    if matches!(
                        job.kind,
                        JobKind::ListUpgrades | JobKind::ListInstalled | JobKind::Search { .. }
                    ) {
                        job.raw.push(text.clone());
                    }
                    if !text.trim().is_empty() {
                        self.log(LogKind::Raw, text);
                    }
                }
            }
            AgentMessage::StepFinished {
                index,
                success,
                exit_code,
                ..
            } => {
                let outcome = classify_exit(success, exit_code);
                let why = describe_exit_code(exit_code);
                match &mut job.kind {
                    JobKind::InstallUpgrades { items, ok, failed } => {
                        if let Some(item) = items.get(index) {
                            match outcome {
                                Outcome::Ok => {
                                    self.log(
                                        LogKind::Success,
                                        format!(
                                            "✔ {} aktualisiert ({} → {})",
                                            item.name, item.installed_version, item.available_version
                                        ),
                                    );
                                    ok.push(item.name.clone());
                                }
                                Outcome::OkNeedsRestart => {
                                    self.log(
                                        LogKind::Success,
                                        format!("✔ {} aktualisiert - {why}", item.name),
                                    );
                                    ok.push(format!("{} (Neustart nötig)", item.name));
                                }
                                Outcome::Failed => {
                                    self.log(
                                        LogKind::Error,
                                        format!("✖ {} wurde nicht aktualisiert - {why}", item.name),
                                    );
                                    failed.push(format!("{} ({why})", item.name));
                                }
                            }
                        }
                        job.steps_done = index.saturating_add(1);
                    }
                    JobKind::Install { item } => match outcome {
                        Outcome::Ok => self.log(
                            LogKind::Success,
                            format!("✔ {} wurde auf {host} installiert.", item.name),
                        ),
                        Outcome::OkNeedsRestart => self.log(
                            LogKind::Success,
                            format!("✔ {} wurde auf {host} installiert - {why}", item.name),
                        ),
                        Outcome::Failed => self.log(
                            LogKind::Error,
                            format!("✖ {} konnte nicht installiert werden - {why}", item.name),
                        ),
                    },
                    JobKind::Uninstall { item } => {
                        if outcome == Outcome::Failed {
                            self.log(
                                LogKind::Error,
                                format!("✖ {} konnte nicht deinstalliert werden - {why}", item.name),
                            );
                        } else {
                            self.log(
                                LogKind::Success,
                                format!("✔ {} wurde von {host} entfernt.", item.name),
                            );
                            let id = item.id.clone();
                            self.installed.retain(|i| i.id != id);
                        }
                    }
                    // Listen-Abfragen: Ergebnis kommt mit `Finished`.
                    _ => {}
                }
            }
            AgentMessage::Finished { .. } => {
                // `winget upgrade` / `search` liefern auch dann einen
                // Fehlercode, wenn es nichts zu tun gibt - deshalb zählt bei
                // Listen nur, was sich aus der Ausgabe lesen lässt.
                self.finish_job(job, &host);
                return;
            }
            AgentMessage::Rejected { reason, .. } => {
                self.log(LogKind::Error, format!("⚠ Abgelehnt: {reason}"));
                return; // Auftrag beendet
            }
            _ => {}
        }
        self.running = Some(job);
    }

    fn finish_job(&mut self, job: RunningJob, host: &str) {
        let raw = job.raw.join("\n");
        match job.kind {
            JobKind::ListUpgrades => {
                self.upgrade_items = parse_upgrade_output(&raw);
                match self.upgrade_items.len() {
                    0 => self.log(LogKind::Success, format!("✔ {host} ist aktuell - keine Updates verfügbar.")),
                    n => self.log(LogKind::Info, format!("{n} Update(s) auf {host} verfügbar.")),
                }
            }
            JobKind::InstallUpgrades { items, ok, failed } => {
                if failed.is_empty() {
                    self.log(
                        LogKind::Success,
                        format!(
                            "━━ Fertig: {} von {} Update(s) installiert: {}",
                            ok.len(),
                            items.len(),
                            ok.join(", ")
                        ),
                    );
                } else {
                    let mut text = format!("━━ Fertig: {} von {} Update(s) installiert", ok.len(), items.len());
                    if !ok.is_empty() {
                        text.push_str(&format!(" ({})", ok.join(", ")));
                    }
                    text.push_str(&format!(". Nicht aktualisiert: {}", failed.join("; ")));
                    self.log(LogKind::Warning, text);
                }
                // Liste neu laden, damit erledigte Updates verschwinden.
                self.upgrades_loaded = false;
            }
            JobKind::Search { query } => {
                let mut items = parse_package_table(&raw);
                sort_suggestions(&mut items, &query);
                self.search_results = items;
            }
            JobKind::Install { .. } => {}
            JobKind::ListInstalled => {
                self.installed = parse_package_table(&raw);
                self.log(
                    LogKind::Info,
                    format!("{} installierte Programme auf {host} geladen.", self.installed.len()),
                );
            }
            JobKind::Uninstall { .. } => {}
        }
    }

    // ------------------------------------------------------------------
    // Oberfläche
    // ------------------------------------------------------------------

    /// Pro Frame aufrufen (auch bei geschlossenem Fenster, damit
    /// Verbindungsereignisse nicht liegen bleiben).
    /// `visible = false`: nur Ereignisse verarbeiten, Fenster nicht zeigen
    /// (z. B. solange dieser PC selbst ferngesteuert wird).
    pub fn show(&mut self, ctx: &egui::Context, accent: Color32, visible: bool) {
        self.poll();
        self.poll_scan();
        self.auto_actions();
        self.auto_scan(self.open && visible);

        if self.scanning {
            ctx.request_repaint_after(Duration::from_millis(120));
        }
        if !matches!(self.state, ConnState::Disconnected) {
            ctx.request_repaint_after(Duration::from_millis(100));
        } else if self.open && visible {
            // Damit die automatische Neu-Suche auch ohne Mausbewegung anläuft.
            ctx.request_repaint_after(Duration::from_secs(2));
        }
        if !self.open || !visible {
            return;
        }

        let screen = ctx.screen_rect();
        let mut open = self.open;
        egui::Window::new(RichText::new("📡 Remote-Steuerung").strong().size(17.0))
            .id(egui::Id::new("remote_window"))
            .open(&mut open)
            .default_size([
                (screen.width() * 0.88).max(760.0),
                (screen.height() * 0.86).max(540.0),
            ])
            .min_size([720.0, 500.0])
            .default_pos(screen.center() - egui::vec2(screen.width() * 0.44, screen.height() * 0.43))
            .resizable(true)
            .collapsible(false)
            .show(ctx, |ui| self.ui(ui, accent));
        self.open = open;

        self.confirm_uninstall_window(ctx);
    }

    fn ui(&mut self, ui: &mut egui::Ui, accent: Color32) {
        self.connection_bar(ui, accent);
        ui.add_space(8.0);

        // Reiter
        ui.horizontal(|ui| {
            for (tab, label) in [
                (Tab::Updates, "⬆  Updates auswählen"),
                (Tab::Install, "⬇  Paket installieren"),
                (Tab::Uninstall, "🗑  Paket deinstallieren"),
            ] {
                let selected = self.tab == tab;
                let text = RichText::new(label).size(15.0).strong();
                let btn = if selected {
                    egui::Button::new(text.color(Color32::WHITE)).fill(accent)
                } else {
                    egui::Button::new(text)
                };
                if ui.add(btn.min_size(egui::vec2(190.0, 34.0))).clicked() {
                    self.tab = tab;
                }
            }
        });
        ui.add_space(4.0);
        ui.separator();

        // Platz aufteilen: Reiter-Inhalt oben, Ausgabe unten.
        let total = ui.available_height();
        let output_h = (total * 0.34).clamp(130.0, 320.0);
        let content_h = (total - output_h - 44.0).max(160.0);
        ui.allocate_ui_with_layout(
            egui::vec2(ui.available_width(), content_h),
            egui::Layout::top_down(egui::Align::Min),
            |ui| {
                ui.set_min_height(content_h);
                if !self.is_connected() {
                    self.discovery_panel(ui, accent, content_h - 70.0);
                    return;
                }
                let list_h = content_h - 110.0;
                match self.tab {
                    Tab::Updates => self.updates_tab(ui, list_h),
                    Tab::Install => self.install_tab(ui, accent, list_h),
                    Tab::Uninstall => self.uninstall_tab(ui, accent, list_h),
                }
            },
        );
        ui.separator();
        self.output_panel(ui, output_h);
    }

    /// Zeigt die Warnung "Zertifikat geändert" für einen bekannten PC.
    fn raise_cert_alert(&mut self, known: usize, new: String) {
        let Some(k) = self.known.get(known) else { return };
        let old = k.fingerprint.clone().unwrap_or_default();
        let hostname = k.hostname.clone();
        self.log(
            LogKind::Error,
            format!(
                "⚠ Zertifikat geändert: {hostname} meldet sich mit einem ANDEREN Zertifikat als \
                 bisher (neu: {}, bisher: {}). Es wurde kein Anmelde-Nachweis gesendet.",
                tls::short_fingerprint(&new),
                tls::short_fingerprint(&old)
            ),
        );
        self.cert_alert = Some(CertAlert {
            known,
            hostname,
            old,
            new,
        });
    }

    /// Merkt sich einen PC nach erfolgreicher Verbindung und speichert die Liste.
    fn remember_pc(
        &mut self,
        hostname: &str,
        ip: Option<IpAddr>,
        mac: &str,
        code: Option<&str>,
        fingerprint: &str,
    ) {
        let ip = ip.map(|i| i.to_string()).unwrap_or_else(|| NO_MAC.to_string());
        upsert_known(&mut self.known, hostname, &ip, mac, now_secs());
        if let Some(i) = self.known_for(hostname, mac) {
            if self.known[i].fingerprint.is_none() {
                self.log(
                    LogKind::Info,
                    format!(
                        "🔒 Zertifikat von {hostname} gespeichert ({}). Ab jetzt wird bei jeder \
                         Verbindung geprüft, dass es derselbe PC ist.",
                        tls::short_fingerprint(fingerprint)
                    ),
                );
            }
            self.known[i].fingerprint = Some(fingerprint.to_ascii_lowercase());
        }
        if let Some(code) = code {
            match seal_code(code) {
                Some(sealed) => {
                    if let Some(i) = self.known_for(hostname, mac) {
                        self.known[i].code = Some(sealed);
                    }
                }
                None => self.log(
                    LogKind::Warning,
                    "⚠ Der Code konnte nicht gespeichert werden - beim nächsten Mal bitte erneut eingeben.",
                ),
            }
        }
        self.persist_known();
    }

    fn persist_known(&mut self) {
        if let Some(path) = history_path() {
            if let Err(e) = save_known(&path, &self.known) {
                self.log(
                    LogKind::Warning,
                    format!("⚠ Die Liste \"Bereits verbunden\" konnte nicht gespeichert werden: {e}"),
                );
            }
        }
    }

    /// Zeigt ein gefundener PC ein anderes Zertifikat als gespeichert?
    /// Liefert dann (Eintrag in "Bereits verbunden", neuer Fingerabdruck).
    fn changed_cert(&self, pc: &DiscoveredPc) -> Option<(usize, String)> {
        let i = self.known_for(&pc.hostname, &pc.mac)?;
        let old = self.known[i].fingerprint.as_deref()?;
        let new = pc.fingerprint.as_deref()?;
        (!old.eq_ignore_ascii_case(new)).then(|| (i, new.to_string()))
    }

    /// Warnung "Zertifikat geändert" mit der Möglichkeit, dem neuen
    /// Zertifikat bewusst zu vertrauen.
    fn cert_alert_box(&mut self, ui: &mut egui::Ui) {
        let Some(alert) = &self.cert_alert else { return };
        let mut trust = false;
        let mut dismiss = false;
        egui::Frame::none()
            .fill(Color32::from_rgba_unmultiplied(205, 65, 65, 40))
            .stroke(egui::Stroke::new(1.5_f32, RED))
            .rounding(10.0)
            .inner_margin(egui::Margin::same(12.0))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(
                    RichText::new(format!("⚠  Zertifikat von {} hat sich geändert", alert.hostname))
                        .strong()
                        .size(16.0)
                        .color(RED),
                );
                ui.label(
                    "Normal, wenn die App dort neu installiert oder das Windows-Profil gewechselt wurde - \
                     sonst gibt sich womöglich ein anderes Gerät als dieser PC aus. Es wurde nichts gesendet.",
                );
                ui.horizontal(|ui| {
                    ui.label("Bisher:");
                    ui.label(RichText::new(tls::short_fingerprint(&alert.old)).monospace());
                    ui.add_space(16.0);
                    ui.label("Jetzt:");
                    ui.label(RichText::new(tls::short_fingerprint(&alert.new)).monospace().strong());
                });
                ui.horizontal(|ui| {
                    if ui
                        .add(primary_button("✔ Zertifikat neu vertrauen", AMBER))
                        .on_hover_text(
                            "Den neuen Fingerabdruck für diesen PC speichern. Nur tun, wenn \"Jetzt\" mit \
                             der Anzeige auf dem Ziel-PC übereinstimmt (Hauptfenster, Bereich \
                             \"Verbindungscode\", Zeile \"Zertifikat\").",
                        )
                        .clicked()
                    {
                        trust = true;
                    }
                    if ui.button("Abbrechen").clicked() {
                        dismiss = true;
                    }
                    ui.label(
                        RichText::new("Nur vertrauen, wenn \"Jetzt\" mit der Anzeige am Ziel-PC übereinstimmt.")
                            .weak()
                            .small(),
                    );
                });
            });
        ui.add_space(8.0);

        if trust {
            if let Some(alert) = self.cert_alert.take() {
                if let Some(k) = self.known.get_mut(alert.known) {
                    k.fingerprint = Some(alert.new.to_ascii_lowercase());
                    let host = k.hostname.clone();
                    self.persist_known();
                    self.log(
                        LogKind::Warning,
                        format!(
                            "🔒 Neues Zertifikat für {host} gespeichert ({}). Jetzt erneut verbinden.",
                            tls::short_fingerprint(&alert.new)
                        ),
                    );
                }
            }
        } else if dismiss {
            self.cert_alert = None;
        }
    }

    /// Liste der im Netzwerk gefundenen PCs mit "Verbinden"-Knopf, darunter
    /// die Liste der PCs, mit denen schon einmal verbunden wurde.
    fn discovery_panel(&mut self, ui: &mut egui::Ui, accent: Color32, list_h: f32) {
        let is_disconnected = matches!(self.state, ConnState::Disconnected);
        let scanning = self.scanning;
        let has_known = !self.known.is_empty();
        // Platz für die Zertifikats-Warnung abziehen.
        let list_h = if self.cert_alert.is_some() {
            (list_h - 140.0).max(120.0)
        } else {
            list_h
        };
        // Platz aufteilen: oben gefundene PCs, unten der Verlauf.
        let found_h = if has_known {
            (list_h * 0.5).max(90.0)
        } else {
            list_h.max(80.0)
        };
        let known_h = (list_h - found_h - 40.0).max(70.0);
        // Ziel eines Klicks auf "Verbinden" (IP-Adresse + Eintrag in "Bereits
        // verbunden", falls vorhanden) bzw. "Entfernen" (Index).
        let mut connect_target: Option<(String, Option<usize>)> = None;
        let mut forget: Option<usize> = None;
        // Klick auf "⚠ Zertifikat geändert" in der Liste: (Eintrag, neuer Fingerabdruck)
        let mut show_alert: Option<(usize, String)> = None;

        self.cert_alert_box(ui);

        ui.horizontal(|ui| {
            ui.label(RichText::new("🖧  PCs im Netzwerk").strong().size(17.0));
            ui.add_space(8.0);
            if ui
                .add_enabled(!scanning && is_disconnected, egui::Button::new("🔄 Neu suchen"))
                .on_hover_text(
                    "Durchsucht das eigene Netzwerk nach PCs, auf denen diese App läuft.",
                )
                .clicked()
            {
                self.start_scan(false);
            }
            if scanning {
                ui.spinner();
                ui.label(
                    RichText::new(format!(
                        "Suche läuft ... {}/{}",
                        self.scan_progress.load(Ordering::SeqCst),
                        SCAN_HOSTS
                    ))
                    .weak(),
                );
            }
        });
        ui.add_space(4.0);

        if self.shown_pcs().is_empty() {
            if scanning {
                placeholder(ui, "Suche nach PCs mit der Abk-WingetApp im Netzwerk ...");
            } else {
                placeholder(
                    ui,
                    "Keine PCs gefunden. Die Abk-WingetApp muss auf dem Ziel-PC geöffnet sein \
                     (Port 47800 in der Firewall frei). Alternativ oben die IP-Adresse eintragen.",
                );
            }
        } else {
            egui::ScrollArea::vertical()
                .id_source("scan_results")
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .max_height(found_h)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    egui::Grid::new("scan_grid")
                        .num_columns(5)
                        .striped(true)
                        .spacing([18.0, 8.0])
                        .show(ui, |ui| {
                            ui.label(RichText::new("Gerätename").strong());
                            ui.label(RichText::new("IPv4-Adresse").strong());
                            ui.label(RichText::new("MAC-Adresse").strong());
                            ui.label(RichText::new("Version").strong());
                            ui.label("");
                            ui.end_row();
                            for pc in self.shown_pcs() {
                                ui.label(RichText::new(&pc.hostname).strong());
                                ui.label(RichText::new(pc.ip.to_string()).monospace());
                                ui.label(RichText::new(&pc.mac).monospace());
                                ui.label(if pc.version.is_empty() {
                                    "?".to_string()
                                } else {
                                    pc.version.clone()
                                });
                                if !pc.compatible {
                                    ui.label(RichText::new("andere App-Version").weak().italics());
                                } else if pc.busy {
                                    ui.label(
                                        RichText::new("wird ferngesteuert").color(AMBER).italics(),
                                    );
                                } else if let Some((i, new_fp)) = self.changed_cert(pc) {
                                    if ui
                                        .add(primary_button("⚠ Zertifikat geändert", RED))
                                        .on_hover_text(
                                            "Dieser PC zeigt ein anderes Zertifikat als bei der letzten \
                                             Verbindung. Klicken für Details.",
                                        )
                                        .clicked()
                                    {
                                        show_alert = Some((i, new_fp));
                                    }
                                } else {
                                    let known = self.known_for(&pc.hostname, &pc.mac);
                                    let saved = self.uses_saved_code(known);
                                    let (label, hint) = if saved {
                                        (
                                            "🔑 Direkt verbinden",
                                            "Code ist gespeichert - verbindet ohne Eingabe.",
                                        )
                                    } else {
                                        ("🔌 Verbinden", "Mit diesem PC verbinden (Code siehe oben).")
                                    };
                                    if ui
                                        .add_enabled(
                                            is_disconnected && self.has_code(known),
                                            primary_button(label, accent),
                                        )
                                        .on_hover_text(hint)
                                        .on_disabled_hover_text(
                                            "Bitte oben einmalig den Verbindungscode des Ziel-PCs \
                                             eintragen - danach merkt sich die App ihn.",
                                        )
                                        .clicked()
                                    {
                                        connect_target = Some((pc.ip.to_string(), known));
                                    }
                                }
                                ui.end_row();
                            }
                        });
                });
        }

        // ---- Bereits verbunden ----
        if has_known {
            ui.add_space(8.0);
            ui.separator();
            ui.label(RichText::new("🕘  Bereits verbunden").strong().size(17.0));
            ui.add_space(4.0);
            // Welche der bekannten PCs sind gerade im Netzwerk zu sehen (und unter
            // welcher IP - die kann sich seit dem letzten Mal geändert haben)?
            let online: Vec<Option<String>> = self
                .known
                .iter()
                .map(|k| {
                    self.scan_results
                        .iter()
                        .find(|p| p.compatible && is_same_pc(&k.hostname, &k.mac, &p.hostname, &p.mac))
                        .map(|p| p.ip.to_string())
                })
                .collect();
            let now = now_secs();
            egui::ScrollArea::vertical()
                .id_source("known_pcs")
                .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
                .max_height(known_h)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    egui::Grid::new("known_grid")
                        .num_columns(9)
                        .striped(true)
                        .spacing([18.0, 8.0])
                        .show(ui, |ui| {
                            ui.label(RichText::new("Status").strong());
                            ui.label(RichText::new("Gerätename").strong());
                            ui.label(RichText::new("IPv4-Adresse").strong());
                            ui.label(RichText::new("MAC-Adresse").strong());
                            ui.label(RichText::new("Zuletzt verbunden").strong());
                            ui.label(RichText::new("Code").strong());
                            ui.label(RichText::new("Zertifikat").strong());
                            ui.label("");
                            ui.label("");
                            ui.end_row();
                            for (i, k) in self.known.iter().enumerate() {
                                let live_ip = online[i].clone();
                                let shown_ip = live_ip.clone().unwrap_or_else(|| k.ip.clone());
                                ui.horizontal(|ui| {
                                    let (color, text) = if live_ip.is_some() {
                                        (GREEN, "online")
                                    } else {
                                        (Color32::GRAY, "offline")
                                    };
                                    status_dot(ui, color);
                                    ui.label(RichText::new(text).color(color));
                                });
                                ui.label(RichText::new(&k.hostname).strong());
                                ui.label(RichText::new(&shown_ip).monospace());
                                ui.label(RichText::new(&k.mac).monospace());
                                ui.label(
                                    RichText::new(format_ago(now.saturating_sub(k.last_connected)))
                                        .weak(),
                                );
                                if k.code.is_some() {
                                    ui.label(RichText::new("🔑 gespeichert").color(GREEN))
                                        .on_hover_text(
                                            "Der Code dieses PCs ist verschlüsselt gespeichert - \
                                             Verbinden geht ohne Eingabe.",
                                        );
                                } else {
                                    ui.label(RichText::new("–").weak()).on_hover_text(
                                        "Kein Code gespeichert. Nach der nächsten Verbindung mit \
                                         eingetipptem Code wird er gespeichert.",
                                    );
                                }
                                match &k.fingerprint {
                                    Some(fp) => {
                                        ui.label(
                                            RichText::new(format!("🔒 {}", tls::short_fingerprint(fp)))
                                                .monospace()
                                                .color(GREEN),
                                        )
                                        .on_hover_text(format!(
                                            "Gespeicherter Fingerabdruck des Zertifikats:\n{}\n\
                                             Muss mit der Anzeige auf dem Ziel-PC übereinstimmen.",
                                            fp.to_uppercase()
                                        ));
                                    }
                                    None => {
                                        ui.label(RichText::new("–").weak()).on_hover_text(
                                            "Noch nicht verschlüsselt verbunden - wird bei der \
                                             nächsten Verbindung gespeichert.",
                                        );
                                    }
                                }
                                let saved = self.uses_saved_code(Some(i));
                                let label = if saved { "🔑 Direkt verbinden" } else { "🔌 Verbinden" };
                                if ui
                                    .add_enabled(
                                        is_disconnected && shown_ip != NO_MAC && self.has_code(Some(i)),
                                        primary_button(label, accent),
                                    )
                                    .on_hover_text(if saved {
                                        "Mit dem gespeicherten Code verbinden - keine Eingabe nötig."
                                    } else {
                                        "Erneut mit diesem PC verbinden (Code siehe oben)."
                                    })
                                    .on_disabled_hover_text(
                                        "Bitte oben den aktuellen Verbindungscode des Ziel-PCs eintragen.",
                                    )
                                    .clicked()
                                {
                                    connect_target = Some((shown_ip.clone(), Some(i)));
                                }
                                if ui
                                    .small_button("🗑")
                                    .on_hover_text("Aus der Liste entfernen (auch der gespeicherte Code wird gelöscht)")
                                    .clicked()
                                {
                                    forget = Some(i);
                                }
                                ui.end_row();
                            }
                        });
                });
        }

        if let Some((i, new_fp)) = show_alert {
            self.raise_cert_alert(i, new_fp);
        }
        if let Some(i) = forget {
            if i < self.known.len() {
                self.known.remove(i);
                // Indizes haben sich verschoben.
                self.cert_alert = None;
                self.persist_known();
            }
        }
        if let Some((addr, known)) = connect_target {
            self.address = addr;
            self.connect_known(known);
        }
    }

    fn connection_bar(&mut self, ui: &mut egui::Ui, accent: Color32) {
        let is_disconnected = matches!(self.state, ConnState::Disconnected);
        let is_connecting = matches!(self.state, ConnState::Connecting);
        egui::Frame::none()
            .fill(ui.visuals().faint_bg_color)
            .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
            .rounding(10.0)
            .inner_margin(egui::Margin::symmetric(14.0, 10.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Ziel-PC").strong());
                    let addr = ui.add_enabled(
                        is_disconnected,
                        egui::TextEdit::singleline(&mut self.address)
                            .hint_text("IP-Adresse, z. B. 192.168.4.123")
                            .font(egui::FontId::proportional(16.0))
                            .desired_width(200.0),
                    );
                    ui.add_space(10.0);
                    ui.label(RichText::new("Code").strong());
                    let pw = ui.add_enabled(
                        is_disconnected,
                        egui::TextEdit::singleline(&mut self.password)
                            .password(!self.show_password)
                            .hint_text("nur beim 1. Mal nötig")
                            .font(egui::FontId::proportional(16.0))
                            .desired_width(190.0),
                    );
                    ui.add_enabled_ui(is_disconnected, |ui| {
                        ui.toggle_value(&mut self.show_password, "👁")
                            .on_hover_text("Code anzeigen");
                    });
                    ui.add_space(10.0);

                    let enter = (addr.lost_focus() || pw.lost_focus())
                        && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if is_disconnected {
                        let known = self.known_by_ip(&self.address);
                        let can_connect = !self.address.trim().is_empty() && self.has_code(known);
                        if ui
                            .add_enabled(can_connect, primary_button("🔌 Verbinden", accent))
                            .clicked()
                            || (enter && can_connect)
                        {
                            self.connect_known(known);
                        }
                    } else if is_connecting {
                        ui.spinner();
                    } else if ui.add(primary_button("✖ Trennen", RED)).clicked() {
                        self.disconnect();
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        match &self.state {
                            ConnState::Disconnected => pill(ui, Color32::GRAY, "Nicht verbunden"),
                            ConnState::Connecting => pill(ui, AMBER, "Verbinde ..."),
                            ConnState::Connected {
                                hostname,
                                agent_version,
                            } => {
                                let hint = format!("Abk-WingetApp {agent_version} auf dem Ziel-PC");
                                ui.scope(|ui| pill(ui, GREEN, format!("Verbunden mit {hostname}")))
                                    .response
                                    .on_hover_text(hint);
                            }
                        }
                    });
                });
            });
    }

    fn updates_tab(&mut self, ui: &mut egui::Ui, list_h: f32) {
        let host = self.hostname();
        let busy = self.is_busy();

        // Fortschritt laufender Update-Aufträge
        if let Some(job) = &self.running {
            match &job.kind {
                JobKind::ListUpgrades => {
                    ui.add_space(20.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(RichText::new(format!("Updates werden auf {host} ermittelt ...")).size(16.0));
                    });
                    return;
                }
                JobKind::InstallUpgrades { items, .. } => {
                    let done = job.steps_done.min(items.len());
                    let current = items
                        .get(done)
                        .map(|i| i.name.as_str())
                        .unwrap_or("abschließen");
                    ui.add_space(20.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(
                            RichText::new(format!(
                                "Installiere Update {} von {}: {current}",
                                (done + 1).min(items.len()),
                                items.len()
                            ))
                            .size(16.0),
                        );
                    });
                    ui.add_space(8.0);
                    ui.add(
                        egui::ProgressBar::new(done as f32 / items.len().max(1) as f32)
                            .show_percentage()
                            .animate(true),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("Was erledigt ist, steht unten in der Ausgabe.").weak(),
                    );
                    return;
                }
                _ => {}
            }
        }

        let count = self.upgrade_items.len();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("🔄 Neu suchen"))
                .clicked()
            {
                self.upgrades_loaded = false;
            }
            if count > 0 {
                ui.label(RichText::new(format!("{count} Update(s) verfügbar")).strong());
                ui.add_space(12.0);
                if ui.button("Alle auswählen").clicked() {
                    self.upgrade_items.iter_mut().for_each(|i| i.selected = true);
                }
                if ui.button("Keine auswählen").clicked() {
                    self.upgrade_items.iter_mut().for_each(|i| i.selected = false);
                }
            }
        });
        ui.add_space(4.0);

        if count == 0 {
            if self.upgrades_loaded {
                ui.add_space(24.0);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("✅ Alles aktuell").size(22.0).strong().color(GREEN));
                    ui.label(RichText::new(format!("Auf {host} sind keine Updates verfügbar.")).weak());
                });
            }
            return;
        }

        egui::ScrollArea::vertical()
            .id_source("remote_upgrades")
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
            .max_height(list_h.max(80.0))
            .auto_shrink([false, true])
            .show(ui, |ui| {
                egui::Grid::new("remote_upgrade_grid")
                    .num_columns(5)
                    .striped(true)
                    .spacing([18.0, 8.0])
                    .show(ui, |ui| {
                        // Kästchen über der Liste: alle an-/abhaken.
                        crate::select_all_checkbox(ui, &mut self.upgrade_items);
                        ui.label(RichText::new("Programm").strong());
                        ui.label(RichText::new("Paket-ID").strong());
                        ui.label(RichText::new("Installiert").strong());
                        ui.label(RichText::new("Neu").strong());
                        ui.end_row();
                        for item in &mut self.upgrade_items {
                            ui.checkbox(&mut item.selected, "");
                            ui.label(RichText::new(&item.name).strong());
                            ui.label(RichText::new(&item.id).weak());
                            ui.label(&item.installed_version);
                            ui.label(RichText::new(&item.available_version).color(GREEN).strong());
                            ui.end_row();
                        }
                    });
            });

        ui.add_space(8.0);
        let selected = self.upgrade_items.iter().filter(|i| i.selected).count();
        let label = match selected {
            0 => "Programme zum Aktualisieren anhaken".to_string(),
            1 => "⬆  1 Update auf dem Ziel-PC installieren".to_string(),
            n => format!("⬆  {n} Updates auf dem Ziel-PC installieren"),
        };
        if ui
            .add_enabled(selected > 0 && !busy, primary_button(label, GREEN).min_size(egui::vec2(320.0, 38.0)))
            .clicked()
        {
            self.install_selected_upgrades();
        }
    }

    fn install_tab(&mut self, ui: &mut egui::Ui, accent: Color32, list_h: f32) {
        let host = self.hostname();
        let resp = big_input(
            ui,
            &mut self.search_text,
            "🔍",
            "Programm suchen, z. B. Firefox, 7-Zip, VLC ...",
            accent,
        );
        if resp.changed() {
            self.search_edited_at = Instant::now();
        }
        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            // Sofort suchen statt auf die Tipp-Pause zu warten.
            self.search_edited_at = Instant::now() - SEARCH_DEBOUNCE;
        }

        let q = self.search_text.trim().to_string();
        ui.add_space(4.0);
        ui.horizontal(|ui| match &self.running {
            Some(RunningJob {
                kind: JobKind::Search { query },
                ..
            }) => {
                ui.spinner();
                ui.label(format!("Suche „{query}“ auf {host} ..."));
            }
            Some(RunningJob {
                kind: JobKind::Install { item },
                ..
            }) => {
                ui.spinner();
                ui.label(RichText::new(format!("{} wird auf {host} installiert ...", item.name)).strong());
            }
            _ if q.chars().count() < MIN_SEARCH_LEN => {
                ui.label(
                    RichText::new(format!(
                        "Mindestens {MIN_SEARCH_LEN} Zeichen eingeben - die Vorschläge kommen direkt von {host}."
                    ))
                    .weak(),
                );
            }
            _ if !is_valid_query(&q) => {
                ui.label(RichText::new("Ungültiger Suchbegriff.").color(RED));
            }
            _ if q != self.searched_for => {
                ui.label(RichText::new("Vorschläge werden gleich geladen ...").weak());
            }
            _ if self.search_results.is_empty() => {
                ui.label(RichText::new(format!("Keine Pakete zu „{q}“ gefunden.")).weak());
            }
            _ => {
                ui.label(
                    RichText::new(format!("{} Vorschläge für „{q}“", self.search_results.len())).strong(),
                );
            }
        });
        ui.add_space(4.0);

        if self.search_results.is_empty() || q.chars().count() < MIN_SEARCH_LEN {
            return;
        }
        let busy = self.is_busy();
        let mut to_install = None;
        egui::ScrollArea::vertical()
            .id_source("remote_search")
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
            .max_height(list_h.max(80.0))
            .auto_shrink([false, true])
            .show(ui, |ui| {
                egui::Grid::new("remote_search_grid")
                    .num_columns(5)
                    .striped(true)
                    .spacing([18.0, 8.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("Programm").strong());
                        ui.label(RichText::new("Paket-ID").strong());
                        ui.label(RichText::new("Version").strong());
                        ui.label(RichText::new("Quelle").strong());
                        ui.label("");
                        ui.end_row();
                        for item in &self.search_results {
                            ui.label(RichText::new(&item.name).strong());
                            ui.label(RichText::new(&item.id).weak());
                            ui.label(&item.version);
                            ui.label(&item.source);
                            let valid = is_valid_package_id(&item.id);
                            let btn = ui
                                .add_enabled(!busy && valid, primary_button("⬇ Installieren", accent))
                                .on_disabled_hover_text(if valid {
                                    "Bitte warten, bis der laufende Vorgang fertig ist."
                                } else {
                                    "Diese Paket-ID ist abgeschnitten oder ungültig."
                                });
                            if btn.clicked() {
                                to_install = Some(item.clone());
                            }
                            ui.end_row();
                        }
                    });
            });
        if let Some(item) = to_install {
            self.install(item);
        }
    }

    fn uninstall_tab(&mut self, ui: &mut egui::Ui, accent: Color32, list_h: f32) {
        let host = self.hostname();
        big_input(
            ui,
            &mut self.uninstall_filter,
            "🔍",
            "Installierte Programme filtern ...",
            accent,
        );
        ui.add_space(4.0);
        let busy = self.is_busy();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!busy, egui::Button::new("🔄 Liste neu laden"))
                .clicked()
            {
                self.installed_loaded = false;
            }
            match &self.running {
                Some(RunningJob {
                    kind: JobKind::ListInstalled,
                    ..
                }) => {
                    ui.spinner();
                    ui.label(format!("Lade installierte Programme von {host} ..."));
                }
                Some(RunningJob {
                    kind: JobKind::Uninstall { item },
                    ..
                }) => {
                    ui.spinner();
                    ui.label(RichText::new(format!("{} wird deinstalliert ...", item.name)).strong());
                }
                _ => {
                    ui.label(format!("{} Programme auf {host} installiert", self.installed.len()));
                }
            }
        });
        ui.add_space(4.0);

        let filter = self.uninstall_filter.trim().to_lowercase();
        let mut to_remove = None;
        egui::ScrollArea::vertical()
            .id_source("remote_installed")
            .scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysVisible)
            .max_height(list_h.max(80.0))
            .auto_shrink([false, true])
            .show(ui, |ui| {
                egui::Grid::new("remote_installed_grid")
                    .num_columns(4)
                    .striped(true)
                    .spacing([18.0, 8.0])
                    .show(ui, |ui| {
                        ui.label(RichText::new("Programm").strong());
                        ui.label(RichText::new("Paket-ID").strong());
                        ui.label(RichText::new("Version").strong());
                        ui.label("");
                        ui.end_row();
                        for item in self.installed.iter().filter(|i| {
                            filter.is_empty()
                                || i.name.to_lowercase().contains(&filter)
                                || i.id.to_lowercase().contains(&filter)
                        }) {
                            ui.label(RichText::new(&item.name).strong());
                            ui.label(RichText::new(&item.id).weak());
                            ui.label(&item.version);
                            let valid = is_valid_package_id(&item.id);
                            let btn = ui
                                .add_enabled(!busy && valid, primary_button("🗑 Deinstallieren", RED))
                                .on_disabled_hover_text(if valid {
                                    "Bitte warten, bis der laufende Vorgang fertig ist."
                                } else {
                                    "Dieses Programm ist nicht über winget verwaltet und kann \
                                     nur in den Windows-Einstellungen entfernt werden."
                                });
                            if btn.clicked() {
                                to_remove = Some(item.clone());
                            }
                            ui.end_row();
                        }
                    });
            });
        if to_remove.is_some() {
            self.confirm_uninstall = to_remove;
        }
    }

    fn confirm_uninstall_window(&mut self, ctx: &egui::Context) {
        let Some(item) = self.confirm_uninstall.clone() else {
            return;
        };
        let host = self.hostname();
        let mut decision = None;
        egui::Window::new("Programm deinstallieren?")
            .id(egui::Id::new("remote_confirm_uninstall"))
            .min_width(420.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(
                    RichText::new(format!("{} wirklich von {host} entfernen?", item.name))
                        .size(16.0)
                        .strong(),
                );
                ui.label(RichText::new(format!("Paket-ID: {}", item.id)).weak());
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(primary_button("🗑 Ja, deinstallieren", RED)).clicked() {
                        decision = Some(true);
                    }
                    if ui.add(egui::Button::new("Abbrechen").min_size(egui::vec2(0.0, 32.0))).clicked() {
                        decision = Some(false);
                    }
                });
            });
        match decision {
            Some(true) => {
                self.confirm_uninstall = None;
                self.uninstall(item);
            }
            Some(false) => self.confirm_uninstall = None,
            None => {}
        }
    }

    fn output_panel(&mut self, ui: &mut egui::Ui, height: f32) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Ausgabe").strong().size(15.0));
            ui.add_space(12.0);
            ui.checkbox(&mut self.show_details, "winget-Details anzeigen");
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Leeren").clicked() {
                    self.lines.clear();
                }
            });
        });
        let show_details = self.show_details;
        egui::Frame::none()
            .fill(TERM_BG)
            .rounding(8.0)
            .inner_margin(egui::Margin::same(10.0))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_source("remote_output")
                    .max_height(height)
                    .auto_shrink([false, false])
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        for line in self
                            .lines
                            .iter()
                            .filter(|l| show_details || !l.kind.is_detail())
                        {
                            ui.label(
                                RichText::new(&line.text)
                                    .monospace()
                                    .color(line.kind.color()),
                            );
                        }
                    });
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    /// Wie sich ein Test-Ziel-PC verhält.
    #[derive(Clone, Copy)]
    enum Fake {
        /// Kennt den Code und antwortet korrekt (inkl. Pong auf Ping).
        Honest,
        /// Gibt sich als Ziel-PC aus, kennt den Code aber nicht.
        Impostor,
        /// Beantwortet die Netzwerk-Suche.
        Discover,
    }

    /// Startet einen minimalen Ziel-PC (TLS + Protokoll 4) für genau eine
    /// Verbindung. Liefert Adresse, Fingerabdruck und am Ende die Liste der
    /// empfangenen Nachrichtentypen.
    fn fake_agent(
        code: &'static str,
        mode: Fake,
    ) -> (SocketAddr, String, std::thread::JoinHandle<Vec<String>>) {
        let identity = tls::AgentIdentity::generate().unwrap();
        let fp = identity.fingerprint.clone();
        let config = identity.server_config().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let own_fp = fp.clone();
        let handle = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let (tcp, _) = listener.accept().unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let Ok(tls) = tls::accept(tcp, config) else {
                return seen;
            };
            let mut conn = BufReader::new(tls);
            let Ok(Some(ClientMessage::Hello { client_nonce, .. })) = read_msg(&mut conn) else {
                return seen;
            };
            seen.push("hello".to_string());
            let cn = hex_decode(&client_nonce.unwrap()).unwrap();
            let nonce = random_nonce();
            write_msg(conn.get_mut(), &AgentMessage::Challenge { nonce: hex_encode(&nonce) }).unwrap();
            match read_msg::<_, ClientMessage>(&mut conn) {
                Ok(Some(ClientMessage::Discover)) => {
                    seen.push("discover".into());
                    if matches!(mode, Fake::Discover) {
                        write_msg(
                            conn.get_mut(),
                            &AgentMessage::DiscoverReply {
                                agent_version: "0.6.0".into(),
                                hostname: "TEST-PC".into(),
                                busy: false,
                            },
                        )
                        .unwrap();
                    }
                    return seen;
                }
                Ok(Some(ClientMessage::Auth { .. })) => seen.push("auth".into()),
                _ => return seen,
            }
            let proof_code = match mode {
                Fake::Impostor => "GERATEN-FALSCH",
                _ => code,
            };
            write_msg(
                conn.get_mut(),
                &AgentMessage::Hello {
                    protocol: PROTOCOL_VERSION,
                    agent_version: "0.6.0".into(),
                    hostname: "TEST-PC".into(),
                    admin: Some(true),
                    proof: Some(compute_agent_proof(proof_code, &cn, &nonce, &own_fp)),
                },
            )
            .unwrap();
            while let Ok(Some(msg)) = read_msg::<_, ClientMessage>(&mut conn) {
                if let ClientMessage::Ping = msg {
                    seen.push("ping".into());
                    let _ = write_msg(conn.get_mut(), &AgentMessage::Pong);
                }
            }
            seen
        });
        (addr, fp, handle)
    }

    #[test]
    fn handshake_checks_agent_proof_and_runs_io_loop() {
        // Echter Ziel-PC: Anmeldung klappt, Ping/Pong läuft über den Verbindungs-Thread.
        let (addr, fp, agent) = fake_agent("CODE-1234-5678", Fake::Honest);
        let session = match handshake(&addr.to_string(), "CODE-1234-5678", Some(&fp)) {
            Ok(s) => s,
            Err(HandshakeError::Failed(e)) => panic!("{e}"),
            Err(HandshakeError::CertChanged { .. }) => panic!("Zertifikat passt doch"),
        };
        assert_eq!(session.fingerprint, fp);
        assert_eq!(session.hostname, "TEST-PC");
        let (out_tx, out_rx) = channel();
        let (ui_tx, ui_rx) = channel();
        let raw = session.raw.try_clone().unwrap();
        let io = std::thread::spawn(move || io_loop(1, session.tls, session.lines, out_rx, ui_tx));
        out_tx.send(ClientMessage::Ping).unwrap();
        match ui_rx.recv_timeout(Duration::from_secs(5)).unwrap() {
            UiEvent::Agent { msg: AgentMessage::Pong, .. } => {}
            _ => panic!("Pong erwartet"),
        }
        drop(out_tx); // Oberfläche trennt
        io.join().unwrap();
        let _ = raw.shutdown(Shutdown::Both);
        assert_eq!(agent.join().unwrap(), vec!["hello", "auth", "ping"]);

        // Falscher Ziel-PC, der den Code nicht kennt: Abbruch trotz TLS.
        let (addr, _, agent) = fake_agent("CODE-1234-5678", Fake::Impostor);
        match handshake(&addr.to_string(), "CODE-1234-5678", None) {
            Err(HandshakeError::Failed(e)) => assert!(e.contains("nachweisen"), "{e}"),
            _ => panic!("Betrüger darf nicht akzeptiert werden"),
        }
        drop(agent);
    }

    /// Gemerkter Fingerabdruck passt nicht: Abbruch, BEVOR irgendetwas
    /// (auch kein Hello und kein Anmelde-Nachweis) gesendet wurde.
    #[test]
    fn changed_certificate_stops_before_sending() {
        let (addr, real_fp, agent) = fake_agent("CODE", Fake::Honest);
        let pinned = "00".repeat(32);
        match handshake(&addr.to_string(), "CODE", Some(&pinned)) {
            Err(HandshakeError::CertChanged { fingerprint }) => assert_eq!(fingerprint, real_fp),
            _ => panic!("Zertifikatswechsel muss erkannt werden"),
        }
        assert!(agent.join().unwrap().is_empty(), "nichts darf gesendet worden sein");
    }

    #[test]
    fn discovery_runs_over_tls_and_detects_old_versions() {
        let (addr, fp, agent) = fake_agent("CODE", Fake::Discover);
        let pc = probe_host(Ipv4Addr::LOCALHOST, addr.port()).expect("PC gefunden");
        assert!(pc.compatible);
        assert_eq!(pc.hostname, "TEST-PC");
        assert_eq!(pc.fingerprint.as_deref(), Some(fp.as_str()));
        assert_eq!(agent.join().unwrap(), vec!["hello", "discover"]);

        // Alte App (unverschlüsselt): antwortet auf Klartext mit einer
        // Challenge; die TLS-Anfrage davor scheitert.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let Ok(stream) = stream else { continue };
                let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut writer = stream;
                if let Ok(Some(_)) = read_msg::<_, serde_json::Value>(&mut reader) {
                    let _ = write_msg(&mut writer, &AgentMessage::Challenge { nonce: "00".into() });
                } else {
                    // TLS-Anfrage einer neuen Version: alte App schickt Fehler im Klartext.
                    let _ = write_msg(&mut writer, &AgentMessage::Error { message: "?".into() });
                }
            }
        });
        let old = probe_host(Ipv4Addr::LOCALHOST, port).expect("alte Version gefunden");
        assert!(!old.compatible);
        assert_eq!(old.hostname, "(ältere App-Version)");
        assert!(old.fingerprint.is_none());
    }

    #[test]
    fn changed_cert_is_flagged_in_discovery_list() {
        let mut panel = RemotePanel {
            known: vec![KnownPc {
                hostname: "BUERO-PC".into(),
                ip: "192.168.4.123".into(),
                mac: "AA:BB:CC:11:22:33".into(),
                last_connected: 0,
                code: None,
                fingerprint: Some("ab".repeat(32)),
            }],
            ..RemotePanel::default()
        };
        let mut pc = DiscoveredPc {
            ip: Ipv4Addr::new(192, 168, 4, 123),
            hostname: "BUERO-PC".into(),
            mac: "AA:BB:CC:11:22:33".into(),
            version: "0.6.0".into(),
            compatible: true,
            busy: false,
            fingerprint: Some("AB".repeat(32)),
        };
        assert!(panel.changed_cert(&pc).is_none(), "gleich (Groß/klein egal)");
        pc.fingerprint = Some("cd".repeat(32));
        assert_eq!(panel.changed_cert(&pc), Some((0, "cd".repeat(32))));

        // Fingerabdruck wird beim Verbinden gemerkt; Warnung + "neu vertrauen".
        panel.raise_cert_alert(0, "cd".repeat(32));
        assert!(panel.cert_alert.is_some());
        panel.known[0].fingerprint = None;
        panel.remember_pc("BUERO-PC", None, "AA:BB:CC:11:22:33", None, &"EF".repeat(32));
        assert_eq!(panel.known[0].fingerprint.as_deref(), Some("ef".repeat(32).as_str()));
    }

    #[test]
    fn legacy_known_codes_are_resealed() {
        let legacy = hex_encode(&protect_with_legacy_for_tests(b"AAAA-BBBB-CCCC-DDDD"));
        let mut list = vec![KnownPc {
            hostname: "PC".into(),
            ip: "1.2.3.4".into(),
            mac: NO_MAC.into(),
            last_connected: 0,
            code: Some(legacy.clone()),
            fingerprint: None,
        }];
        assert!(upgrade_sealed_codes(&mut list));
        let now = list[0].code.clone().unwrap();
        assert_ne!(now, legacy);
        assert_eq!(open_code_ext(&now), Some(("AAAA-BBBB-CCCC-DDDD".into(), false)));
        assert!(!upgrade_sealed_codes(&mut list), "zweites Mal nichts mehr zu tun");
    }

    #[test]
    fn mac_parsing_windows_and_linux() {
        assert_eq!(
            parse_mac("  192.168.4.123   aa-bb-cc-11-22-33  dynamisch").as_deref(),
            Some("AA:BB:CC:11:22:33")
        );
        assert_eq!(
            parse_mac("192.168.4.123 dev eth0 lladdr de:ad:be:ef:00:01 REACHABLE").as_deref(),
            Some("DE:AD:BE:EF:00:01")
        );
        assert_eq!(parse_mac("keine mac hier"), None);
        assert_eq!(parse_mac("x 00-00-00-00-00-00 y"), None);
    }

    #[test]
    fn ago_text_is_readable() {
        assert_eq!(format_ago(5), "gerade eben");
        assert_eq!(format_ago(120), "vor 2 Min.");
        assert_eq!(format_ago(7200), "vor 2 Std.");
        assert_eq!(format_ago(86400), "vor 1 Tag");
        assert_eq!(format_ago(3 * 86400 + 5), "vor 3 Tagen");
    }

    #[test]
    fn known_pcs_are_updated_not_duplicated() {
        let mut list = Vec::new();
        upsert_known(&mut list, "BUERO-PC", "192.168.4.10", "AA:BB:CC:00:11:22", 100);
        upsert_known(&mut list, "LAPTOP", "192.168.4.20", NO_MAC, 200);
        assert_eq!(list[0].hostname, "LAPTOP"); // neuester zuerst

        // Gleiche MAC, neue IP + neuer Name: derselbe PC.
        upsert_known(&mut list, "Buero-PC-neu", "192.168.4.99", "aa:bb:cc:00:11:22", 300);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].hostname, "Buero-PC-neu");
        assert_eq!(list[0].ip, "192.168.4.99");

        // Gleicher Name ohne bekannte MAC: MAC bleibt erhalten.
        upsert_known(&mut list, "buero-pc-neu", "192.168.4.5", NO_MAC, 400);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].mac, "AA:BB:CC:00:11:22");
        assert_eq!(list[0].last_connected, 400);
    }

    #[test]
    fn known_pcs_survive_save_and_load() {
        let dir = std::env::temp_dir().join(format!("winget-known-{}", std::process::id()));
        let path = dir.join("sub").join("bekannte-pcs.json");
        assert!(load_known(&path).is_empty()); // Datei fehlt
        let mut list = Vec::new();
        upsert_known(&mut list, "PC1", "10.0.0.2", "AA:BB:CC:DD:EE:FF", 42);
        save_known(&path, &list).unwrap();
        assert_eq!(load_known(&path), list);
        std::fs::write(&path, "kaputt").unwrap();
        assert!(load_known(&path).is_empty()); // kaputte Datei
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn suggestions_prefer_prefix_matches() {
        let mk = |n: &str| PackageItem {
            name: n.into(),
            ..Default::default()
        };
        let mut items = vec![mk("Waterfox"), mk("Firefox Nightly"), mk("Mozilla Firefox"), mk("Firefox")];
        sort_suggestions(&mut items, "fire");
        let names: Vec<_> = items.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["Firefox", "Firefox Nightly", "Mozilla Firefox", "Waterfox"]);
    }
}
