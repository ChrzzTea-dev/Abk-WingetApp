//! Agent: läuft auf dem Ziel-PC und führt die vom Haupt-PC geschickten,
//! whitelisteten winget-Befehle aus.
//!
//! Der Agent startet automatisch im Hintergrund, sobald die WingetApp
//! geöffnet wird ([`start_background`]) - man muss auf dem Ziel-PC also nur
//! die App starten. Für einen Betrieb ohne Oberfläche gibt es weiterhin
//! `winget-app --agent` ([`run_agent_cli`]).
//!
//! Sicherheit (ab 0.6.0):
//! - Die gesamte Verbindung ist mit TLS 1.3 verschlüsselt (eigenes Zertifikat
//!   pro Ziel-PC, privater Schlüssel per DPAPI geschützt, siehe `tls.rs`).
//! - Jede Verbindung muss per Challenge-Response (HMAC-SHA256) den Code
//!   nachweisen, bevor irgendein Befehl läuft. Der Nachweis ist an das
//!   TLS-Zertifikat gebunden (Channel Binding), und der Ziel-PC beweist
//!   umgekehrt, dass auch er den Code kennt (gegenseitige Anmeldung).
//! - Fehlversuche werden pro IP gezählt (5 -> 5 Minuten Sperre) und
//!   zusätzlich insgesamt (30 in 10 Minuten -> 5 Minuten Sperre für alle).
//! - Es kann immer nur EIN Haupt-PC gleichzeitig verbunden sein.
//!
//! Netzwerk-Suche: Auf `Discover` antwortet der Agent auch OHNE Passwort - aber
//! nur mit Rechnername, Version und Belegt-Status (ebenfalls verschlüsselt).
//! Steuern kann ihn nur, wer den Code kennt.

use crate::protocol::*;
use crate::tls;
use std::collections::{HashMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Nach so vielen Fehlversuchen einer IP wird sie für [`LOCKOUT_DURATION`]
/// gesperrt, statt weitere Versuche überhaupt erst zu prüfen.
const MAX_AUTH_FAILURES: u32 = 5;
const LOCKOUT_DURATION: Duration = Duration::from_secs(5 * 60);
/// Künstliche Verzögerung nach jedem Fehlversuch, damit Durchprobieren
/// langsam bleibt, selbst innerhalb des erlaubten Kontingents.
const AUTH_FAIL_DELAY: Duration = Duration::from_millis(800);
/// Globale Sperre: So viele Fehlversuche (egal von welchen IPs) innerhalb von
/// [`GLOBAL_FAILURE_WINDOW`] sperren die Anmeldung für ALLE für
/// [`GLOBAL_LOCKOUT_DURATION`]. Schützt davor, dass ein Angreifer die
/// IP-Sperre umgeht, indem er ständig die Absender-Adresse wechselt.
const GLOBAL_MAX_FAILURES: usize = 30;
const GLOBAL_FAILURE_WINDOW: Duration = Duration::from_secs(10 * 60);
const GLOBAL_LOCKOUT_DURATION: Duration = Duration::from_secs(5 * 60);
/// Zeitlimit beim Senden (hängt der Haupt-PC, wird die Sitzung beendet).
const WRITE_TIMEOUT: Duration = Duration::from_secs(60);
/// Höchstens so viele Verbindungen dürfen gleichzeitig in der Anmeldung
/// stecken (schützt vor massenhaft offenen, stummen Verbindungen).
const MAX_PENDING_HANDSHAKES: usize = 8;
pub const DEFAULT_AGENT_BIND_ADDR: &str = "0.0.0.0:47800";
/// Zeitlimit für den Handshake (Hello + Passwort).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Kommt so lange gar nichts vom Haupt-PC (auch kein Ping), gilt die
/// Verbindung als tot und der Agent wird für neue Verbindungen frei. Der
/// Haupt-PC schickt im Leerlauf alle 20 s einen Ping.
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// Wie oft die Annahme-Schleife prüft, ob der Agent beendet werden soll.
const ACCEPT_POLL: Duration = Duration::from_millis(150);

/// Version des Agents (entspricht der App-Version).
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Ereignisse, die der Agent an die Oberfläche (oder die Konsole) meldet.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// Agent lauscht und ist bereit.
    Listening {
        addr: SocketAddr,
        lan_ip: Option<IpAddr>,
        /// Das gültige Passwort bzw. der Verbindungscode dieses PCs (zur
        /// Anzeige auf dem Ziel-PC).
        password: String,
        /// `true` = zufällig erzeugter Code, `false` = aus der Umgebungsvariable.
        generated: bool,
        /// Läuft die App mit Administratorrechten? Ohne sie brauchen viele
        /// Updates eine UAC-Bestätigung direkt am Ziel-PC.
        admin: bool,
        /// Fingerabdruck des TLS-Zertifikats (zum Vergleichen mit der Anzeige
        /// auf dem Haupt-PC).
        fingerprint: String,
    },
    /// Ein Haupt-PC hat sich erfolgreich angemeldet.
    Connected { peer: SocketAddr, controller: String },
    /// Die Verbindung zum Haupt-PC ist beendet.
    Disconnected { peer: SocketAddr, reason: String },
    /// Falsches Passwort.
    AuthFailed { peer: SocketAddr },
    /// Verbindung abgelehnt (gesperrt oder schon ein anderer Haupt-PC verbunden).
    Refused { peer: SocketAddr, reason: String },
    /// Ein Auftrag startet (`description` z. B. "Git.Git INSTALLIEREN").
    JobStarted { description: String },
    /// Ein kompletter Auftrag ist fertig.
    JobFinished { success: bool },
    /// Agent wurde beendet (Fernzugriff ausgeschaltet).
    Stopped,
}

/// Wohin die Ereignisse gehen (GUI-Kanal oder Konsolen-Ausgabe).
pub type Notify = Arc<dyn Fn(AgentEvent) + Send + Sync>;

/// Zählt Authentifizierungs-Fehlversuche pro IP-Adresse und insgesamt.
#[derive(Default)]
struct AuthGuard {
    failures: HashMap<IpAddr, (u32, Instant)>,
    /// Zeitpunkte aller Fehlversuche der letzten [`GLOBAL_FAILURE_WINDOW`].
    recent: VecDeque<Instant>,
    /// Globale Sperre aktiv bis zu diesem Zeitpunkt.
    global_until: Option<Instant>,
}

impl AuthGuard {
    /// Ist die Anmeldung gerade für ALLE gesperrt?
    fn global_locked(&mut self) -> bool {
        match self.global_until {
            Some(until) if Instant::now() < until => true,
            Some(_) => {
                self.global_until = None;
                self.recent.clear();
                false
            }
            None => false,
        }
    }

    fn is_locked(&mut self, ip: IpAddr) -> bool {
        match self.failures.get(&ip) { 
            Some((count, since)) if *count >= MAX_AUTH_FAILURES => {
                if since.elapsed() < LOCKOUT_DURATION {
                    true
                } else {
                    self.failures.remove(&ip);
                    false
                }
            }
            _ => false,
        }
    }

    fn record_failure(&mut self, ip: IpAddr) {
        let now = Instant::now();
        let entry = self.failures.entry(ip).or_insert((0, now));
        entry.0 += 1;
        entry.1 = now;

        while self
            .recent
            .front()
            .is_some_and(|t| now.duration_since(*t) > GLOBAL_FAILURE_WINDOW)
        {
            self.recent.pop_front();
        }
        self.recent.push_back(now);
        if self.recent.len() >= GLOBAL_MAX_FAILURES {
            self.global_until = Some(now + GLOBAL_LOCKOUT_DURATION);
        }
        // Speicher begrenzen: abgelaufene IP-Einträge entfernen.
        if self.failures.len() > 1024 {
            self.failures
                .retain(|_, (_, since)| since.elapsed() < LOCKOUT_DURATION);
        }
    }

    fn record_success(&mut self, ip: IpAddr) {
        self.failures.remove(&ip);
    }
}

/// Gemeinsamer Zustand aller Verbindungs-Threads eines Agents.
struct Shared {
    /// Bereits mit [`normalize_password`] vereinheitlicht. Hinter einem Mutex,
    /// damit der Code im Betrieb neu erzeugt werden kann.
    password: Mutex<String>,
    guard: Mutex<AuthGuard>,
    /// Die aktive Sitzung (Kopie des Sockets, damit sie beim Ausschalten
    /// sofort getrennt werden kann). `Some` = ein Haupt-PC ist verbunden.
    session: Mutex<Option<TcpStream>>,
    /// TLS-Konfiguration mit dem Zertifikat dieses PCs.
    tls: Arc<rustls::ServerConfig>,
    /// Fingerabdruck dieses Zertifikats (geht in die Anmeldung ein).
    fingerprint: String,
    pending: AtomicUsize,
    stop: AtomicBool,
    notify: Notify,
}

/// Griff auf einen im Hintergrund laufenden Agent. Beim Fallenlassen
/// (`drop`) wird der Agent beendet.
pub struct AgentHandle {
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
}

impl AgentHandle {
    /// Erzeugt einen neuen Verbindungscode, speichert ihn dauerhaft und gibt
    /// ihn zurück. Ab sofort gilt nur noch der neue Code (auch nach einem
    /// Neustart); eine bereits laufende Sitzung bleibt bestehen. Haupt-PCs,
    /// die sich den alten Code gemerkt haben, müssen den neuen einmal eingeben.
    pub fn new_password(&self) -> String {
        let code = generate_password();
        if let Some(path) = own_code_path() {
            if let Err(e) = save_own_code(&path, &code) {
                eprintln!("Neuer Verbindungscode konnte nicht gespeichert werden: {e}");
            }
        }
        *self.shared.password.lock().unwrap() = normalize_password(&code);
        code
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(stream) = self.shared.session.lock().unwrap().as_ref() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

impl Drop for AgentHandle {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Programmname von winget. Über die Umgebungsvariable `WINGET_PROGRAM`
/// lässt sich das für Tests ersetzen (z. B. durch `echo`).
fn winget_program() -> String {
    std::env::var("WINGET_PROGRAM").unwrap_or_else(|_| "winget".to_string())
}

/// Passwort aus [`PASSWORD_ENV_VAR`], sonst der dauerhafte Verbindungscode
/// dieses PCs. Zweiter Wert: `true` = Verbindungscode (nicht Umgebungsvariable).
/// Ein selbst gewähltes Passwort unter [`MIN_CUSTOM_PASSWORD_CHARS`] Zeichen
/// wird abgelehnt - der Agent startet dann nicht.
pub fn agent_password() -> io::Result<(String, bool)> {
    match std::env::var(PASSWORD_ENV_VAR) {
        Ok(p) if !p.trim().is_empty() => {
            check_custom_password(&p).map_err(io::Error::other)?;
            Ok((p, false))
        }
        _ => Ok((persistent_code(own_code_path().as_deref()), true)),
    }
}

/// Der Verbindungscode bleibt über Neustarts gleich: Er wird beim ersten Start
/// einmal erzeugt und verschlüsselt gespeichert. Nur "Neu erzeugen" ändert ihn.
fn persistent_code(path: Option<&std::path::Path>) -> String {
    if let Some(code) = path.and_then(load_own_code) {
        return code;
    }
    let code = generate_password();
    if let Some(path) = path {
        if let Err(e) = save_own_code(path, &code) {
            eprintln!("Verbindungscode konnte nicht gespeichert werden: {e}");
        }
    }
    code
}

/// Ermittelt die IPv4-Adresse, unter der dieser PC im lokalen Netzwerk
/// erreichbar ist. Trick: Ein UDP-Socket wird zu einer externen Adresse
/// "verbunden" (dabei wird kein einziges Paket gesendet) - das Betriebs-
/// system wählt dafür die passende Netzwerkkarte, deren Adresse wir dann
/// auslesen. Kommt ohne zusätzliche Bibliothek aus.
pub fn lan_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let ip = socket.local_addr().ok()?.ip();
    if ip.is_unspecified() || ip.is_loopback() {
        None
    } else {
        Some(ip)
    }
}

/// Startet den Agent im Hintergrund (wird von der App beim Start aufgerufen).
/// `Err` z. B. wenn der Port schon belegt ist (zweite App-Instanz).
pub fn start_background(addr: &str, notify: Notify) -> io::Result<AgentHandle> {
    start_background_with(addr, notify, tls::identity_dir().as_deref())
}

/// Wie [`start_background`], mit frei wählbarem Ordner für das Zertifikat
/// (`None` = flüchtiges Zertifikat, für Tests).
fn start_background_with(
    addr: &str,
    notify: Notify,
    identity_dir: Option<&std::path::Path>,
) -> io::Result<AgentHandle> {
    let sock: SocketAddr = addr.parse().map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("Ungültige Adresse: {addr}"))
    })?;
    let (password, generated) = agent_password()?;
    let identity = tls::AgentIdentity::load_or_create(identity_dir)?;
    let tls_config = identity.server_config()?;
    let listener = TcpListener::bind(sock)?;
    let shared = Arc::new(Shared {
        password: Mutex::new(normalize_password(&password)),
        guard: Mutex::new(AuthGuard::default()),
        session: Mutex::new(None),
        tls: tls_config,
        fingerprint: identity.fingerprint.clone(),
        pending: AtomicUsize::new(0),
        stop: AtomicBool::new(false),
        notify,
    });
    (shared.notify)(AgentEvent::Listening {
        addr: listener.local_addr().unwrap_or(sock),
        lan_ip: lan_ip(),
        password,
        generated,
        admin: is_elevated(),
        fingerprint: identity.fingerprint,
    });
    let thread_shared = Arc::clone(&shared);
    let thread = std::thread::Builder::new()
        .name("winget-agent".into())
        .spawn(move || serve(listener, thread_shared))?;
    Ok(AgentHandle {
        shared,
        thread: Some(thread),
    })
}

/// Einstiegspunkt für `--agent [adresse]` (Betrieb ohne Oberfläche). Das
/// Passwort wird bewusst nicht als Kommandozeilen-Argument angenommen
/// (würde in der Prozessliste auftauchen), sondern aus [`PASSWORD_ENV_VAR`].
pub fn run_agent_cli(addr: Option<&str>) -> io::Result<()> {
    let addr = addr.unwrap_or(DEFAULT_AGENT_BIND_ADDR);
    let notify: Notify = Arc::new(print_event);
    let mut handle = start_background(addr, notify)?;
    println!("(Strg+C oder Fenster schließen zum Beenden)");
    // Läuft, bis der Prozess beendet wird.
    if let Some(t) = handle.thread.take() {
        let _ = t.join();
    }
    Ok(())
}

/// Konsolen-Ausgabe der Ereignisse im `--agent`-Modus.
fn print_event(event: AgentEvent) {
    match event {
        AgentEvent::Listening {
            addr,
            lan_ip,
            password,
            generated,
            admin,
            fingerprint,
        } => {
            println!("Abk-WingetApp-Agent {AGENT_VERSION} läuft auf {addr} (TLS 1.3).");
            println!(
                "🔒 Zertifikat dieses PCs: {}",
                tls::short_fingerprint(&fingerprint)
            );
            if !admin {
                println!(
                    "⚠ Ohne Administratorrechte gestartet: Updates wie Visual C++ oder .NET \
                     brauchen dann eine UAC-Bestätigung hier am PC. Besser: Rechtsklick -> \
                     \"Als Administrator ausführen\"."
                );
            }
            if generated {
                println!("🔑 Verbindungscode dieses PCs: {password}");
            } else {
                println!("🔑 Es gilt das Passwort aus {PASSWORD_ENV_VAR}.");
            }
            match lan_ip {
                Some(ip) => println!(
                    "➜ Auf dem Haupt-PC im Remote-Fenster eintragen: {ip}"
                ),
                None => println!("➜ Eigene IP mit `ipconfig` nachsehen (IPv4-Adresse)."),
            }
        }
        AgentEvent::Connected { peer, controller } => {
            println!("● Verbunden: {controller} ({}) steuert diesen PC.", peer.ip())
        }
        AgentEvent::Disconnected { peer, reason } => {
            println!("○ Getrennt von {}: {reason}", peer.ip())
        }
        AgentEvent::AuthFailed { peer } => {
            println!("✘ Falsches Passwort von {}.", peer.ip())
        }
        AgentEvent::Refused { peer, reason } => {
            println!("✘ Verbindung von {} abgelehnt: {reason}", peer.ip())
        }
        AgentEvent::JobStarted { description } => println!("  → {description}"),
        AgentEvent::JobFinished { success } => {
            println!("  {}", if success { "✔ fertig" } else { "✘ mit Fehler beendet" })
        }
        AgentEvent::Stopped => println!("Agent beendet."),
    }
}

/// Nimmt Verbindungen an, bis der Agent gestoppt wird. Jede Verbindung
/// läuft in einem eigenen Thread, damit ein zweiter Haupt-PC sofort eine
/// klare Absage bekommt, statt ewig zu warten.
fn serve(listener: TcpListener, shared: Arc<Shared>) {
    if let Err(e) = listener.set_nonblocking(true) {
        eprintln!("Agent: nonblocking nicht möglich: {e}");
    }
    while !shared.stop.load(Ordering::SeqCst) {
        let (stream, peer) = match listener.accept() {
            Ok(x) => x,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
            Err(e) => {
                eprintln!("Fehler beim Annehmen einer Verbindung: {e}");
                std::thread::sleep(ACCEPT_POLL);
                continue;
            }
        };
        let _ = stream.set_nonblocking(false);
        if shared.guard.lock().unwrap().is_locked(peer.ip()) {
            (shared.notify)(AgentEvent::Refused {
                peer,
                reason: "zu viele Fehlversuche, vorübergehend gesperrt".into(),
            });
            continue; // Socket wird geschlossen
        }
        if shared.pending.fetch_add(1, Ordering::SeqCst) >= MAX_PENDING_HANDSHAKES {
            shared.pending.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let conn_shared = Arc::clone(&shared);
        let spawned = std::thread::Builder::new()
            .name(format!("agent-{peer}"))
            .spawn(move || {
                if let Err(e) = handle_connection(stream, peer, &conn_shared) {
                    eprintln!("Verbindung zu {peer} beendet: {e}");
                }
            });
        if spawned.is_err() {
            shared.pending.fetch_sub(1, Ordering::SeqCst);
        }
    }
    (shared.notify)(AgentEvent::Stopped);
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock)
}

/// Gibt den "Anmeldung läuft"-Platz genau einmal wieder frei.
struct PendingSlot<'a> {
    counter: &'a AtomicUsize,
    released: bool,
}

impl PendingSlot<'_> {
    fn release(&mut self) {
        if !self.released {
            self.released = true;
            self.counter.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for PendingSlot<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

/// Lesender Teil der verschlüsselten Verbindung; geschrieben wird über
/// `get_mut()` (eine TLS-Verbindung lässt sich nicht in zwei Hälften teilen).
type Conn = BufReader<tls::ServerTls>;

/// Hinweis an Haupt-PCs mit einer älteren App-Version.
const OLD_CLIENT_MESSAGE: &str = "Dieser Ziel-PC verwendet Abk-WingetApp 0.6.0 mit \
    verschlüsselter Verbindung. Bitte auch auf dem Haupt-PC Version 0.6.0 (oder neuer) installieren.";

/// Ältere Versionen (bis 0.5.x) sprechen unverschlüsselt und beginnen mit
/// `{`. Sie bekommen - einmalig, ohne jede Steuerungsmöglichkeit - einen
/// verständlichen Hinweis statt eines unlesbaren TLS-Fehlers.
fn answer_old_client(stream: TcpStream) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let _ = read_msg::<_, serde_json::Value>(&mut reader);
    write_msg(
        &mut writer,
        &AgentMessage::Error {
            message: OLD_CLIENT_MESSAGE.into(),
        },
    )?;
    let _ = writer.shutdown(Shutdown::Both);
    Ok(())
}

fn handle_connection(stream: TcpStream, peer: SocketAddr, shared: &Shared) -> io::Result<()> {
    let mut slot = PendingSlot {
        counter: &shared.pending,
        released: false,
    };
    // Handshake mit Zeitlimit, damit eine stumme Verbindung nichts blockiert.
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;

    let mut first = [0u8; 1];
    if stream.peek(&mut first)? == 0 {
        return Ok(());
    }
    if first[0] == b'{' {
        return answer_old_client(stream);
    }

    let raw = stream.try_clone()?; // zum sofortigen Trennen beim Ausschalten
    let mut conn: Conn = BufReader::new(tls::accept(stream, Arc::clone(&shared.tls))?);

    let (controller_name, client_nonce) = match read_msg::<_, ClientMessage>(&mut conn)? {
        Some(ClientMessage::Hello {
            protocol,
            name,
            client_nonce,
        }) if protocol == PROTOCOL_VERSION => {
            match client_nonce.as_deref().and_then(hex_decode) {
                Some(n) if n.len() == NONCE_BYTES => (name, n),
                _ => {
                    send(&mut conn, &AgentMessage::Error {
                        message: "Ungültige Anmeldung (Zufallswert fehlt).".into(),
                    })?;
                    return Ok(());
                }
            }
        }
        Some(ClientMessage::Hello { protocol, .. }) => {
            send(
                &mut conn,
                &AgentMessage::Error {
                    message: format!(
                        "Versionen passen nicht zusammen (Haupt-PC: Protokoll {protocol}, \
                         Ziel-PC: {PROTOCOL_VERSION}). Bitte auf beiden PCs dieselbe \
                         Abk-WingetApp-Version verwenden."
                    ),
                },
            )?;
            return Ok(());
        }
        _ => {
            send(
                &mut conn,
                &AgentMessage::Error {
                    message: "Erwartet wurde eine Hello-Nachricht.".into(),
                },
            )?;
            return Ok(());
        }
    };

    // Passwort-Nachweis: Nonce schicken, HMAC-Antwort prüfen. Das Passwort
    // selbst wird dabei nie übertragen.
    let nonce = random_nonce();
    send(
        &mut conn,
        &AgentMessage::Challenge {
            nonce: hex_encode(&nonce),
        },
    )?;
    let password = shared.password.lock().unwrap().clone();
    let authenticated = match read_msg::<_, ClientMessage>(&mut conn)? {
        Some(ClientMessage::Auth { response }) => {
            if shared.guard.lock().unwrap().global_locked() {
                // Während der globalen Sperre wird gar nicht erst geprüft -
                // Raten ist in dieser Zeit wertlos.
                std::thread::sleep(AUTH_FAIL_DELAY);
                let reason = "Zu viele Fehlversuche - die Anmeldung ist für einige Minuten gesperrt.";
                send(&mut conn, &AgentMessage::AuthFailed { message: reason.into() })?;
                (shared.notify)(AgentEvent::Refused {
                    peer,
                    reason: "zu viele Fehlversuche insgesamt, Anmeldung vorübergehend gesperrt".into(),
                });
                return Ok(());
            }
            let expected =
                compute_auth_response(&password, &client_nonce, &nonce, &shared.fingerprint);
            constant_time_eq(&expected, &response)
        }
        // Netzwerk-Suche: nur Kennung zurückgeben, keine Steuerung. Zählt
        // nicht als Fehlversuch.
        Some(ClientMessage::Discover) => {
            let busy = shared.session.lock().unwrap().is_some();
            send(
                &mut conn,
                &AgentMessage::DiscoverReply {
                    agent_version: AGENT_VERSION.to_string(),
                    hostname: local_hostname(),
                    busy,
                },
            )?;
            close(&mut conn);
            return Ok(());
        }
        _ => false,
    };
    if !authenticated {
        shared.guard.lock().unwrap().record_failure(peer.ip());
        std::thread::sleep(AUTH_FAIL_DELAY);
        send(
            &mut conn,
            &AgentMessage::AuthFailed {
                message: "Falsches Passwort.".into(),
            },
        )?;
        close(&mut conn);
        (shared.notify)(AgentEvent::AuthFailed { peer });
        return Ok(());
    }
    shared.guard.lock().unwrap().record_success(peer.ip());

    // Nur EIN Haupt-PC gleichzeitig.
    {
        let mut session = shared.session.lock().unwrap();
        if session.is_some() || shared.stop.load(Ordering::SeqCst) {
            let reason = "Dieser PC wird bereits von einem anderen PC ferngesteuert.";
            let _ = send(
                &mut conn,
                &AgentMessage::Error {
                    message: reason.into(),
                },
            );
            close(&mut conn);
            (shared.notify)(AgentEvent::Refused {
                peer,
                reason: reason.into(),
            });
            return Ok(());
        }
        *session = Some(raw.try_clone()?);
    }
    slot.release();

    let controller = controller_name
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| peer.ip().to_string());
    let proof = compute_agent_proof(&password, &client_nonce, &nonce, &shared.fingerprint);
    let reason = match start_session(&mut conn, proof) {
        Ok(()) => {
            (shared.notify)(AgentEvent::Connected { peer, controller });
            session_loop(&mut conn, shared)
        }
        Err(e) => format!("Verbindungsfehler: {e}"),
    };
    *shared.session.lock().unwrap() = None;
    close(&mut conn);
    let _ = raw.shutdown(Shutdown::Both);
    // Erst nach dem Aufräumen melden: Danach ist der Agent wieder frei.
    (shared.notify)(AgentEvent::Disconnected { peer, reason });
    Ok(())
}

/// Sendet eine Nachricht über die verschlüsselte Verbindung.
fn send(conn: &mut Conn, msg: &AgentMessage) -> io::Result<()> {
    write_msg(conn.get_mut(), msg)
}

/// Beendet die TLS-Verbindung sauber (close_notify), Fehler egal.
fn close(conn: &mut Conn) {
    let tls = conn.get_mut();
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// Schaltet auf Sitzungsbetrieb um und bestätigt die Anmeldung (mit dem
/// eigenen Nachweis, dass auch dieser PC den Code kennt).
fn start_session(conn: &mut Conn, proof: String) -> io::Result<()> {
    // Zeitlimits direkt an dem Socket setzen, über den gelesen wird - nicht an
    // einer Kopie (unter Windows hat jede Kopie ein eigenes Zeitlimit, sonst
    // os error 10060).
    let sock = &conn.get_ref().sock;
    sock.set_read_timeout(Some(IDLE_TIMEOUT))?;
    sock.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let _ = sock.set_nodelay(true);
    send(
        conn,
        &AgentMessage::Hello {
            protocol: PROTOCOL_VERSION,
            agent_version: AGENT_VERSION.to_string(),
            hostname: local_hostname(),
            admin: Some(is_elevated()),
            proof: Some(proof),
        },
    )
}

/// Ermittelt den Rechnernamen aus der jeweiligen Umgebungsvariable.
fn local_hostname() -> String {
    ["COMPUTERNAME", "HOSTNAME"]
        .iter()
        .find_map(|key| std::env::var(key).ok().filter(|name| !name.trim().is_empty()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// Läuft, solange der Haupt-PC verbunden ist. Liefert den Trennungsgrund.
fn session_loop(conn: &mut Conn, shared: &Shared) -> String {
    loop {
        if shared.stop.load(Ordering::SeqCst) {
            return "Fernzugriff wurde auf dem Ziel-PC ausgeschaltet.".into();
        }
        let msg = match read_msg::<_, ClientMessage>(conn) {
            Ok(Some(m)) => m,
            Ok(None) => return "Haupt-PC hat die Verbindung getrennt.".into(),
            Err(e) if is_timeout(&e) => {
                return format!(
                    "Haupt-PC hat sich {} Sekunden lang nicht gemeldet.",
                    IDLE_TIMEOUT.as_secs()
                )
            }
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return "Haupt-PC hat die Verbindung getrennt.".into()
            }
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                let _ = send(
                    conn,
                    &AgentMessage::Error {
                        message: format!("Ungültige Nachricht: {e}"),
                    },
                );
                return format!("Ungültige Nachricht: {e}");
            }
            Err(e) => {
                if shared.stop.load(Ordering::SeqCst) {
                    return "Fernzugriff wurde auf dem Ziel-PC ausgeschaltet.".into();
                }
                return format!("Verbindung abgebrochen: {e}");
            }
        };

        let result = match msg {
            ClientMessage::Ping => send(conn, &AgentMessage::Pong),
            ClientMessage::Hello { .. } => Ok(()), // doppeltes Hello ignorieren
            ClientMessage::Discover => Ok(()),     // nach dem Handshake unbedeutend
            ClientMessage::Auth { .. } => {
                let _ = send(
                    conn,
                    &AgentMessage::Error {
                        message: "Unerwartete Auth-Nachricht nach dem Handshake.".into(),
                    },
                );
                return "Protokollfehler (Auth nach Handshake).".into();
            }
            ClientMessage::Run { job, command } => {
                run_job(job, &command, conn.get_mut(), &shared.notify)
            }
        };
        if let Err(e) = result {
            return format!("Verbindung abgebrochen: {e}");
        }
    }
}

/// Führt einen Job aus und streamt die Ausgabe zurück.
fn run_job<W: Write>(
    job: u64,
    command: &RemoteCommand,
    out: &mut W,
    notify: &Notify,
) -> io::Result<()> {
    let invocations = match command.to_invocations() {
        Ok(list) => list,
        Err(reason) => {
            return write_msg(out, &AgentMessage::Rejected { job, reason });
        }
    };

    let program = winget_program();
    let mut all_ok = true;
    let mut last_code = None;
    for (index, args) in invocations.into_iter().enumerate() {
        let display = format!("winget {}", args.join(" "));
        if index == 0 {
            notify(AgentEvent::JobStarted {
                description: describe_command(command),
            });
        }
        write_msg(
            out,
            &AgentMessage::Started {
                job,
                display: format!("$ {display}"),
            },
        )?;
        let (ok, code) = run_invocation(&program, &args, job, out)?;
        write_msg(
            out,
            &AgentMessage::StepFinished {
                job,
                index,
                success: ok,
                exit_code: code,
            },
        )?;
        all_ok &= ok;
        last_code = code;
    }
    notify(AgentEvent::JobFinished { success: all_ok });
    write_msg(
        out,
        &AgentMessage::Finished {
            job,
            success: all_ok,
            exit_code: last_code,
        },
    )
}

/// Startet einen einzelnen winget-Prozess und leitet stdout/stderr zeilenweise
/// weiter. Läuft der Prozess weiter, obwohl der Haupt-PC weg ist, wird die
/// Ausgabe verworfen statt den Prozess zu blockieren; der Fehler wird erst
/// nach dem Ende gemeldet.
fn run_invocation<W: Write>(
    program: &str,
    args: &[String],
    job: u64,
    out: &mut W,
) -> io::Result<(bool, Option<i32>)> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            write_msg(
                out,
                &AgentMessage::Line {
                    job,
                    text: format!("Fehler beim Starten von {program}: {e}"),
                },
            )?;
            return Ok((false, None));
        }
    };

    let (tx, rx) = mpsc::channel::<String>();
    let mut readers = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        readers.push(spawn_line_reader(stdout, tx.clone()));
    }
    if let Some(stderr) = child.stderr.take() {
        readers.push(spawn_line_reader(stderr, tx.clone()));
    }
    drop(tx);

    let mut write_error: Option<io::Error> = None;
    for text in rx {
        if write_error.is_none() {
            if let Err(e) = write_msg(out, &AgentMessage::Line { job, text }) {
                write_error = Some(e);
            }
        }
    }
    for handle in readers {
        let _ = handle.join();
    }
    let status = child.wait()?;
    if let Some(e) = write_error {
        return Err(e);
    }
    Ok((status.success(), status.code()))
}

fn spawn_line_reader<R: Read + Send + 'static>(stream: R, tx: Sender<String>) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match reader.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let raw = String::from_utf8_lossy(&buf);
                    if let Some(line) = clean_line(&raw) {
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                }
            }
        }
    })
}

/// Fortschrittsbalken von winget (z. B. "██████▒▒▒▒  1.00 MB / 2.00 MB").
pub fn is_progress_line(line: &str) -> bool {
    line.contains(['█', '▒', '▓', '░'])
}

/// winget überschreibt Fortschrittsanzeigen per `\r`. Behalten wird jeweils
/// nur das letzte sichtbare Segment; reine Spinner-Zeichen und Fortschritts-
/// balken entfallen.
fn clean_line(raw: &str) -> Option<String> {
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    if trimmed.trim().is_empty() {
        return Some(String::new());
    }
    let segment = trimmed.rsplit('\r').find(|s| !s.trim().is_empty())?;
    let segment = segment.trim_end();
    if matches!(segment.trim(), "-" | "\\" | "|" | "/") || is_progress_line(segment) {
        return None;
    }
    Some(segment.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_line_keeps_last_segment() {
        assert_eq!(clean_line("abc\r\n").as_deref(), Some("abc"));
        assert_eq!(clean_line("10%\r50%\r100%\n").as_deref(), Some("100%"));
        assert_eq!(clean_line("-\n"), None);
        assert_eq!(clean_line("\\\r|\r/\n"), None);
        assert_eq!(clean_line("\n").as_deref(), Some(""));
        assert_eq!(clean_line("  ██████▒▒▒▒  1.00 MB / 2.00 MB\n"), None);
    }

    #[test]
    fn code_survives_restart() {
        let dir = std::env::temp_dir().join(format!("abk-agent-{}", std::process::id()));
        let path = dir.join("verbindungscode.dat");
        let _ = std::fs::remove_dir_all(&dir);
        let first = persistent_code(Some(&path));
        // "Neustart": derselbe Code kommt wieder.
        assert_eq!(persistent_code(Some(&path)), first);
        assert_eq!(persistent_code(Some(&path)), first);
        // Ohne Speicherort gibt es trotzdem einen (dann flüchtigen) Code.
        assert_ne!(persistent_code(None), first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Startet einen Test-Agent auf einem freien Port und sammelt Ereignisse.
    fn spawn_test_agent(
        password: &str,
    ) -> (AgentHandle, SocketAddr, String, std::sync::mpsc::Receiver<AgentEvent>) {
        std::env::set_var(PASSWORD_ENV_VAR, password);
        let (tx, rx) = std::sync::mpsc::channel();
        let tx = Mutex::new(tx);
        let notify: Notify = Arc::new(move |e| {
            let _ = tx.lock().unwrap().send(e);
        });
        let handle = start_background_with("127.0.0.1:0", notify, None).unwrap();
        let (addr, fp) = match rx.recv().unwrap() {
            AgentEvent::Listening { addr, fingerprint, .. } => (addr, fingerprint),
            other => panic!("unerwartet: {other:?}"),
        };
        (handle, addr, fp, rx)
    }

    /// Verschlüsselte Test-Verbindung aus Sicht des Haupt-PCs.
    struct Client {
        conn: BufReader<tls::ClientTls>,
        raw: TcpStream,
        fingerprint: String,
    }

    impl Client {
        fn connect(addr: SocketAddr) -> Self {
            let tcp = TcpStream::connect(addr).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let raw = tcp.try_clone().unwrap();
            let (tls, fingerprint) = tls::connect(tcp).unwrap();
            Self {
                conn: BufReader::new(tls),
                raw,
                fingerprint,
            }
        }
        fn send(&mut self, msg: &ClientMessage) {
            write_msg(self.conn.get_mut(), msg).unwrap();
        }
        fn recv(&mut self) -> io::Result<Option<AgentMessage>> {
            read_msg(&mut self.conn)
        }
        fn hello(&mut self, name: Option<&str>) -> ([u8; NONCE_BYTES], Vec<u8>) {
            let client_nonce = random_nonce();
            self.send(&ClientMessage::Hello {
                protocol: PROTOCOL_VERSION,
                name: name.map(str::to_string),
                client_nonce: Some(hex_encode(&client_nonce)),
            });
            match self.recv().unwrap().unwrap() {
                AgentMessage::Challenge { nonce } => (client_nonce, hex_decode(&nonce).unwrap()),
                other => panic!("unerwartet: {other:?}"),
            }
        }
    }

    /// Anmeldung wie der Haupt-PC; prüft bei Erfolg auch den Gegen-Nachweis.
    fn login(addr: SocketAddr, password: &str) -> (Client, AgentMessage) {
        let mut c = Client::connect(addr);
        let (cn, nonce) = c.hello(Some("HAUPT-PC"));
        let response = compute_auth_response(password, &cn, &nonce, &c.fingerprint);
        c.send(&ClientMessage::Auth { response });
        let answer = c.recv().unwrap().unwrap();
        if let AgentMessage::Hello { proof, .. } = &answer {
            let expected = compute_agent_proof(password, &cn, &nonce, &c.fingerprint);
            assert!(
                constant_time_eq(proof.as_deref().unwrap_or(""), &expected),
                "Ziel-PC muss den Code ebenfalls nachweisen"
            );
        }
        (c, answer)
    }

    /// Netzwerk-Suche: fragt ohne Passwort nach Name, Version und Belegt-Status.
    fn discover(addr: SocketAddr) -> AgentMessage {
        let mut c = Client::connect(addr);
        c.hello(None);
        c.send(&ClientMessage::Discover);
        c.recv().unwrap().unwrap()
    }

    /// Leitet Bytes unverändert weiter und zeichnet alles auf - so sieht ein
    /// Mitlauscher im Netzwerk die Verbindung.
    fn sniffing_relay(target: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<u8>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = Arc::clone(&seen);
        std::thread::spawn(move || {
            let (client, _) = listener.accept().unwrap();
            let server = TcpStream::connect(target).unwrap();
            let pump = |mut from: TcpStream, mut to: TcpStream, seen: Arc<Mutex<Vec<u8>>>| {
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    loop {
                        match from.read(&mut buf) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                seen.lock().unwrap().extend_from_slice(&buf[..n]);
                                if to.write_all(&buf[..n]).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                    let _ = to.shutdown(Shutdown::Both);
                })
            };
            pump(client.try_clone().unwrap(), server.try_clone().unwrap(), Arc::clone(&seen2));
            pump(server, client, seen2);
        });
        (addr, seen)
    }

    /// Angreifer in der Mitte: zeigt dem Haupt-PC sein EIGENES Zertifikat und
    /// reicht die Nachrichten an den echten Ziel-PC weiter.
    fn mitm_relay(target: SocketAddr) -> SocketAddr {
        let config = tls::AgentIdentity::generate().unwrap().server_config().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut victim = BufReader::new(tls::accept(tcp, config).unwrap());
            let (up, _) = tls::connect(TcpStream::connect(target).unwrap()).unwrap();
            let mut upstream = BufReader::new(up);
            // Hello -> Challenge <- Auth -> Antwort <-
            for to_agent in [true, false, true, false] {
                let mut line = String::new();
                let (from, to): (&mut dyn BufRead, &mut dyn Write) = if to_agent {
                    (&mut victim, upstream.get_mut())
                } else {
                    (&mut upstream, victim.get_mut())
                };
                if from.read_line(&mut line).unwrap_or(0) == 0 {
                    return;
                }
                to.write_all(line.as_bytes()).unwrap();
                to.flush().unwrap();
            }
        });
        addr
    }

    #[test]
    fn global_lockout_stops_ip_hopping() {
        let mut guard = AuthGuard::default();
        for i in 0..(GLOBAL_MAX_FAILURES - 1) {
            let ip: IpAddr = format!("10.0.{}.{}", i / 200, i % 200 + 1).parse().unwrap();
            guard.record_failure(ip);
            assert!(!guard.global_locked(), "zu früh gesperrt bei {i}");
        }
        // Jede IP für sich ist noch nicht gesperrt ...
        assert!(!guard.is_locked("10.0.0.1".parse().unwrap()));
        // ... aber der 30. Fehlversuch insgesamt sperrt die Anmeldung für alle.
        guard.record_failure("10.9.9.9".parse().unwrap());
        assert!(guard.global_locked());
        // Nach Ablauf ist die Sperre wieder weg.
        guard.global_until = Some(Instant::now() - Duration::from_secs(1));
        assert!(!guard.global_locked());
        assert!(guard.recent.is_empty());
    }

    /// Alle Netzwerk-Tests in einem, weil sie Umgebungsvariablen setzen
    /// (parallele Tests würden sich sonst gegenseitig stören).
    #[cfg(unix)]
    #[test]
    fn agent_end_to_end() {
        std::env::set_var("WINGET_PROGRAM", "echo");

        // Zu kurzes eigenes Passwort: Agent startet gar nicht erst.
        std::env::set_var(PASSWORD_ENV_VAR, "hallo12345");
        let err = start_background_with("127.0.0.1:0", Arc::new(|_| {}), None)
            .err()
            .expect("kurzes Passwort muss abgelehnt werden");
        assert!(err.to_string().contains("mindestens 12"), "{err}");

        let pw = "richtig-und-lang";
        let (handle, addr, agent_fp, events) = spawn_test_agent(pw);

        // 0) Netzwerk-Suche klappt ohne Passwort und zählt nicht als Fehlversuch.
        for _ in 0..(MAX_AUTH_FAILURES + 1) {
            match discover(addr) {
                AgentMessage::DiscoverReply { busy, agent_version, .. } => {
                    assert!(!busy);
                    assert_eq!(agent_version, AGENT_VERSION);
                }
                other => panic!("unerwartet: {other:?}"),
            }
        }

        // 0b) Alte App-Version (unverschlüsselt) bekommt einen klaren Hinweis.
        {
            let stream = TcpStream::connect(addr).unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut writer = stream;
            writer
                .write_all(b"{\"type\":\"hello\",\"protocol\":3,\"name\":\"ALT\"}\n")
                .unwrap();
            match read_msg::<_, AgentMessage>(&mut reader).unwrap().unwrap() {
                AgentMessage::Error { message } => assert!(message.contains("0.6.0"), "{message}"),
                other => panic!("unerwartet: {other:?}"),
            }
        }

        // 1) Falsches Passwort wird abgelehnt und die Verbindung beendet.
        let (mut c, answer) = login(addr, "falsch");
        assert!(matches!(answer, AgentMessage::AuthFailed { .. }));
        assert!(matches!(c.recv(), Ok(None) | Err(_)));
        assert!(matches!(events.recv().unwrap(), AgentEvent::AuthFailed { .. }));

        // 1b) Angreifer in der Mitte mit eigenem Zertifikat: Obwohl der
        // Haupt-PC den RICHTIGEN Code benutzt, scheitert die Anmeldung, weil
        // sie an das Zertifikat gebunden ist, das der Haupt-PC gesehen hat.
        let relay = mitm_relay(addr);
        let (c, answer) = login(relay, pw);
        assert_ne!(c.fingerprint, agent_fp, "Relay zeigt sein eigenes Zertifikat");
        assert!(matches!(answer, AgentMessage::AuthFailed { .. }), "{answer:?}");
        assert!(matches!(events.recv().unwrap(), AgentEvent::AuthFailed { .. }));

        // 2) Richtiges Passwort (über einen Mitlauscher, der alles aufzeichnet):
        // Connected-Ereignis mit dem Namen des Haupt-PCs.
        let (sniff_addr, sniffed) = sniffing_relay(addr);
        let (mut c, answer) = login(sniff_addr, pw);
        assert_eq!(c.fingerprint, agent_fp, "Fingerabdruck = Zertifikat des Ziel-PCs");
        assert!(matches!(answer, AgentMessage::Hello { protocol, .. } if protocol == PROTOCOL_VERSION));
        match events.recv().unwrap() {
            AgentEvent::Connected { controller, .. } => assert_eq!(controller, "HAUPT-PC"),
            other => panic!("unerwartet: {other:?}"),
        }

        // 2b) Während der Sitzung meldet die Suche "belegt".
        assert!(matches!(
            discover(addr),
            AgentMessage::DiscoverReply { busy: true, .. }
        ));

        // 3) Ein zweiter Haupt-PC bekommt eine klare Absage.
        let (_c2, answer2) = login(addr, pw);
        match answer2 {
            AgentMessage::Error { message } => assert!(message.contains("bereits")),
            other => panic!("unerwartet: {other:?}"),
        }
        assert!(matches!(events.recv().unwrap(), AgentEvent::Refused { .. }));

        // 4) Mehrfach-Update: Ergebnis pro Paket (StepFinished) + Finished.
        c.send(&ClientMessage::Run {
            job: 1,
            command: RemoteCommand::UpgradeIds {
                ids: vec!["Geheim.Paket".into(), "C.D".into()],
            },
        });
        let mut steps = Vec::new();
        let mut output = String::new();
        loop {
            match c.recv().unwrap().unwrap() {
                AgentMessage::StepFinished { index, success, .. } => steps.push((index, success)),
                AgentMessage::Finished { job, success, .. } => {
                    assert_eq!(job, 1);
                    assert!(success);
                    break;
                }
                AgentMessage::Line { text, .. } => output.push_str(&text),
                AgentMessage::Started { .. } => {}
                other => panic!("unerwartet: {other:?}"),
            }
        }
        assert_eq!(steps, vec![(0, true), (1, true)]);
        assert!(output.contains("Geheim.Paket"), "Ausgabe kommt beim Haupt-PC an");

        // 4b) Der Mitlauscher hat nur verschlüsselte Daten gesehen.
        {
            let seen = sniffed.lock().unwrap();
            assert!(seen.len() > 500, "es wurde etwas übertragen");
            for secret in [
                &b"Geheim.Paket"[..],
                b"HAUPT-PC",
                b"upgrade",
                b"challenge",
                b"\"type\"",
                pw.as_bytes(),
            ] {
                assert!(
                    !seen.windows(secret.len()).any(|w| w == secret),
                    "Klartext im Netzwerk sichtbar: {}",
                    String::from_utf8_lossy(secret)
                );
            }
        }

        // 5) Ungültige ID wird abgelehnt, ohne etwas zu starten.
        c.send(&ClientMessage::Run {
            job: 2,
            command: RemoteCommand::Install { id: "--force".into() },
        });
        assert!(matches!(
            c.recv().unwrap().unwrap(),
            AgentMessage::Rejected { job: 2, .. }
        ));

        // 6) Trennen -> Disconnected-Ereignis, danach ist der Agent wieder frei.
        c.raw.shutdown(Shutdown::Both).unwrap();
        loop {
            match events.recv_timeout(Duration::from_secs(5)).unwrap() {
                AgentEvent::Disconnected { .. } => break,
                AgentEvent::JobStarted { .. } | AgentEvent::JobFinished { .. } => {}
                other => panic!("unerwartet: {other:?}"),
            }
        }
        let (mut c3, answer3) = login(addr, pw);
        assert!(matches!(answer3, AgentMessage::Hello { .. }));

        // 6b) Neuer Code: der alte ist sofort ungültig, der neue wird akzeptiert
        // (die Sitzung ist belegt, daher kommt erst NACH der Anmeldung "bereits").
        let new_code = handle.new_password();
        assert_eq!(normalize_password(&new_code).len(), GENERATED_PASSWORD_CHARS);
        assert!(matches!(login(addr, pw).1, AgentMessage::AuthFailed { .. }));
        match login(addr, &normalize_password(&new_code)).1 {
            AgentMessage::Error { message } => assert!(message.contains("bereits")),
            other => panic!("unerwartet: {other:?}"),
        }

        // 7) Ausschalten trennt die laufende Sitzung sofort.
        drop(handle);
        assert!(matches!(c3.recv(), Ok(None) | Err(_)));
        std::env::remove_var(PASSWORD_ENV_VAR);
    }
}
