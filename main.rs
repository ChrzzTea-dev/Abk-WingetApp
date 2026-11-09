// Im Release-Build kein zusätzliches schwarzes Konsolenfenster hinter der App.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, RichText};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

// Fernsteuerung: Protokoll, Agent (läuft in der App mit) und Remote-Fenster.
mod agent;
mod protocol;
mod remote_ui;
mod tls;

/// Baut einen winget-Aufruf: ohne aufblitzendes Konsolenfenster (Windows)
/// und ohne Eingabe, damit winget nie auf eine Rückfrage wartet.
fn winget() -> Command {
    let mut cmd = Command::new("winget");
    cmd.stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    cmd
}

// ---------------------------------------------------------------------------
// Autostart mit Administratorrechten (Windows-Aufgabenplanung)
// ---------------------------------------------------------------------------
//
// Viele Updates (z. B. Visual C++, .NET) brauchen Administratorrechte. Läuft
// die App ohne sie, zeigt Windows am Ziel-PC bei jedem solchen Update eine
// UAC-Abfrage, die jemand anklicken muss. Diese Abfrage kann (und darf) ein
// Programm nicht selbst wegklicken. Die Lösung: Die App wird einmalig als
// geplante Aufgabe "bei Anmeldung, mit höchsten Rechten" eingetragen. Dafür
// ist GENAU EINE UAC-Bestätigung nötig - danach startet die App bei jeder
// Anmeldung mit Administratorrechten, und Updates laufen ohne jeden Klick.

/// Name der geplanten Aufgabe in der Windows-Aufgabenplanung.
const AUTOSTART_TASK: &str = "Abk-WingetApp";

/// Ergebnisse aus den Hintergrund-Threads rund um den Autostart.
enum AutostartEvent {
    /// Ergebnis der Prüfung beim Programmstart: Ist die Aufgabe eingerichtet?
    Status(bool),
    /// Einrichten fertig.
    Installed(Result<(), String>),
    /// Entfernen fertig.
    Removed(Result<(), String>),
}

/// Kein Konsolenfenster für Hilfsprogramme (schtasks, PowerShell).
fn hidden(cmd: &mut Command) -> &mut Command {
    cmd.stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    cmd
}

/// Base64 (Standard-Alphabet mit Auffüllung) - für PowerShell -EncodedCommand.
fn base64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// PowerShell-Skript als `-EncodedCommand` (Base64 von UTF-16LE). So gibt es
/// keine Probleme mit Anführungszeichen oder Leerzeichen in Pfaden.
fn ps_encode(script: &str) -> String {
    let bytes: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    base64(&bytes)
}

/// Text als PowerShell-Zeichenkette in einfachen Anführungszeichen.
fn ps_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// Ist die Aufgabe in der Aufgabenplanung eingetragen?
fn autostart_task_exists() -> bool {
    cfg!(windows)
        && hidden(Command::new("schtasks").args(["/Query", "/TN", AUTOSTART_TASK]))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

/// Startet ein (kodiertes) Skript per UAC-Abfrage mit Administratorrechten.
/// Bricht der Benutzer ab, endet es mit Code 1223 (ERROR_CANCELLED).
fn elevate_script(inner_encoded: &str) -> String {
    format!(
        "try {{ $p = Start-Process -FilePath 'powershell.exe' -Verb RunAs -WindowStyle Hidden \
         -Wait -PassThru -ErrorAction Stop -ArgumentList '-NoProfile','-NonInteractive',\
         '-ExecutionPolicy','Bypass','-EncodedCommand','{inner_encoded}'; exit $p.ExitCode }} \
         catch {{ exit 1223 }}"
    )
}

/// Skript, das die geplante Aufgabe anlegt (läuft mit Administratorrechten).
fn autostart_install_script(exe: &str, user: &str) -> String {
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         try {{\n\
           $exe = {exe}\n\
           $user = {user}\n\
           $action = New-ScheduledTaskAction -Execute $exe -WorkingDirectory (Split-Path -Parent $exe)\n\
           $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user\n\
           $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Highest\n\
           $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)\n\
           Register-ScheduledTask -TaskName {task} -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null\n\
           exit 0\n\
         }} catch {{ exit 2 }}\n",
        exe = ps_quote(exe),
        user = ps_quote(user),
        task = ps_quote(AUTOSTART_TASK),
    )
}

/// Skript, das die geplante Aufgabe wieder entfernt.
fn autostart_remove_script() -> String {
    format!(
        "try {{ Unregister-ScheduledTask -TaskName {} -Confirm:$false -ErrorAction Stop; exit 0 }} \
         catch {{ exit 2 }}",
        ps_quote(AUTOSTART_TASK)
    )
}

/// Führt ein PowerShell-Skript mit Administratorrechten aus: direkt, wenn die
/// App schon als Administrator läuft, sonst über EINE UAC-Abfrage.
fn run_elevated_powershell(script: &str) -> Result<(), String> {
    if !cfg!(windows) {
        return Err("Nur unter Windows verfügbar.".into());
    }
    let inner = ps_encode(script);
    let output = if protocol::is_elevated() {
        hidden(&mut Command::new("powershell.exe"))
            .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"])
            .args(["-EncodedCommand", &inner])
            .output()
    } else {
        hidden(&mut Command::new("powershell.exe"))
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &ps_encode(&elevate_script(&inner))])
            .output()
    };
    match output {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) if o.status.code() == Some(1223) => {
            Err("Die Windows-Abfrage (UAC) wurde abgebrochen.".into())
        }
        Ok(o) => Err(format!(
            "Einrichten fehlgeschlagen (Code {}). {}",
            o.status.code().map_or("?".to_string(), |c| c.to_string()),
            combine_output(&o).trim()
        )),
        Err(e) => Err(format!("PowerShell konnte nicht gestartet werden: {e}")),
    }
}

/// Richtet den Autostart mit Administratorrechten für den angemeldeten
/// Benutzer ein (bei Anmeldung, ohne Zeitlimit, auch im Akkubetrieb).
fn install_autostart() -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("Programmpfad nicht gefunden: {e}"))?
        .to_string_lossy()
        .into_owned();
    // Der Benutzer, der die App gerade benutzt - auch wenn die UAC-Abfrage mit
    // einem anderen Administrator-Konto bestätigt wird.
    let domain = std::env::var("USERDOMAIN")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_default();
    let user = std::env::var("USERNAME").map_err(|_| "Benutzername nicht gefunden.".to_string())?;
    let user = if domain.is_empty() { user } else { format!("{domain}\\{user}") };
    let result = run_elevated_powershell(&autostart_install_script(&exe, &user));
    // Gegenprobe: Gibt es die Aufgabe jetzt?
    match result {
        Ok(()) | Err(_) if autostart_task_exists() => Ok(()),
        Ok(()) => Err("Die Aufgabe wurde nicht angelegt.".into()),
        Err(e) => Err(e),
    }
}

/// Entfernt den Autostart wieder (braucht ebenfalls eine UAC-Bestätigung).
fn remove_autostart() -> Result<(), String> {
    let result = run_elevated_powershell(&autostart_remove_script());
    match result {
        Ok(()) | Err(_) if !autostart_task_exists() => Ok(()),
        Ok(()) => Err("Die Aufgabe konnte nicht entfernt werden.".into()),
        Err(e) => Err(e),
    }
}

/// Startet die App über die Aufgabe neu - dann mit Administratorrechten und
/// ohne UAC-Abfrage.
fn run_autostart_task() -> Result<(), String> {
    match hidden(Command::new("schtasks").args(["/Run", "/TN", AUTOSTART_TASK]))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("schtasks meldet Code {:?}", s.code())),
        Err(e) => Err(e.to_string()),
    }
}

/// Fügt stdout und stderr eines winget-Aufrufs zu einem Text zusammen.
fn combine_output(output: &std::process::Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    let err = String::from_utf8_lossy(&output.stderr);
    if !err.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&err);
    }
    text
}

/// winget überschreibt Fortschrittsanzeigen per `\r` - sichtbar ist nur das
/// letzte Segment einer Zeile.
fn visible_part(line: &str) -> &str {
    line.rsplit('\r').find(|s| !s.trim().is_empty()).unwrap_or("")
}

/// Zeilen, die nur Spinner oder Fortschrittsbalken enthalten.
fn is_noise_line(line: &str) -> bool {
    let t = line.trim();
    matches!(t, "-" | "\\" | "|" | "/") || agent::is_progress_line(t)
}

// Ein winget-Kommando für die Buttonliste rechts.
// `args` ist bereits so aufgebaut, dass es 1:1 an
// `winget().args(...)` übergeben wird.
// Hinweis: Manche Kommandos (Suchen/Installieren/Deinstallieren/Details/
// Quellen aktualisieren/Export/Import) öffnen inzwischen ein eigenes
// Fenster mit Eingabefeld statt den Befehl sofort auszuführen - `args`
// und `help` bleiben trotzdem als Referenz und für das Hilfe-Fenster
// erhalten.
struct WingetCommand {
    label: &'static str,
    args: &'static [&'static str],
    help: &'static str,
}

// "Winget-Version anzeigen" entfällt (steht dauerhaft unten rechts).
// "Quellen auflisten" wurde ins Burgermenü verschoben (siehe SOURCE_LIST_COMMAND).
// "Einstellungen öffnen" wurde komplett entfernt - die GUI-Einstellungen
// (Design/Schriftgröße/Sprache) leben jetzt im Burgermenü.
const WINGET_COMMANDS: &[WingetCommand] = &[
    // Alphabetisch nach der sichtbaren Bezeichnung sortiert.
    WingetCommand {
        label: "Alle Updates installieren",
        args: &["upgrade", "--all"],
        help: "Zeigt zunächst die Liste aller verfügbaren Updates (alle bereits angehakt) und installiert nach einer einmaligen Bestätigung alles zusammen.",
    },
    WingetCommand {
        label: "Liste installierter Pakete",
        args: &["list"],
        help: "Zeigt alle aktuell auf diesem PC installierten Programme an, die winget kennt.",
    },
    WingetCommand {
        label: "Paket deinstallieren",
        args: &["uninstall"],
        help: "Öffnet ein Fenster mit Eingabefeld und einer Liste der installierten Pakete, aus der du eines zum Entfernen auswählen kannst.",
    },
    WingetCommand {
        label: "Paket installieren",
        args: &["install"],
        help: "Öffnet ein Fenster mit Eingabefeld und einer Online-Suche über winget, damit du das gewünschte Paket suchen und anschließend installieren kannst.",
    },
    WingetCommand {
        label: "Paket suchen",
        args: &["search"],
        help: "Öffnet ein Fenster mit Eingabefeld, um in den winget-Quellen nach Paketen zu suchen (winget search <Begriff>).",
    },
    WingetCommand {
        label: "Paket-Details anzeigen",
        args: &["show"],
        help: "Öffnet ein Fenster mit Eingabefeld und zeigt ausführliche Informationen zu einem Paket an (Version, Hersteller, Beschreibung usw.).",
    },
    WingetCommand {
        label: "Paketliste exportieren",
        args: &["export"],
        help: "Öffnet ein Fenster, in dem du Zieldatei und Dateiformat auswählst, bevor exportiert wird.",
    },
    WingetCommand {
        label: "Paketliste importieren",
        args: &["import"],
        help: "Öffnet ein Fenster, in dem du Quelldatei und Dateiformat auswählst, bevor importiert wird.",
    },
    WingetCommand {
        label: "Quellen aktualisieren",
        args: &["source", "update"],
        help: "Öffnet ein Fenster, das live anzeigt, welche Quellen gerade aktualisiert werden.",
    },
    WingetCommand {
        label: "Updates auswählen",
        args: &["upgrade"],
        help: "Ermittelt alle verfügbaren Updates und zeigt sie als Liste an, in der du einzeln auswählen kannst, welche Programme aktualisiert werden sollen. Gibt es keine Updates, wird das deutlich angezeigt.",
    },
];

// Eigenständiges Kommando für "Quellen auflisten", das jetzt nur noch im
// Burgermenü erreichbar ist (siehe Anforderung: erfüllt für Christoph
// keine eigene Aufgabe genug, um einen ganzen Button auf der Frontseite
// zu belegen).
const SOURCE_LIST_COMMAND: WingetCommand = WingetCommand {
    label: "Quellen auflisten",
    args: &["source", "list"],
    help: "Zeigt an, aus welchen Quellen (z. B. winget, msstore) Pakete bezogen werden können.",
};

/// Beschriftung und Hilfetext eines Befehls in der gewählten Sprache. Die
/// deutschen Texte stehen in der Konstante, die englischen hier.
fn localized_command(cmd: &WingetCommand, lang: Language) -> (&'static str, &'static str) {
    let en = match cmd.args {
        ["upgrade", "--all"] => (
            "Install all updates",
            "First shows the list of all available updates (all already ticked) and installs everything together after a single confirmation.",
        ),
        ["list"] => (
            "List installed packages",
            "Shows all programs currently installed on this PC that winget knows about.",
        ),
        ["uninstall"] => (
            "Uninstall package",
            "Opens a window with an input field and a list of installed packages from which you can pick one to remove.",
        ),
        ["install"] => (
            "Install package",
            "Opens a window with an input field and an online search via winget so you can find and then install the package you want.",
        ),
        ["search"] => (
            "Search package",
            "Opens a window with an input field to search the winget sources for packages (winget search <term>).",
        ),
        ["show"] => (
            "Show package details",
            "Opens a window with an input field and shows detailed information about a package (version, publisher, description, etc.).",
        ),
        ["export"] => (
            "Export package list",
            "Opens a window where you choose the target file and file format before exporting.",
        ),
        ["import"] => (
            "Import package list",
            "Opens a window where you choose the source file and file format before importing.",
        ),
        ["source", "update"] => (
            "Update sources",
            "Opens a window that shows live which sources are currently being updated.",
        ),
        ["upgrade"] => (
            "Select updates",
            "Finds all available updates and shows them as a list in which you can choose individually which programs to update. If there are no updates, this is clearly shown.",
        ),
        ["source", "list"] => (
            "List sources",
            "Shows which sources (e.g. winget, msstore) packages can be installed from.",
        ),
        _ => return (cmd.label, cmd.help),
    };
    pick(lang, (cmd.label, cmd.help), en)
}

// Ein Paket-Eintrag, wie er aus `winget list` / `winget search` geparst wird.
#[derive(Clone, Default)]
struct PackageItem {
    name: String,
    id: String,
    version: String,
    source: String,
}

// Ein einzelnes Update, das winget für ein installiertes Programm gefunden hat.
// Wird aus der Textausgabe von `winget upgrade` geparst.
#[derive(Clone, Default)]
struct UpgradeItem {
    name: String,
    id: String,
    installed_version: String,
    available_version: String,
    #[allow(dead_code)] // wird geparst, aktuell aber nicht angezeigt
    source: String,
    selected: bool,
}

/// Kästchen über einer Update-Liste: Ein Klick hakt alle an, ein weiterer
/// Klick hakt alle wieder ab. Ist nur ein Teil angehakt, zeigt es einen Strich;
/// ein Klick hakt dann alle an.
pub(crate) fn select_all_checkbox(ui: &mut egui::Ui, items: &mut [UpgradeItem]) -> egui::Response {
    let selected = items.iter().filter(|i| i.selected).count();
    let all = !items.is_empty() && selected == items.len();
    let mut checked = all;
    let response = ui
        .add(egui::Checkbox::new(&mut checked, "").indeterminate(selected > 0 && !all))
        .on_hover_text(if all {
            "Alle abwählen / deselect all"
        } else {
            "Alle auswählen / select all"
        });
    if response.changed() {
        toggle_all(items);
    }
    response
}

/// Alle angehakt -> alle ab, sonst (keins oder ein Teil) -> alle an.
fn toggle_all(items: &mut [UpgradeItem]) {
    let all = !items.is_empty() && items.iter().all(|i| i.selected);
    items.iter_mut().for_each(|i| i.selected = !all);
}

// Dateiformat für Export/Import der Paketliste.
#[derive(Clone, Copy, PartialEq)]
enum FileFormat {
    /// Natives winget-Format (JSON), erzeugt/gelesen über `winget export`/`winget import`.
    WingetJson,
    /// Eigenes, einfaches Format: eine winget-Id pro Zeile (`#` = Kommentar).
    TextList,
}

// GUI-Sprache (Burgermenü -> Darstellung). Deckt bewusst nur einen Teil
// der Oberfläche ab (Grundlage für spätere, vollständigere Übersetzung).
#[derive(Clone, Copy, PartialEq)]
enum Language {
    De,
    En,
}

/// Wählt je nach GUI-Sprache den deutschen oder den englischen Text.
fn pick<T>(lang: Language, de: T, en: T) -> T {
    match lang {
        Language::De => de,
        Language::En => en,
    }
}

/// Was die App gerade im Hintergrund tut. Ersetzt die früheren Einzel-Flags
/// (running, searching, installing, ...): Es kann immer nur EINE Sache laufen,
/// und das Zurücksetzen passiert an genau einer Stelle (`Busy::Idle`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Busy {
    Idle,
    /// Einfacher Befehl, dessen Ausgabe direkt ins Terminal geht.
    Command,
    ListUpgrades,
    InstallUpgrades,
    Search,
    InstallSearch,
    Installing,
    LoadInstalled,
    Uninstalling,
    Details,
    SourceUpdate,
    Export,
    Import,
}

impl Busy {
    fn is_active(self) -> bool {
        self != Busy::Idle
    }
}

/// Nachrichten, die vom Hintergrund-Thread (winget-Ausführung) ans UI
/// zurückgeschickt werden.
enum TerminalMsg {
    /// Ein Befehl wurde gestartet (für die Anzeige "$ winget ...").
    Started(String),
    /// Ausgabe (stdout/stderr) ist fertig - der Befehl ist damit beendet.
    Output { text: String, success: bool },
    /// Zwischenergebnis eines Befehls mit mehreren Schritten (z. B. ein
    /// Paket von mehreren Updates). Beendet den Befehl NICHT.
    Progress { text: String, summary: String },
    /// Ergebnis der Versionsabfrage (für die Statusleiste unten rechts).
    VersionResult(String),
    /// Ergebnis von "winget upgrade", bereits in einzelne Pakete geparst.
    UpgradeList(Vec<UpgradeItem>),
    /// Ergebnis von "winget search ...", geparst in einzelne Pakete.
    SearchResult(Vec<PackageItem>),
    /// Ergebnis der Online-Paketsuche aus dem Installieren-Fenster.
    InstallSearchResult(Vec<PackageItem>),
    /// Ergebnis von "winget list" für das Deinstallieren-Fenster.
    InstalledList(Vec<PackageItem>),
    /// Ergebnis von "winget show ...".
    DetailsResult(String),
    /// Eine einzelne Zeile Live-Ausgabe (Quellen aktualisieren / Text-Import).
    StreamLine(String),
    /// Ein gestreamter Vorgang ist fertig.
    StreamDone { success: bool },
}

/// Zustand des Fernzugriffs auf DIESEN PC (Agent in der App).
enum AgentStatus {
    Off,
    Listening {
        ip: Option<IpAddr>,
        password: String,
        /// Läuft die App mit Administratorrechten?
        admin: bool,
        /// Fingerabdruck des TLS-Zertifikats dieses PCs (zum Vergleichen).
        fingerprint: String,
    },
    Failed(String),
}

/// Ein Haupt-PC steuert gerade diesen PC.
struct RemoteSession {
    controller: String,
    ip: IpAddr,
    /// Befehl, der gerade ferngesteuert ausgeführt wird.
    current: Option<String>,
}

/// Name und Version der App (Version kommt aus der Cargo.toml).
pub const APP_NAME: &str = "Abk-WingetApp";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

const TERM_BG: Color32 = Color32::from_rgb(24, 26, 31);
const AMBER: Color32 = Color32::from_rgb(220, 150, 30);
const GREEN: Color32 = Color32::from_rgb(46, 160, 90);
const RED: Color32 = Color32::from_rgb(205, 65, 65);

/// Verbirgt einen Code für die Anzeige, behält aber die Gruppierung bei
/// ("3FA9-27BC" -> "••••-••••").
fn mask_code(code: &str) -> String {
    code.chars()
        .map(|c| if c == '-' || c == ' ' { c } else { '•' })
        .collect()
}

/// Farbe einer Terminal-Zeile anhand ihres Anfangs.
fn terminal_line_color(line: &str) -> Color32 {
    let t = line.trim_start();
    if t.starts_with('$') {
        Color32::from_rgb(120, 170, 255)
    } else if t.starts_with('✔')
        || t.starts_with('🔓')
        || (t.starts_with("━━ Fertig") && !t.contains("Nicht"))
        || (t.starts_with("━━ Done") && !t.contains("Not updated"))
    {
        Color32::from_rgb(110, 210, 140)
    } else if t.starts_with('✖') {
        Color32::from_rgb(240, 110, 110)
    } else if t.starts_with('⚠') || t.starts_with('🔒') || t.starts_with("━━") || t.starts_with('↳') {
        Color32::from_rgb(240, 190, 90)
    } else {
        Color32::from_rgb(214, 218, 224)
    }
}

/// Ein einzelner Eintrag im Versionsverlauf (entspricht einer veröffentlichten
/// Version der App) - wird direkt im Code gepflegt, ganz ohne Git.
struct AppVersion {
    version: &'static str,
    date: &'static str,
    // Kurze Stichpunkte, was in dieser Version geändert/neu hinzugekommen ist.
    changes: &'static [&'static str],
}

// Versionsverlauf der WingetApp, neueste Version zuerst.
const VERSION_HISTORY: &[AppVersion] = &[
    AppVersion {
        version: "0.6.0",
        date: "2026-11-03",
        changes: &[
            "Sicherheit: Die gesamte Fernsteuerung läuft jetzt verschlüsselt (TLS 1.3). Niemand \
             im Netzwerk kann mehr mitlesen, welche Programme installiert werden, oder Befehle \
             unterwegs verändern - auch die Netzwerk-Suche ist verschlüsselt.",
            "Jeder Ziel-PC hat ein eigenes Sicherheits-Zertifikat (privater Schlüssel per Windows-DPAPI \
             geschützt). Der Haupt-PC merkt sich dessen Fingerabdruck beim ersten Verbinden und warnt \
             mit \"⚠ Zertifikat geändert\", falls sich ein anderes Gerät als dieser PC ausgibt - \
             mit Knopf \"Zertifikat neu vertrauen\" für den Fall einer Neuinstallation.",
            "Gegenseitige Anmeldung mit Channel Binding: Auch der Ziel-PC muss beweisen, dass er den \
             Code kennt, und der Nachweis ist an das Zertifikat gebunden. Ein Angreifer dazwischen \
             kann eine Anmeldung weder weiterreichen noch einen falschen Ziel-PC vortäuschen.",
            "Neue Verbindungscodes sind länger (20 statt 16 Zeichen, 80 Bit). Bestehende Codes \
             bleiben gültig. Eigene Passwörter (WINGET_AGENT_PASSWORD) brauchen mindestens 12 Zeichen.",
            "Der Verbindungscode ist im Hauptfenster standardmäßig verborgen (\"👁 Anzeigen\"); \
             Kopieren funktioniert weiterhin.",
            "Zusätzliche globale Sperre: Nach 30 Fehlversuchen in 10 Minuten (egal von welchen \
             IP-Adressen) ist die Anmeldung 5 Minuten für alle gesperrt.",
            "Gespeicherte Codes werden mit zusätzlichem App-Schlüssel (DPAPI-Entropie) verschlüsselt; \
             ältere Dateien werden automatisch umgestellt.",
            "Wichtig: 0.6.0 ist nicht mit älteren Versionen kompatibel - bitte auf ALLEN PCs \
             aktualisieren. Ältere Versionen werden in der Liste als \"ältere App-Version\" angezeigt.",
        ],
    },
    AppVersion {
        version: "0.5.4",
        date: "2026-10-27",
        changes: &[
            "Neuer Name: \"Abk-WingetApp\" in der Titelleiste und oben im Fenster.",
            "Fester Verbindungscode pro PC: Der Code wird beim ersten Start einmal erzeugt und \
             verschlüsselt gespeichert (Windows-DPAPI) - er bleibt nach jedem Neustart gleich. \
             Nur \"🎲 Neu erzeugen\" ändert ihn.",
            "Direkt wieder verbinden: Der Haupt-PC merkt sich nach der ersten erfolgreichen \
             Verbindung den Code jedes PCs (ebenfalls verschlüsselt). In \"Bereits verbunden\" \
             und in der Netzwerk-Liste reicht dann ein Klick auf \"🔑 Direkt verbinden\" - ohne \
             Code-Eingabe. Stimmt ein gespeicherter Code nicht mehr (Ziel-PC hat \"Neu erzeugen\" \
             gedrückt), wird er verworfen und die App sagt, dass der neue Code einmal einzugeben ist.",
            "Updates ohne Mausklick am Ziel-PC: Neuer Punkt \"🛡 Mit Adminrechten automatisch \
             starten\" (Burgermenü bzw. Hinweis oben im Fenster). Er trägt die App einmalig in die \
             Windows-Aufgabenplanung ein (eine UAC-Bestätigung). Danach startet sie bei jeder \
             Anmeldung mit Administratorrechten, und Updates wie Visual C++ oder .NET laufen ohne \
             Windows-Abfrage durch. Zusätzlich fragt winget selbst nie mehr nach \
             (--disable-interactivity).",
            "Kästchen über der Update-Liste (Remote und lokal): ein Klick hakt alle Updates an, \
             ein weiterer Klick alle wieder ab; bei teilweiser Auswahl zeigt es einen Strich.",
        ],
    },
    AppVersion {
        version: "0.5.3",
        date: "2026-10-25",
        changes: &[
            "Verbindungscode statt Passwort-Einrichtung: Jede WingetApp erzeugt beim Start \
             automatisch einen zufälligen Code (SHA-256, z. B. 3FA9-27BC-91D4-E0A1) und zeigt \
             ihn oben in der Mitte an - mit Knöpfen zum Kopieren und Neu-Erzeugen. Auf dem \
             Haupt-PC reicht es, den Code einzugeben (Groß-/Kleinschreibung und Bindestriche \
             sind egal). setx und Umgebungsvariable sind nicht mehr nötig; \
             WINGET_AGENT_PASSWORD bleibt als optionales festes Passwort. Das Test-Passwort \
             wurde entfernt.",
            "Neue Liste \"Bereits verbunden\" im Remote-Fenster: Gerätename, IPv4- und \
             MAC-Adresse, wann zuletzt verbunden und ob der PC gerade im Netzwerk gefunden wird - \
             mit Verbinden- und Entfernen-Knopf. Die Liste bleibt nach einem Neustart erhalten \
             (Codes werden nicht gespeichert).",
            "Fehler behoben: Die Hilfe nannte die falsche Umgebungsvariable WINGETAPP_PASSWORD.",
        ],
    },
    AppVersion {
        version: "0.5.2",
        date: "2026-10-20",
        changes: &[
            "Fehler behoben: Updates wie \"Microsoft Visual C++ v14 Redistributable\" \
             (Microsoft.VCRedist.2015+.x64/x86) und \"Microsoft Windows Desktop Runtime\" \
             (Microsoft.DotNet.DesktopRuntime.10) schlugen fehl bzw. wurden mit \"Ungültige \
             Paket-ID\" abgelehnt. Ursache: Bei langen Namen/Ids steht in der winget-Tabelle \
             nur EIN Leerzeichen zwischen den Spalten, dadurch wurden Name+Id bzw. Id+Version \
             zusammengeklebt. Die Tabellen werden jetzt exakt an den Spaltenpositionen der \
             Kopfzeile geschnitten (auch mit chinesischen/japanischen Namen, ARP-Einträgen und \
             mehreren Tabellen in einer Ausgabe).",
            "Remote: Eine unbrauchbare Paket-Id kippt nicht mehr den ganzen Update-Auftrag - \
             betroffene Einträge werden übersprungen und gemeldet, der Rest wird installiert.",
            "Remote: Installieren und Deinstallieren melden jetzt immer ein Ergebnis (vorher \
             passierte bei einzelnen Apps sichtbar nichts).",
            "Fehlercodes im Klartext: Jedes fehlgeschlagene Update/Installieren/Deinstallieren \
             zeigt den Code (z. B. 0x8A150014) mit Erklärung, auch in der Zusammenfassung \
             \"Nicht aktualisiert\". Neustart-Codes (3010, 0x8A150109) zählen als Erfolg.",
            "Hinweis bei fehlenden Administratorrechten auf dem Ziel-PC: Ohne sie brauchen \
             systemweite Updates (Visual C++, .NET) dort eine UAC-Bestätigung. Der Haupt-PC \
             zeigt die Warnung beim Verbinden an.",
        ],
    },
    AppVersion {
        version: "0.5.1",
        date: "2026-10-20",
        changes: &[
            "Fernzugriff nur mit eigenem Passwort: Im Release-Build startet der Agent \
             nur, wenn die Umgebungsvariable WINGETAPP_PASSWORD gesetzt ist. Das \
             Test-Passwort gibt es nur noch im Debug-Build und wird dort in der \
             Statusleiste deutlich markiert.",
            "Text-Export/-Import arbeitet mit winget-Ids statt Namen. Import \
             installiert exakt (-e), überspringt Kommentarzeilen mit # und meldet, \
             welche Pakete nicht installiert werden konnten.",
            "Tabellen von winget werden sprachunabhängig gelesen (die Kopfzeile wird \
             an der Trennlinie erkannt, nicht mehr am Wort \"Name\"/\"Id\").",
            "Aufgeräumt: gemeinsame Hilfsfunktion für stdout+stderr und ein einziger \
             Status (Busy) statt vieler einzelner Flags. Dabei behoben: Nach einem \
             JSON-Import blieb die Import-Anzeige hängen.",
            "Sprache: Hilfe, alle Fenster, Statusleiste, Fernzugriffs-Meldungen und \
             Terminal-Meldungen gibt es jetzt auch auf Englisch (Burgermenü -> \
             Darstellung). Der Versionsverlauf bleibt deutsch.",
        ],
    },
    AppVersion {
        version: "0.5.0",
        date: "2026-10-19",
        changes: &[
            "Netzwerk-Suche zurück: Beim Start sucht die App automatisch alle PCs im \
             eigenen Netzwerk, auf denen die WingetApp läuft, und zeigt Gerätename, \
             IPv4- und MAC-Adresse sowie Version an - Verbinden mit einem Klick.",
            "Kein separater Agent mehr nötig: Jede geöffnete WingetApp ist gleichzeitig \
             Ziel und Steuerzentrale. Die Suche funktioniert ohne Passwort, Befehle \
             nur nach Anmeldung.",
            "Ferngesteuerte Befehle werden im Klartext angezeigt (z. B. \"Git.Git \
             INSTALLIEREN\"). PCs, die gerade ferngesteuert werden, sind markiert.",
            "App-Name und Version stehen in Titelleiste und Kopfzeile. Neues \
             Protokoll (v3): ältere App-Versionen erscheinen als \"andere App-Version\".",
        ],
    },
    AppVersion {
        version: "0.4.0",
        date: "2026-10-18",
        changes: &[
            "Fernzugriff startet automatisch mit der App - auf dem Ziel-PC muss nur noch \
             die WingetApp geöffnet sein (kein --agent in der Konsole mehr nötig). \
             Abschaltbar im Burgermenü.",
            "Wird ein PC ferngesteuert, zeigt er ein Hinweis-Banner mit dem Namen des \
             Haupt-PCs und sperrt alle Befehle, bis die Verbindung getrennt wird. \
             Verbinden und Trennen erscheinen im Terminal.",
            "Remote-Fenster komplett neu: größer, mit den Reitern \"Updates auswählen\", \
             \"Paket installieren\" (Suche mit automatischen Vorschlägen vom Ziel-PC) und \
             \"Paket deinstallieren\" (filterbare Liste).",
            "Die Ausgabe im Remote-Fenster sagt jetzt genau, welche Programme aktualisiert, \
             installiert oder entfernt wurden - mit verständlichen Fehlertexten.",
            "Neues Design für die ganze App: Kopfleiste, einheitliche Buttons mit Symbolen, \
             farbiges Terminal, Statusleiste mit Fernzugriffs-Anzeige.",
            "Fehler behoben: Bei mehreren lokalen Updates galt der Befehl schon nach dem \
             ersten Paket als fertig; Spinner-Zeichen von winget landeten im Terminal; \
             winget-Aufrufe öffneten Konsolenfenster bzw. konnten auf einem neuen PC an \
             der Quellen-Zustimmung hängen bleiben.",
        ],
    },
    AppVersion {
        version: "0.3.4",
        date: "2026-10-14",
        changes: &[
            "App umbenannt in \"Abk-WingetApp\"; die Version steht jetzt im Fenstertitel und im Kopf.",
            "Neuer Knopf \"PCs im Netzwerk suchen\" im Remote-Fenster: findet alle PCs im gleichen Netzwerk, auf denen die App läuft, und zeigt Gerätename, IPv4- und MAC-Adresse an - per Klick direkt verbinden.",
            "Der Ziel-PC zeigt in der Agent-Konsole jetzt an, welcher Haupt-PC verbunden ist und welchen Befehl er gerade ausführt.",
        ],
    },
    AppVersion {
        version: "0.3.3",
        date: "2026-10-12",
        changes: &[
            "Fehler behoben: Remote-Verbindungen brachen nach ca. 10 Sekunden mit \
             \"os error 10060\" ab. Die Verbindung bleibt jetzt dauerhaft bestehen \
             (Keep-Alive alle 20 Sekunden).",
            "Neuer Button \"Updates auswählen\" im Remote-Fenster: zeigt die \
             verfügbaren Updates des Ziel-PCs als Liste mit Häkchen an und \
             installiert die ausgewählten direkt dort.",
            "Der Agent gibt eine tote Verbindung nach 2 Minuten ohne Lebenszeichen \
             frei, damit man sich danach sofort wieder verbinden kann.",
        ],
    },
    AppVersion {
        version: "0.3.2",
        date: "2026-10-12",
        changes: &[
            "Remote-Verbindung im lokalen Netzwerk vereinfacht: Der Agent zeigt beim \
             Start die IP-Adresse an, die man auf dem anderen PC eintragen muss.",
            "Im Remote-Fenster reicht jetzt die IP-Adresse - der Port 47800 wird \
             automatisch ergänzt. Das Feld startet leer statt mit 127.0.0.1; der \
             Knopf \"Dieser PC\" setzt die lokale Adresse zum Testen.",
            "Der Agent zeigt den PowerShell-Befehl zum Freigeben des Ports in der \
             Windows-Firewall an.",
        ],
    },
    AppVersion {
        version: "0.3.1",
        date: "2026-10-02",
        changes: &[
            "Neuer lila Button \"Remote\" unter den winget-Befehlen auf der Startseite, \
             der das Remote-Fenster öffnet.",
            "Verbindung zu anderen PCs im Netzwerk: Agent mit --agent starten, im \
             Remote-Fenster die IP-Adresse eintragen. Zum Testen gilt das \
             Test-Passwort, solange WINGETAPP_PASSWORD nicht gesetzt ist.",
        ],
    },
    AppVersion {
        version: "0.3.0",
        date: "2026-10-01",
        changes: &[
            "Grundlage für die Fernsteuerung anderer PCs: JSON-Protokoll mit fester \
             Befehls-Whitelist (keine freien Shell-Befehle).",
            "Neuer Agent-Modus (winget-app --agent), der die Befehle auf dem Ziel-PC \
             ausführt und die Ausgabe live zurückstreamt. Vorerst nur lokal erreichbar.",
            "Neues Fenster \"Remote \" im Burgermenü zum Verbinden mit dem Agent.",
        ],
    },
    AppVersion {
        version: "0.2.0",
        date: "2026-09-14",
        changes: &[
            "Paket suchen, installieren, deinstallieren und Details anzeigen haben jetzt \
             jeweils ein eigenes Fenster mit Eingabefeld.",
            "Paket installieren zeigt passende Vorschläge während der Eingabe und einen \
             Fortschrittsbalken während der Installation.",
            "Paket deinstallieren zeigt unter dem Eingabefeld eine filterbare Liste aller \
             installierten Pakete zur direkten Auswahl.",
            "\"Updates auswählen\" zeigt jetzt einen festen Hinweis \"Keine Updates \
             verfügbar\", wenn nichts zu aktualisieren ist.",
            "\"Alle Updates installieren\" zeigt weiterhin die vollständige Liste (alle \
             vorausgewählt) und installiert erst nach einer einmaligen Bestätigung.",
            "Quellen auflisten wurde ins Burgermenü verschoben, Einstellungen öffnen \
             komplett entfernt.",
            "Quellen aktualisieren zeigt jetzt ein eigenes Fenster mit Live-Ausgabe und \
             Fortschrittsanzeige.",
            "Paketliste exportieren/importieren öffnen ein eigenes Fenster zur Auswahl von \
             Pfad und Dateiformat (natives winget-JSON oder einfache Textliste).",
            "Burgermenü enthält jetzt Darstellungs-Einstellungen (Schriftgröße, \
             Akzentfarbe, Sprache) für die gesamte GUI.",
            "Terminal leeren fragt vor dem Löschen erst um Bestätigung.",
            "Die Winget-Befehle rechts sind alphabetisch sortiert. Das Installieren-Fenster sucht Pakete jetzt über die eingerichteten winget-Quellen online und zeigt die Treffer alphabetisch mit Scrollbereich an.",
        ],
    },
    AppVersion {
        version: "0.1.0",
        date: "2026-09-11",
        changes: &[
            "Verlaufs-/Timeline-Ansicht arbeitet jetzt mit einer im Code gepflegten \
             Versionsliste statt mit dem lokalen Git-Verlauf.",
        ],
    },
];

struct WingetApp {
    dark_mode: bool,
    fullscreen: bool,
    background_color: egui::Color32,
    button_color: egui::Color32,

    // --- Dynamisches Design (Burgermenü) ---
    accent_color: egui::Color32,
    font_size: f32,
    language: Language,

    // --- Terminal-Bereich ---
    busy: Busy,
    terminal_lines: Vec<String>,
    tx: Sender<TerminalMsg>,
    rx: Receiver<TerminalMsg>,

    // --- Statusleiste ---
    winget_version: Option<String>,

    // --- Hilfe ---
    show_help: bool,

    // --- Update-Auswahl ---
    show_upgrade_list: bool,
    upgrade_items: Vec<UpgradeItem>,
    upgrades_loaded: bool,
    pending_select_all: bool,

    // --- Verlauf / Timeline ---
    show_timeline: bool,
    remote: remote_ui::RemotePanel,
    selected_timeline_index: Option<usize>,

    // --- Paket suchen ---
    show_search: bool,
    search_query: String,
    search_results: Vec<PackageItem>,
    search_all_results: Vec<PackageItem>,
    search_page: usize,
    search_has_more: bool,

    // --- Paket installieren ---
    show_install: bool,
    install_query: String,
    install_results: Vec<PackageItem>,
    install_all_results: Vec<PackageItem>,
    install_shown: usize,
    install_has_more: bool,

    // --- Paket deinstallieren ---
    show_uninstall: bool,
    uninstall_query: String,
    installed_packages: Vec<PackageItem>,

    // --- Paket-Details ---
    show_details: bool,
    details_query: String,
    details_text: String,

    // --- Quellen aktualisieren (live gestreamt) ---
    show_source_update: bool,
    live_log: Vec<String>,

    // --- Paketliste exportieren ---
    show_export: bool,
    export_path: String,
    export_format: FileFormat,

    // --- Paketliste importieren ---
    show_import: bool,
    import_path: String,
    import_format: FileFormat,

    // --- Terminal leeren: Bestätigung ---
    show_confirm_clear: bool,

    // --- Fernzugriff auf DIESEN PC (Agent läuft in der App mit) ---
    egui_ctx: Option<egui::Context>,
    agent: Option<agent::AgentHandle>,
    agent_tx: Sender<agent::AgentEvent>,
    agent_rx: Receiver<agent::AgentEvent>,
    agent_status: AgentStatus,
    /// Verbindungscode im Klartext anzeigen? Standard: verborgen (Schutz vor
    /// neugierigen Blicken / Bildschirmfreigabe).
    show_code: bool,
    allow_remote: bool,
    /// `Some` = ein Haupt-PC steuert diesen PC -> Bedienung gesperrt.
    remote_session: Option<RemoteSession>,

    // --- Autostart mit Administratorrechten ---
    /// Ist die geplante Aufgabe eingerichtet? `None` = noch nicht geprüft.
    autostart: Option<bool>,
    /// Einrichten/Entfernen läuft gerade (wartet ggf. auf die UAC-Abfrage).
    autostart_busy: bool,
    autostart_tx: Sender<AutostartEvent>,
    autostart_rx: Receiver<AutostartEvent>,
}

impl Default for WingetApp {
    fn default() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        let (agent_tx, agent_rx) = std::sync::mpsc::channel();
        let (autostart_tx, autostart_rx) = std::sync::mpsc::channel();

        {
            let version_tx = tx.clone();
            std::thread::spawn(move || {
                let result = winget().arg("--version").output();
                let text = match result {
                    Ok(output) => {
                        let mut s = String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if s.is_empty() {
                            s = String::from_utf8_lossy(&output.stderr).trim().to_string();
                        }
                        if s.is_empty() {
                            "unbekannt".to_string()
                        } else {
                            s
                        }
                    }
                    Err(_) => "nicht gefunden".to_string(),
                };
                let _ = version_tx.send(TerminalMsg::VersionResult(text));
            });
        }

        let mut app = Self {
            dark_mode: false,
            fullscreen: false,
            background_color: egui::Color32::WHITE,
            button_color: egui::Color32::WHITE,

            accent_color: egui::Color32::from_rgb(40, 110, 220),
            font_size: 16.0,
            language: Language::De,

            busy: Busy::Idle,
            terminal_lines: vec![
                "Herzlich willkommen bei der Abk-WingetApp!".to_string(),
                "Rechts findest du alle Befehle. Bei Fragen hilft der Button \"❓ Hilfe\".".to_string(),
                String::new(),
            ],
            tx,
            rx,
            winget_version: None,
            show_help: false,

            show_upgrade_list: false,
            upgrade_items: Vec::new(),
            upgrades_loaded: false,
            pending_select_all: false,

            show_timeline: false,
            remote: remote_ui::RemotePanel::default(),
            selected_timeline_index: None,

            show_search: false,
            search_query: String::new(),
            search_results: Vec::new(),
            search_all_results: Vec::new(),
            search_page: 0,
            search_has_more: false,

            show_install: false,
            install_query: String::new(),
            install_results: Vec::new(),
            install_all_results: Vec::new(),
            install_shown: 0,
            install_has_more: false,

            show_uninstall: false,
            uninstall_query: String::new(),
            installed_packages: Vec::new(),

            show_details: false,
            details_query: String::new(),
            details_text: String::new(),

            show_source_update: false,
            live_log: Vec::new(),

            show_export: false,
            export_path: String::new(),
            export_format: FileFormat::WingetJson,

            show_import: false,
            import_path: String::new(),
            import_format: FileFormat::WingetJson,

            show_confirm_clear: false,

            egui_ctx: None,
            agent: None,
            agent_tx,
            agent_rx,
            agent_status: AgentStatus::Off,
            show_code: false,
            allow_remote: true,
            remote_session: None,

            autostart: None,
            autostart_busy: false,
            autostart_tx,
            autostart_rx,
        };
        app.set_theme(false);
        app
    }
}

impl WingetApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut app = Self::default();
        app.egui_ctx = Some(cc.egui_ctx.clone());
        app.start_agent();
        // Im Hintergrund nachsehen, ob der Autostart schon eingerichtet ist.
        let tx = app.autostart_tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(AutostartEvent::Status(autostart_task_exists()));
        });
        app
    }

    /// Startet den Agent im Hintergrund: Ab jetzt kann ein anderer PC diesen
    /// PC mit dem Passwort fernsteuern - ohne Konsole und ohne `--agent`.
    fn start_agent(&mut self) {
        if self.agent.is_some() {
            return;
        }
        let tx = Mutex::new(self.agent_tx.clone());
        let ctx = self.egui_ctx.clone();
        let notify: agent::Notify = Arc::new(move |event| {
            let _ = tx.lock().unwrap().send(event);
            if let Some(ctx) = &ctx {
                ctx.request_repaint();
            }
        });
        match agent::start_background(agent::DEFAULT_AGENT_BIND_ADDR, notify) {
            Ok(handle) => self.agent = Some(handle),
            Err(e) => {
                let text = if e.kind() == std::io::ErrorKind::AddrInUse {
                    pick(
                        self.language,
                        format!(
                            "Port {} ist schon belegt - läuft die Abk-WingetApp (oder --agent) bereits?",
                            protocol::DEFAULT_AGENT_PORT
                        ),
                        format!(
                            "Port {} is already in use - is Abk-WingetApp (or --agent) already running?",
                            protocol::DEFAULT_AGENT_PORT
                        ),
                    )
                } else {
                    pick(
                        self.language,
                        format!("Fernzugriff konnte nicht gestartet werden: {e}"),
                        format!("Remote access could not be started: {e}"),
                    )
                };
                self.terminal_lines.push(format!("⚠ {text}"));
                self.agent_status = AgentStatus::Failed(text);
            }
        }
    }

    fn set_remote_allowed(&mut self, allowed: bool) {
        self.allow_remote = allowed;
        if allowed {
            self.start_agent();
        } else {
            // Fallenlassen beendet den Agent.
            self.agent = None;
            self.agent_status = AgentStatus::Off;
            self.note(
                "📡 Fernzugriff auf diesen PC ausgeschaltet.",
                "📡 Remote access to this PC switched off.",
            );
        }
    }

    fn poll_agent_events(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        while let Ok(event) = self.agent_rx.try_recv() {
            match event {
                agent::AgentEvent::Listening {
                    lan_ip,
                    password,
                    admin,
                    fingerprint,
                    ..
                } => {
                    if !admin {
                        self.terminal_lines.push(pick(
                            lang,
                            "⚠ Die App läuft ohne Administratorrechte. Ferngesteuerte Updates wie \
                             Visual C++ oder .NET brauchen dann hier am PC eine Bestätigung per \
                             Mausklick. Abhilfe (einmalig): Burgermenü ☰ -> \"🛡 Mit Adminrechten \
                             automatisch starten\"."
                                .to_string(),
                            "⚠ The app is running without administrator rights. Remote updates such \
                             as Visual C++ or .NET will then need a click on this PC. Fix (once): \
                             burger menu ☰ -> \"🛡 Start automatically with admin rights\"."
                                .to_string(),
                        ));
                    }
                    self.agent_status = AgentStatus::Listening {
                        ip: lan_ip,
                        password,
                        admin,
                        fingerprint,
                    };
                }
                agent::AgentEvent::Connected { peer, controller } => {
                    self.terminal_lines.push(pick(
                        lang,
                        format!(
                            "🔒 {controller} ({}) hat sich verbunden und steuert jetzt diesen PC. \
                             Die Bedienung ist gesperrt, bis die Verbindung getrennt wird.",
                            peer.ip()
                        ),
                        format!(
                            "🔒 {controller} ({}) connected and is now controlling this PC. \
                             Controls are locked until the connection is closed.",
                            peer.ip()
                        ),
                    ));
                    self.remote_session = Some(RemoteSession {
                        controller,
                        ip: peer.ip(),
                        current: None,
                    });
                    ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                        egui::UserAttentionType::Informational,
                    ));
                }
                agent::AgentEvent::Disconnected { reason, .. } => {
                    if let Some(session) = self.remote_session.take() {
                        let reason = reason.trim_end_matches('.').to_string() + ".";
                        self.terminal_lines.push(pick(
                            lang,
                            format!(
                                "🔓 Verbindung zu {} beendet: {reason} Die App ist wieder freigegeben.",
                                session.controller
                            ),
                            format!(
                                "🔓 Connection to {} closed: {reason} The app is unlocked again.",
                                session.controller
                            ),
                        ));
                        self.terminal_lines.push(String::new());
                    }
                }
                agent::AgentEvent::AuthFailed { peer } => {
                    self.terminal_lines.push(pick(
                        lang,
                        format!(
                            "⚠ Verbindungsversuch von {} mit falschem Passwort abgelehnt.",
                            peer.ip()
                        ),
                        format!(
                            "⚠ Connection attempt from {} rejected: wrong password.",
                            peer.ip()
                        ),
                    ));
                }
                agent::AgentEvent::Refused { peer, reason } => {
                    self.terminal_lines.push(pick(
                        lang,
                        format!("⚠ Verbindung von {} abgelehnt: {reason}", peer.ip()),
                        format!("⚠ Connection from {} refused: {reason}", peer.ip()),
                    ));
                }
                agent::AgentEvent::JobStarted { description } => {
                    self.terminal_lines.push(pick(
                        lang,
                        format!("↳ Ferngesteuert: {description}"),
                        format!("↳ Remote-controlled: {description}"),
                    ));
                    if let Some(session) = &mut self.remote_session {
                        session.current = Some(description);
                    }
                }
                agent::AgentEvent::JobFinished { success } => {
                    if let Some(session) = &mut self.remote_session {
                        session.current = None;
                    }
                    if !success {
                        self.note(
                            "↳ Ferngesteuerter Befehl mit Fehler beendet.",
                            "↳ Remote-controlled command finished with an error.",
                        );
                    }
                }
                agent::AgentEvent::Stopped => {
                    if !self.allow_remote {
                        self.agent_status = AgentStatus::Off;
                    }
                }
            }
        }
    }

    /// Schreibt winget-Ausgabe ins Terminal, ohne Spinner und Fortschrittsbalken.
    fn push_output_lines(&mut self, text: &str) {
        for line in text.lines() {
            let line = visible_part(line).trim_end();
            if !line.is_empty() && !is_noise_line(line) {
                self.terminal_lines.push(line.to_string());
            }
        }
    }

    /// Einheitliches, modernes Erscheinungsbild für die ganze App.
    fn apply_style(&self, ctx: &egui::Context) {
        let accent = self.accent_color;
        let mut visuals = if self.dark_mode {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        // Nicht zu rund, sonst werden Häkchen-Kästchen zu Kreisen.
        let rounding = egui::Rounding::same(5.0);
        visuals.window_rounding = egui::Rounding::same(12.0);
        visuals.menu_rounding = egui::Rounding::same(8.0);
        visuals.widgets.noninteractive.rounding = rounding;
        visuals.widgets.inactive.rounding = rounding;
        visuals.widgets.hovered.rounding = rounding;
        visuals.widgets.active.rounding = rounding;
        visuals.widgets.open.rounding = rounding;
        visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.5_f32, accent);
        visuals.hyperlink_color = accent;
        visuals.window_stroke = egui::Stroke::new(1.0_f32, accent.gamma_multiply(0.45));

        if self.dark_mode {
            visuals.panel_fill = Color32::from_rgb(30, 32, 38);
            visuals.window_fill = Color32::from_rgb(36, 38, 45);
            visuals.extreme_bg_color = Color32::from_rgb(20, 21, 25);
            visuals.faint_bg_color = Color32::from_rgb(42, 45, 53);
            visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(50, 54, 63);
            visuals.widgets.inactive.bg_fill = Color32::from_rgb(50, 54, 63);
            visuals.widgets.inactive.bg_stroke =
                egui::Stroke::new(1.0_f32, Color32::from_rgb(98, 104, 118));
            visuals.selection.bg_fill = accent.gamma_multiply(0.7);
            visuals.selection.stroke = egui::Stroke::new(1.0_f32, Color32::WHITE);
        } else {
            visuals.panel_fill = Color32::from_rgb(244, 246, 249);
            visuals.window_fill = Color32::WHITE;
            visuals.extreme_bg_color = Color32::WHITE;
            visuals.faint_bg_color = Color32::from_rgb(236, 239, 244);
            visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(226, 230, 237);
            visuals.widgets.inactive.bg_fill = Color32::from_rgb(226, 230, 237);
            // Sichtbarer Rand für Kästchen und Eingabefelder im hellen Design.
            visuals.widgets.inactive.bg_stroke =
                egui::Stroke::new(1.0_f32, Color32::from_rgb(176, 183, 194));
            visuals.selection.bg_fill = accent.gamma_multiply(0.35);
            visuals.selection.stroke = egui::Stroke::new(1.0_f32, accent);
        }

        let mut style = (*ctx.style()).clone();
        style.visuals = visuals;
        let fs = self.font_size;
        style.text_styles.insert(
            egui::TextStyle::Body,
            egui::FontId::new(fs, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            egui::FontId::new(fs, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Heading,
            egui::FontId::new(fs + 6.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Monospace,
            egui::FontId::new(fs - 2.0, egui::FontFamily::Monospace),
        );
        style.text_styles.insert(
            egui::TextStyle::Small,
            egui::FontId::new(fs - 3.0, egui::FontFamily::Proportional),
        );
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 6.0);
        style.spacing.interact_size.y = 28.0;
        ctx.set_style(style);
    }

    fn t(&self, de: &'static str, en: &'static str) -> &'static str {
        pick(self.language, de, en)
    }

    /// Hängt eine (übersetzte) Zeile ans Terminal an.
    /// Richtet den Autostart mit Administratorrechten ein (im Hintergrund, weil
    /// auf die UAC-Abfrage gewartet wird).
    fn setup_autostart(&mut self) {
        if self.autostart_busy {
            return;
        }
        self.autostart_busy = true;
        self.note(
            "🛡 Richte \"Mit Adminrechten automatisch starten\" ein - bitte die Windows-Abfrage einmal mit \"Ja\" bestätigen ...",
            "🛡 Setting up \"start automatically with admin rights\" - please confirm the Windows prompt once with \"Yes\" ...",
        );
        let tx = self.autostart_tx.clone();
        let ctx = self.egui_ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(AutostartEvent::Installed(install_autostart()));
            if let Some(ctx) = ctx {
                ctx.request_repaint();
            }
        });
    }

    fn teardown_autostart(&mut self) {
        if self.autostart_busy {
            return;
        }
        self.autostart_busy = true;
        let tx = self.autostart_tx.clone();
        let ctx = self.egui_ctx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(AutostartEvent::Removed(remove_autostart()));
            if let Some(ctx) = ctx {
                ctx.request_repaint();
            }
        });
    }

    fn poll_autostart(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        while let Ok(event) = self.autostart_rx.try_recv() {
            match event {
                AutostartEvent::Status(exists) => self.autostart = Some(exists),
                AutostartEvent::Installed(Ok(())) => {
                    self.autostart_busy = false;
                    self.autostart = Some(true);
                    if protocol::is_elevated() {
                        self.note(
                            "✔ Eingerichtet: Die App startet ab jetzt bei jeder Anmeldung mit Administratorrechten.",
                            "✔ Done: from now on the app starts with administrator rights at every sign-in.",
                        );
                        continue;
                    }
                    // Gleich mit Adminrechten neu starten - über die Aufgabe, also
                    // ohne weitere Abfrage. Vorher den Port freigeben.
                    self.note(
                        "✔ Eingerichtet. Die App startet jetzt mit Administratorrechten neu ...",
                        "✔ Done. The app now restarts with administrator rights ...",
                    );
                    self.agent = None;
                    match run_autostart_task() {
                        Ok(()) => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
                        Err(e) => {
                            self.terminal_lines.push(pick(
                                lang,
                                format!("⚠ Neustart fehlgeschlagen ({e}). Bitte die App einmal schließen und neu öffnen."),
                                format!("⚠ Restart failed ({e}). Please close and reopen the app once."),
                            ));
                            if self.allow_remote {
                                self.start_agent();
                            }
                        }
                    }
                }
                AutostartEvent::Installed(Err(e)) => {
                    self.autostart_busy = false;
                    self.terminal_lines.push(pick(
                        lang,
                        format!("✖ Autostart mit Adminrechten nicht eingerichtet: {e}"),
                        format!("✖ Start with admin rights was not set up: {e}"),
                    ));
                }
                AutostartEvent::Removed(result) => {
                    self.autostart_busy = false;
                    match result {
                        Ok(()) => {
                            self.autostart = Some(false);
                            self.note(
                                "✔ Autostart mit Adminrechten entfernt.",
                                "✔ Start with admin rights removed.",
                            );
                        }
                        Err(e) => self.terminal_lines.push(pick(
                            lang,
                            format!("✖ Autostart konnte nicht entfernt werden: {e}"),
                            format!("✖ Could not remove the autostart: {e}"),
                        )),
                    }
                }
            }
        }
        if self.autostart_busy {
            ctx.request_repaint_after(Duration::from_millis(300));
        }
    }

    fn note(&mut self, de: &'static str, en: &'static str) {
        let line = self.t(de, en).to_string();
        self.terminal_lines.push(line);
    }

    fn warn_busy(&mut self) {
        self.note(
            "⚠ Es läuft bereits ein Befehl, bitte warten...",
            "⚠ A command is already running, please wait...",
        );
    }

    fn set_theme(&mut self, dark_mode: bool) {
        self.dark_mode = dark_mode;
        if dark_mode {
            self.background_color = egui::Color32::from_rgb(24, 25, 31);
            self.button_color = egui::Color32::from_rgb(55, 58, 66);
        } else {
            self.background_color = egui::Color32::from_rgb(240, 242, 245);
            self.button_color = egui::Color32::from_rgb(220, 224, 230);
        }
    }

    fn run_winget_command(&mut self, cmd: &WingetCommand) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }

        let args: Vec<String> = cmd.args.iter().map(|s| s.to_string()).collect();
        let display = format!("$ winget {}", args.join(" "));

        self.busy = Busy::Command;
        let tx = self.tx.clone();
        let _ = tx.send(TerminalMsg::Started(display));

        let lang = self.language;
        std::thread::spawn(move || {
            let result = winget().args(&args).output();

            let msg = match result {
                Ok(output) => {
                    let mut text = combine_output(&output);
                    if text.trim().is_empty() {
                        text = pick(lang, "(keine Ausgabe)", "(no output)").to_string();
                    }
                    TerminalMsg::Output { text, success: output.status.success() }
                }
                Err(e) => TerminalMsg::Output {
                    text: pick(
                            lang,
                            format!("Fehler beim Ausführen von winget: {e}"),
                            format!("Error running winget: {e}"),
                        ),
                    success: false,
                },
            };

            let _ = tx.send(msg);
        });
    }

    fn run_list_upgrades(&mut self) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }

        self.busy = Busy::ListUpgrades;
        let tx = self.tx.clone();
        let _ = tx.send(TerminalMsg::Started("$ winget upgrade".to_string()));

        let lang = self.language;
        std::thread::spawn(move || {
            let result = winget().args(["upgrade", "--accept-source-agreements"]).output();

            match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let items = parse_upgrade_output(&stdout);

                    let mut text = combine_output(&output);
                    if text.trim().is_empty() {
                        text = pick(lang, "(keine Ausgabe)", "(no output)").to_string();
                    }

                    let _ = tx.send(TerminalMsg::Output { text, success: output.status.success() });
                    let _ = tx.send(TerminalMsg::UpgradeList(items));
                }
                Err(e) => {
                    let _ = tx.send(TerminalMsg::Output {
                        text: pick(
                            lang,
                            format!("Fehler beim Ausführen von winget: {e}"),
                            format!("Error running winget: {e}"),
                        ),
                        success: false,
                    });
                    let _ = tx.send(TerminalMsg::UpgradeList(Vec::new()));
                }
            }
        });
    }

    fn install_selected_upgrades(&mut self) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }

        let selected: Vec<(String, String)> = self
            .upgrade_items
            .iter()
            .filter(|item| item.selected)
            .map(|item| (item.id.clone(), item.name.clone()))
            .collect();

        if selected.is_empty() {
            self.note(
                "⚠ Es wurde kein Programm zum Aktualisieren ausgewählt.",
                "⚠ No program was selected for updating.",
            );
            return;
        }

        self.busy = Busy::InstallUpgrades;
        self.show_upgrade_list = false;
        let tx = self.tx.clone();

        let lang = self.language;
        std::thread::spawn(move || {
            let mut done: Vec<String> = Vec::new();
            let mut failed: Vec<String> = Vec::new();
            for (id, name) in selected {
                let display = format!("$ winget upgrade --id {id} -e");
                let _ = tx.send(TerminalMsg::Started(display));

                let result = winget()
                    .args([
                        "upgrade",
                        "--id",
                        &id,
                        "-e",
                        "--silent",
                        "--accept-package-agreements",
                        "--accept-source-agreements",
                        "--disable-interactivity",
                    ])
                    .output();

                // Zwischenergebnis: beendet den Gesamt-Befehl noch NICHT
                // (vorher wurde "running" schon nach dem ersten Paket
                // zurückgesetzt, obwohl noch Updates liefen).
                let msg = match result {
                    Ok(output) => {
                        let text = combine_output(&output);
                        let code = output.status.code();
                        let why = protocol::describe_exit_code(code);
                        let summary = match protocol::classify_exit(output.status.success(), code) {
                            protocol::Outcome::Ok => {
                                done.push(name.clone());
                                pick(lang, format!("✔ {name} aktualisiert"), format!("✔ {name} updated"))
                            }
                            protocol::Outcome::OkNeedsRestart => {
                                done.push(name.clone());
                                pick(
                                    lang,
                                    format!("✔ {name} aktualisiert - {why}"),
                                    format!("✔ {name} updated - restart required ({why})"),
                                )
                            }
                            protocol::Outcome::Failed => {
                                failed.push(format!("{name} ({why})"));
                                pick(
                                    lang,
                                    format!("✖ {name} wurde nicht aktualisiert - {why}"),
                                    format!("✖ {name} was not updated - {why}"),
                                )
                            }
                        };
                        TerminalMsg::Progress { text, summary }
                    }
                    Err(e) => {
                        failed.push(name.clone());
                        TerminalMsg::Progress {
                            text: String::new(),
                            summary: pick(lang, format!("✖ Fehler beim Aktualisieren von {name}: {e}"), format!("✖ Error updating {name}: {e}")),
                        }
                    }
                };
                let _ = tx.send(msg);
            }
            let text = if failed.is_empty() {
                pick(
                    lang,
                    format!("━━ Fertig: {} Update(s) installiert: {}", done.len(), done.join(", ")),
                    format!("━━ Done: {} update(s) installed: {}", done.len(), done.join(", ")),
                )
            } else {
                pick(
                    lang,
                    format!(
                        "━━ Fertig: {} von {} Update(s) installiert. Nicht aktualisiert: {}",
                        done.len(),
                        done.len() + failed.len(),
                        failed.join("; ")
                    ),
                    format!(
                        "━━ Done: {} of {} update(s) installed. Not updated: {}",
                        done.len(),
                        done.len() + failed.len(),
                        failed.join("; ")
                    ),
                )
            };
            let _ = tx.send(TerminalMsg::Output {
                text,
                success: failed.is_empty(),
            });
        });
    }

    fn load_demo_upgrades(&mut self) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }

        let demo_items = vec![
            UpgradeItem {
                name: "Google Chrome".to_string(),
                id: "Google.Chrome".to_string(),
                installed_version: "124.0.6367.91".to_string(),
                available_version: "126.0.6478.63".to_string(),
                source: "winget".to_string(),
                selected: false,
            },
            UpgradeItem {
                name: "7-Zip".to_string(),
                id: "7zip.7zip".to_string(),
                installed_version: "23.01".to_string(),
                available_version: "24.07".to_string(),
                source: "winget".to_string(),
                selected: false,
            },
            UpgradeItem {
                name: "Visual Studio Code".to_string(),
                id: "Microsoft.VisualStudioCode".to_string(),
                installed_version: "1.88.1".to_string(),
                available_version: "1.90.0".to_string(),
                source: "winget".to_string(),
                selected: false,
            },
            UpgradeItem {
                name: "VLC media player".to_string(),
                id: "VideoLAN.VLC".to_string(),
                installed_version: "3.0.18".to_string(),
                available_version: "3.0.20".to_string(),
                source: "winget".to_string(),
                selected: false,
            },
            UpgradeItem {
                name: "Mozilla Firefox".to_string(),
                id: "Mozilla.Firefox".to_string(),
                installed_version: "115.0".to_string(),
                available_version: "127.0".to_string(),
                source: "winget".to_string(),
                selected: false,
            },
        ];

        self.terminal_lines.push(
            "🎬 Testmodus: Beispiel-Updates geladen (kein echter winget-Aufruf).".to_string(),
        );
        self.terminal_lines.push(String::new());
        self.upgrade_items = demo_items;
        self.upgrades_loaded = true;
        self.show_upgrade_list = true;
    }

    fn run_search(&mut self) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }

        let query = self.search_query.trim().to_string();
        self.search_results.clear();
        self.search_all_results.clear();
        self.search_page = 0;
        self.search_has_more = false;
        self.busy = Busy::Search;
        let tx = self.tx.clone();
        let display = if query.is_empty() {
            "$ winget search".to_string()
        } else {
            format!("$ winget search {query}")
        };
        let _ = tx.send(TerminalMsg::Started(display));

        let filter_query = query.to_lowercase();

        let lang = self.language;
        std::thread::spawn(move || {
            let mut args = vec!["search".to_string()];
            if !query.is_empty() {
                args.push(query);
            } else {
                args.push("--query".to_string());
                args.push("".to_string());
            }
            args.push("--count".to_string());
            args.push("50".to_string());
            args.push("--accept-source-agreements".to_string());
            let result = winget().args(&args).output();
            match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let mut items = parse_package_table(&stdout);
                    if !filter_query.is_empty() {
                        items.retain(|item| item.name.to_lowercase().starts_with(&filter_query));
                    }
                    let result_count = items.len();
                    let success = output.status.success();
                    let text = if success {
                        pick(lang, format!("✔ Paketsuche abgeschlossen: {result_count} Treffer geladen (max. 50 pro Seite)."), format!("✔ Package search finished: {result_count} results loaded (max. 50 per page)."))
                    } else {
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        if stderr.trim().is_empty() {
                            pick(lang, format!("✖ Paketsuche fehlgeschlagen ({result_count} Treffer konnten gelesen werden)."), format!("✖ Package search failed ({result_count} results could be read)."))
                        } else {
                            pick(lang, format!("✖ Paketsuche fehlgeschlagen: {}", stderr.trim()), format!("✖ Package search failed: {}", stderr.trim()))
                        }
                    };
                    let _ = tx.send(TerminalMsg::Output { text, success });
                    let _ = tx.send(TerminalMsg::SearchResult(items));
                }
                Err(e) => {
                    let _ = tx.send(TerminalMsg::Output {
                        text: pick(
                            lang,
                            format!("Fehler beim Ausführen von winget: {e}"),
                            format!("Error running winget: {e}"),
                        ),
                        success: false,
                    });
                    let _ = tx.send(TerminalMsg::SearchResult(Vec::new()));
                }
            }
        });
    }

    fn run_load_installed(&mut self) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }

        self.busy = Busy::LoadInstalled;
        let tx = self.tx.clone();
        let _ = tx.send(TerminalMsg::Started("$ winget list".to_string()));

        let lang = self.language;
        std::thread::spawn(move || {
            let result = winget().args(["list", "--accept-source-agreements"]).output();
            match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let items = parse_package_table(&stdout);
                    let mut text = combine_output(&output);
                    if text.trim().is_empty() {
                        text = pick(lang, "(keine Ausgabe)", "(no output)").to_string();
                    }
                    let _ = tx.send(TerminalMsg::Output { text, success: output.status.success() });
                    let _ = tx.send(TerminalMsg::InstalledList(items));
                }
                Err(e) => {
                    let _ = tx.send(TerminalMsg::Output {
                        text: pick(
                            lang,
                            format!("Fehler beim Ausführen von winget: {e}"),
                            format!("Error running winget: {e}"),
                        ),
                        success: false,
                    });
                    let _ = tx.send(TerminalMsg::InstalledList(Vec::new()));
                }
            }
        });
    }

    fn run_install_search(&mut self) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }

        let query = self.install_query.trim().to_string();
        if query.is_empty() {
            self.note(
                "⚠ Bitte zuerst einen Paketnamen oder Suchbegriff eingeben.",
                "⚠ Please enter a package name or search term first.",
            );
            return;
        }

        self.busy = Busy::InstallSearch;
        self.install_results.clear();
        self.install_all_results.clear();
        self.install_shown = 0;
        self.install_has_more = false;

        let tx = self.tx.clone();
        let display = format!("$ winget search {query}");
        let _ = tx.send(TerminalMsg::Started(display));

        let lang = self.language;
        std::thread::spawn(move || {
            let result = winget()
                .args(["search", &query, "--accept-source-agreements"])
                .output();

            match result {
                Ok(output) => {
                    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                    let items = parse_package_table(&stdout);

                    let mut text = combine_output(&output);
                    if text.trim().is_empty() {
                        text = pick(lang, "(keine Suchergebnisse)", "(no search results)").to_string();
                    }

                    let _ = tx.send(TerminalMsg::Output {
                        text,
                        success: output.status.success(),
                    });
                    let _ = tx.send(TerminalMsg::InstallSearchResult(items));
                }
                Err(e) => {
                    let _ = tx.send(TerminalMsg::Output {
                        text: pick(lang, format!("Fehler bei der Online-Paketsuche: {e}"), format!("Error during online package search: {e}")),
                        success: false,
                    });
                    let _ = tx.send(TerminalMsg::InstallSearchResult(Vec::new()));
                }
            }
        });
    }

    fn run_install(&mut self) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }
        let query = self.install_query.trim().to_string();
        if query.is_empty() {
            self.note(
                "⚠ Bitte zuerst ein Paket eingeben, das installiert werden soll.",
                "⚠ Please enter the package to install first.",
            );
            return;
        }

        self.busy = Busy::Installing;
        let tx = self.tx.clone();
        let display = format!("$ winget install {query}");
        let _ = tx.send(TerminalMsg::Started(display));

        let lang = self.language;
        std::thread::spawn(move || {
            let result = winget()
                .args([
                    "install",
                    &query,
                    "-e",
                    "--silent",
                    "--accept-package-agreements",
                    "--accept-source-agreements",
                    "--disable-interactivity",
                ])
                .output();

            let msg = match result {
                Ok(output) => {
                    let mut text = combine_output(&output);
                    if text.trim().is_empty() {
                        text = pick(lang, "(keine Ausgabe)", "(no output)").to_string();
                    }
                    TerminalMsg::Output { text, success: output.status.success() }
                }
                Err(e) => TerminalMsg::Output {
                    text: pick(lang, format!("Fehler bei der Installation: {e}"), format!("Installation error: {e}")),
                    success: false,
                },
            };
            let _ = tx.send(msg);
        });
    }

    fn run_uninstall(&mut self, id: String, name: String) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }

        self.busy = Busy::Uninstalling;
        let tx = self.tx.clone();
        let display = format!("$ winget uninstall --id {id} -e");
        let _ = tx.send(TerminalMsg::Started(display));

        let lang = self.language;
        std::thread::spawn(move || {
            let result = winget()
                .args([
                    "uninstall",
                    "--id",
                    &id,
                    "-e",
                    "--silent",
                    "--accept-source-agreements",
                    "--disable-interactivity",
                ])
                .output();

            let msg = match result {
                Ok(output) => {
                    let mut text = combine_output(&output);
                    if text.trim().is_empty() {
                        text = pick(lang, format!("(keine Ausgabe für {name})"), format!("(no output for {name})"));
                    }
                    TerminalMsg::Output { text, success: output.status.success() }
                }
                Err(e) => TerminalMsg::Output {
                    text: pick(lang, format!("Fehler beim Deinstallieren von {name}: {e}"), format!("Error uninstalling {name}: {e}")),
                    success: false,
                },
            };
            let _ = tx.send(msg);
        });
    }

    fn run_details(&mut self) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }
        let query = self.details_query.trim().to_string();
        if query.is_empty() {
            self.note(
                "⚠ Bitte zuerst ein Paket eingeben, dessen Details angezeigt werden sollen.",
                "⚠ Please enter the package whose details you want to see.",
            );
            return;
        }

        self.busy = Busy::Details;
        self.details_text.clear();
        let tx = self.tx.clone();
        let display = format!("$ winget show {query}");
        let _ = tx.send(TerminalMsg::Started(display));

        let lang = self.language;
        std::thread::spawn(move || {
            let result = winget().args(["show", &query, "--accept-source-agreements"]).output();
            match result {
                Ok(output) => {
                    let mut text = combine_output(&output);
                    if text.trim().is_empty() {
                        text = pick(lang, "(keine Details gefunden)", "(no details found)").to_string();
                    }
                    let _ = tx.send(TerminalMsg::DetailsResult(text.clone()));
                    let _ = tx.send(TerminalMsg::Output { text, success: output.status.success() });
                }
                Err(e) => {
                    let err_text = pick(lang, format!("Fehler beim Abrufen der Details: {e}"), format!("Error fetching details: {e}"));
                    let _ = tx.send(TerminalMsg::DetailsResult(err_text.clone()));
                    let _ = tx.send(TerminalMsg::Output { text: err_text, success: false });
                }
            }
        });
    }

    fn run_source_update(&mut self) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }

        self.busy = Busy::SourceUpdate;
        self.live_log.clear();
        let tx = self.tx.clone();
        let _ = tx.send(TerminalMsg::Started("$ winget source update".to_string()));

        let lang = self.language;
        std::thread::spawn(move || {
            let child = winget()
                .args(["source", "update"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();

            match child {
                Ok(mut child) => {
                    // stderr parallel lesen, sonst kann ein voller Puffer
                    // winget blockieren.
                    if let Some(stderr) = child.stderr.take() {
                        let tx_err = tx.clone();
                        std::thread::spawn(move || {
                            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                                let _ = tx_err.send(TerminalMsg::StreamLine(line));
                            }
                        });
                    }
                    if let Some(stdout) = child.stdout.take() {
                        let reader = BufReader::new(stdout);
                        for line in reader.lines().map_while(Result::ok) {
                            let _ = tx.send(TerminalMsg::StreamLine(line));
                        }
                    }
                    let status = child.wait();
                    let success = matches!(status, Ok(s) if s.success());
                    let _ = tx.send(TerminalMsg::StreamDone { success });
                }
                Err(e) => {
                    let _ = tx.send(TerminalMsg::StreamLine(pick(lang, format!("Fehler: {e}"), format!("Error: {e}"))));
                    let _ = tx.send(TerminalMsg::StreamDone { success: false });
                }
            }
        });
    }

    fn run_export(&mut self) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }
        let path = self.export_path.trim().to_string();
        if path.is_empty() {
            self.note(
                "⚠ Bitte zuerst einen Zielpfad für den Export angeben.",
                "⚠ Please enter a target path for the export first.",
            );
            return;
        }

        self.busy = Busy::Export;
        let format = self.export_format;
        let tx = self.tx.clone();
        let _ = tx.send(TerminalMsg::Started(pick(self.language, format!("$ Paketliste exportieren nach {path}"), format!("$ Export package list to {path}"))));

        let lang = self.language;
        std::thread::spawn(move || match format {
            FileFormat::WingetJson => {
                let result = winget()
                    .args(["export", "-o", &path, "--accept-source-agreements"])
                    .output();
                let msg = match result {
                    Ok(output) => {
                        let mut text = combine_output(&output);
                        if text.trim().is_empty() {
                            text = pick(lang, format!("✔ Paketliste als JSON nach {path} exportiert."), format!("✔ Package list exported to {path} as JSON."));
                        }
                        TerminalMsg::Output { text, success: output.status.success() }
                    }
                    Err(e) => TerminalMsg::Output {
                        text: pick(lang, format!("Fehler beim Export: {e}"), format!("Export error: {e}")),
                        success: false,
                    },
                };
                let _ = tx.send(msg);
            }
            FileFormat::TextList => {
                let result = winget().args(["list", "--accept-source-agreements"]).output();
                let msg = match result {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                        let items = parse_package_table(&stdout);
                        // Ids statt Namen: Namen sind mehrdeutig und passen oft
                        // nicht zu dem, was `winget install` erwartet.
                        let ids: Vec<&str> = items
                            .iter()
                            .map(|i| i.id.as_str())
                            .filter(|id| is_package_id(id))
                            .collect();
                        let skipped = items.len() - ids.len();
                        let content = format!(
                            "# WingetApp-Paketliste: eine winget-Id pro Zeile\n{}\n",
                            ids.join("\n")
                        );
                        match std::fs::write(&path, content) {
                            Ok(_) => TerminalMsg::Output {
                                text: pick(
                                    lang,
                                    format!(
                                        "✔ {} Pakete (Ids) als Textliste nach {} exportiert. {} Einträge ohne winget-Id wurden übersprungen.",
                                        ids.len(), path, skipped
                                    ),
                                    format!(
                                        "✔ {} packages (IDs) exported to {} as a text list. {} entries without a winget ID were skipped.",
                                        ids.len(), path, skipped
                                    ),
                                ),
                                success: true,
                            },
                            Err(e) => TerminalMsg::Output {
                                text: pick(lang, format!("Fehler beim Schreiben der Datei: {e}"), format!("Error writing the file: {e}")),
                                success: false,
                            },
                        }
                    }
                    Err(e) => TerminalMsg::Output {
                        text: pick(lang, format!("Fehler beim Ermitteln der Paketliste: {e}"), format!("Error reading the package list: {e}")),
                        success: false,
                    },
                };
                let _ = tx.send(msg);
            }
        });
    }

    fn run_import(&mut self) {
        if self.busy.is_active() {
            self.warn_busy();
            return;
        }
        let path = self.import_path.trim().to_string();
        if path.is_empty() {
            self.note(
                "⚠ Bitte zuerst eine Quelldatei für den Import angeben.",
                "⚠ Please enter a source file for the import first.",
            );
            return;
        }

        self.busy = Busy::Import;
        self.live_log.clear();
        let format = self.import_format;
        let tx = self.tx.clone();
        let _ = tx.send(TerminalMsg::Started(pick(self.language, format!("$ Paketliste importieren aus {path}"), format!("$ Import package list from {path}"))));

        let lang = self.language;
        std::thread::spawn(move || match format {
            FileFormat::WingetJson => {
                let result = winget()
                    .args([
                        "import",
                        "-i",
                        &path,
                        "--accept-package-agreements",
                        "--accept-source-agreements",
                    ])
                    .output();
                let msg = match result {
                    Ok(output) => {
                        let mut text = combine_output(&output);
                        if text.trim().is_empty() {
                            text = pick(lang, "(keine Ausgabe)", "(no output)").to_string();
                        }
                        TerminalMsg::Output { text, success: output.status.success() }
                    }
                    Err(e) => TerminalMsg::Output {
                        text: pick(lang, format!("Fehler beim Import: {e}"), format!("Import error: {e}")),
                        success: false,
                    },
                };
                let _ = tx.send(msg);
            }
            FileFormat::TextList => {
                match std::fs::read_to_string(&path) {
                    Ok(content) => {
                        let entries: Vec<String> = content
                            .lines()
                            .map(|l| l.trim().to_string())
                            .filter(|l| !l.is_empty() && !l.starts_with('#'))
                            .collect();
                        let mut failed: Vec<String> = Vec::new();
                        for entry in &entries {
                            let _ = tx.send(TerminalMsg::StreamLine(pick(
                                lang,
                                format!("→ Installiere {entry} ..."),
                                format!("→ Installing {entry} ..."),
                            )));
                            // Ids exakt installieren (-e). Alte Listen mit reinen
                            // Namen funktionieren weiter, sind aber mehrdeutig.
                            let mut args: Vec<&str> = vec!["install"];
                            if is_package_id(entry) {
                                args.extend(["--id", entry.as_str(), "-e"]);
                            } else {
                                args.push(entry.as_str());
                                let _ = tx.send(TerminalMsg::StreamLine(
                                    pick(
                                        lang,
                                        "  ⚠ Das ist keine winget-Id, das Paket wird über den Namen gesucht (kann mehrdeutig sein).",
                                        "  ⚠ This is not a winget ID, the package is looked up by name (may be ambiguous).",
                                    )
                                    .to_string(),
                                ));
                            }
                            args.extend([
                                "--silent",
                                "--accept-package-agreements",
                                "--accept-source-agreements",
                                "--disable-interactivity",
                            ]);
                            match winget().args(&args).output() {
                                Ok(output) => {
                                    let _ = tx.send(TerminalMsg::StreamLine(combine_output(&output)));
                                    if !output.status.success() {
                                        failed.push(entry.clone());
                                    }
                                }
                                Err(e) => {
                                    failed.push(entry.clone());
                                    let _ = tx.send(TerminalMsg::StreamLine(pick(
                                        lang,
                                        format!("Fehler bei {entry}: {e}"),
                                        format!("Error with {entry}: {e}"),
                                    )));
                                }
                            }
                        }
                        if !failed.is_empty() {
                            let _ = tx.send(TerminalMsg::StreamLine(pick(
                                lang,
                                format!("✖ Nicht installiert: {}", failed.join(", ")),
                                format!("✖ Not installed: {}", failed.join(", ")),
                            )));
                        }
                        let _ = tx.send(TerminalMsg::StreamDone { success: failed.is_empty() });
                    }
                    Err(e) => {
                        let _ = tx.send(TerminalMsg::StreamLine(pick(
                            lang,
                            format!("Fehler beim Lesen der Datei: {e}"),
                            format!("Error reading the file: {e}"),
                        )));
                        let _ = tx.send(TerminalMsg::StreamDone { success: false });
                    }
                }
            }
        });
    }

    fn poll_terminal_messages(&mut self, ctx: &egui::Context) {
        let mut received_any = false;
        while let Ok(msg) = self.rx.try_recv() {
            received_any = true;
            match msg {
                TerminalMsg::Started(line) => {
                    self.terminal_lines.push(line);
                }
                TerminalMsg::Progress { text, summary } => {
                    self.push_output_lines(&text);
                    self.terminal_lines.push(summary);
                }
                TerminalMsg::Output { text, success } => {
                    self.push_output_lines(&text);
                    self.terminal_lines.push(if success {
                        self.t("✔ Befehl abgeschlossen.", "✔ Command finished.").to_string()
                    } else {
                        self.t("✖ Befehl mit Fehler beendet.", "✖ Command finished with an error.").to_string()
                    });
                    self.terminal_lines.push(String::new());
                    self.busy = Busy::Idle;
                }
                TerminalMsg::VersionResult(version) => {
                    self.winget_version = Some(version);
                }
                TerminalMsg::UpgradeList(items) => {
                    let mut items = items;
                    if self.pending_select_all {
                        for item in &mut items {
                            item.selected = true;
                        }
                        self.pending_select_all = false;
                    }
                    self.upgrade_items = items;
                    self.upgrades_loaded = true;
                    self.show_upgrade_list = true;
                }
                TerminalMsg::SearchResult(mut items) => {
                    items.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
                    self.search_all_results = items;
                    self.search_page = 0;
                    self.search_results = self
                        .search_all_results
                        .iter()
                        .take(SEARCH_PAGE_SIZE)
                        .cloned()
                        .collect();
                    self.search_has_more = self.search_all_results.len() > SEARCH_PAGE_SIZE;
                }
                TerminalMsg::InstallSearchResult(mut items) => {
                    let query_lower = self.install_query.trim().to_lowercase();
                    items.sort_by(|a, b| {
                        let a_name = a.name.to_lowercase();
                        let b_name = b.name.to_lowercase();
                        let a_starts = !query_lower.is_empty() && a_name.starts_with(&query_lower);
                        let b_starts = !query_lower.is_empty() && b_name.starts_with(&query_lower);
                        match (a_starts, b_starts) {
                            (true, false) => std::cmp::Ordering::Less,
                            (false, true) => std::cmp::Ordering::Greater,
                            _ => a_name.cmp(&b_name),
                        }
                    });

                    self.install_all_results = items;
                    self.install_shown = INSTALL_PAGE_SIZE.min(self.install_all_results.len());
                    self.install_results = self
                        .install_all_results
                        .iter()
                        .take(self.install_shown)
                        .cloned()
                        .collect();
                    self.install_has_more = self.install_all_results.len() > self.install_shown;
                }
                TerminalMsg::InstalledList(items) => {
                    self.installed_packages = items;
                }
                TerminalMsg::DetailsResult(text) => {
                    self.details_text = text;
                }
                TerminalMsg::StreamLine(line) => {
                    let line = visible_part(&line).trim_end().to_string();
                    if !is_noise_line(&line) {
                        self.live_log.push(line);
                    }
                }
                TerminalMsg::StreamDone { success } => {
                    self.terminal_lines.push(if success {
                        self.t("✔ Vorgang abgeschlossen.", "✔ Operation finished.").to_string()
                    } else {
                        self.t("✖ Vorgang mit Fehler beendet.", "✖ Operation finished with an error.").to_string()
                    });
                    self.terminal_lines.push(String::new());
                    self.busy = Busy::Idle;
                }
            }
        }
        if self.busy.is_active() || received_any {
            ctx.request_repaint()
        }
    }

    fn show_help_window(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        let mut open = self.show_help;
        egui::Window::new(pick(lang, "❓ Hilfe zur Abk-WingetApp", "❓ Abk-WingetApp help"))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(620.0)
            .default_height(520.0)
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    help_heading(ui, pick(lang, "Was macht diese App?", "What does this app do?"));
                    help_text(
                        ui,
                        pick(
                            lang,
                            "Die Abk-WingetApp ist eine grafische Oberfläche für den Windows-Paketmanager \
                             winget. Statt Befehle selbst in die Kommandozeile zu tippen, klickst du \
                             rechts einfach auf einen Button. Viele Befehle öffnen dafür ein eigenes \
                             Fenster mit Eingabefeld; das Ergebnis erscheint zusätzlich im schwarzen \
                             Terminal-Bereich in der Mitte.",
                            "Abk-WingetApp is a graphical interface for the Windows package manager winget. \
                             Instead of typing commands on the command line, you simply click a button \
                             on the right. Many commands open their own window with an input field; the \
                             result also appears in the black terminal area in the middle.",
                        ),
                    );
                    help_separator(ui);

                    help_heading(ui, pick(lang, "Buttons oben", "Buttons at the top"));
                    help_subheading(ui, pick(lang, "🌙 Dunkel / ☀ Hell", "🌙 Dark / ☀ Light"));
                    help_text(
                        ui,
                        pick(
                            lang,
                            "Wechselt zwischen hellem und dunklem Erscheinungsbild.",
                            "Switches between the light and dark appearance.",
                        ),
                    );
                    ui.add_space(8.0);
                    help_subheading(ui, pick(lang, "🗖 Vollbild", "🗖 Fullscreen"));
                    help_text(
                        ui,
                        pick(
                            lang,
                            "Schaltet das Fenster in den Vollbildmodus.",
                            "Switches the window to fullscreen mode.",
                        ),
                    );
                    ui.add_space(8.0);
                    help_subheading(ui, pick(lang, "❓ Hilfe", "❓ Help"));
                    help_text(
                        ui,
                        pick(lang, "Öffnet genau dieses Hilfe-Fenster.", "Opens exactly this help window."),
                    );
                    help_separator(ui);

                    help_heading(
                        ui,
                        pick(lang, "Winget-Befehle (rechte Leiste)", "Winget commands (right sidebar)"),
                    );
                    for cmd in WINGET_COMMANDS {
                        let (label, help) = localized_command(cmd, lang);
                        help_subheading(ui, label);
                        help_text(ui, help);
                        ui.add_space(8.0);
                    }
                    help_subheading(ui, pick(lang, "🗑 Terminal leeren", "🗑 Clear terminal"));
                    help_text(
                        ui,
                        pick(
                            lang,
                            "Fragt zuerst nach, ob der gesamte bisherige Text im Terminal-Bereich wirklich gelöscht werden soll.",
                            "First asks whether all text in the terminal area should really be deleted.",
                        ),
                    );
                    help_separator(ui);

                    help_heading(
                        ui,
                        pick(
                            lang,
                            "Updates auswählen / Alle Updates installieren",
                            "Select updates / Install all updates",
                        ),
                    );
                    help_text(
                        ui,
                        pick(
                            lang,
                            "Beide Buttons rufen zunächst alle verfügbaren Aktualisierungen ab und \
                             öffnen danach ein Fenster mit einer Liste. Bei \"Updates auswählen\" \
                             legst du per Häkchen selbst fest, was aktualisiert wird; bei \"Alle \
                             Updates installieren\" sind bereits alle Einträge angehakt, sodass ein \
                             einziger Klick auf den Installieren-Button reicht. Sind keine Updates \
                             verfügbar, zeigt das Fenster einen festen Hinweis \"Keine Updates \
                             verfügbar\" an.",
                            "Both buttons first fetch all available updates and then open a window with \
                             a list. With \"Select updates\" you tick what should be updated yourself; \
                             with \"Install all updates\" all entries are already ticked, so a single \
                             click on the install button is enough. If no updates are available, the \
                             window shows a fixed note \"No updates available\".",
                        ),
                    );
                    help_separator(ui);

                    help_heading(ui, pick(lang, "Paketlisten (Export / Import)", "Package lists (export / import)"));
                    help_text(
                        ui,
                        pick(
                            lang,
                            "Das winget-Format (JSON) ist die zuverlässigste Wahl. Die einfache Textliste \
                             enthält eine winget-Id pro Zeile (z. B. Git.Git); Zeilen mit # sind Kommentare. \
                             Beim Import werden Ids exakt installiert. Einträge ohne winget-Id (z. B. nur \
                             lokal installierte Programme) werden beim Export übersprungen. Alte Listen mit \
                             reinen Namen funktionieren weiter, sind aber mehrdeutig.",
                            "The winget format (JSON) is the most reliable choice. The simple text list \
                             contains one winget ID per line (e.g. Git.Git); lines starting with # are \
                             comments. On import, IDs are installed exactly. Entries without a winget ID \
                             (e.g. locally installed programs only) are skipped on export. Old lists with \
                             plain names still work but are ambiguous.",
                        ),
                    );
                    help_separator(ui);

                    help_heading(ui, pick(lang, "Burgermenü (☰ oben rechts)", "Burger menu (☰ top right)"));
                    help_text(
                        ui,
                        pick(
                            lang,
                            "Enthält die Darstellungs-Einstellungen der gesamten GUI (Schriftgröße, \
                             Akzentfarbe, Sprache), den Schalter für den Fernzugriff auf diesen PC, den \
                             Punkt \"Quellen auflisten\", den Präsentations-Testmodus für Updates sowie \
                             den Verlauf (Timeline) mit allen bisherigen Versionen dieser App.",
                            "Contains the appearance settings of the whole GUI (font size, accent color, \
                             language), the switch for remote access to this PC, the \"List sources\" \
                             item, the presentation demo mode for updates and the history (timeline) of \
                             all previous versions of this app.",
                        ),
                    );
                    help_separator(ui);

                    help_heading(
                        ui,
                        pick(lang, "📡 Remote-Steuerung (andere PCs)", "📡 Remote control (other PCs)"),
                    );
                    help_text(
                        ui,
                        pick(
                            lang,
                            "Auf dem Ziel-PC muss nur die Abk-WingetApp geöffnet sein. Der Fernzugriff startet \
                             automatisch. Jeder PC hat einen festen Verbindungscode, der oben in der \
                             Mitte des Fensters steht (📋 kopieren, 🎲 neu erzeugen) - er bleibt auch \
                             nach einem Neustart gleich. Auf deinem PC auf \"📡 Remote-Steuerung\" \
                             klicken, den PC aus der Liste wählen (oder die IP eintragen), beim ersten \
                             Mal den Code eingeben und verbinden. Danach merkt sich die App den Code \
                             (verschlüsselt): In \"Bereits verbunden\" reicht dann \"🔑 Direkt \
                             verbinden\". Du kannst dort Updates auswählen, Programme suchen und \
                             installieren oder deinstallieren. Solange die Verbindung besteht, ist die \
                             Bedienung am Ziel-PC gesperrt. Damit Updates am Ziel-PC ohne jeden \
                             Mausklick laufen, dort einmalig im Burgermenü \"🛡 Mit Adminrechten \
                             automatisch starten\" einrichten. Der Fernzugriff lässt sich im \
                             Burgermenü ausschalten. Wer lieber ein festes Passwort möchte, setzt die \
                             Umgebungsvariable WINGET_AGENT_PASSWORD (mindestens 12 Zeichen). \
                             Sicherheit: Die Verbindung ist mit TLS 1.3 verschlüsselt. Der Code wird \
                             nie übertragen, beide PCs weisen sich gegenseitig nach, dass sie ihn \
                             kennen. Der Haupt-PC merkt sich das Zertifikat jedes Ziel-PCs (🔒 \
                             Fingerabdruck) und warnt, falls es sich ändert. Der Code ist hier oben \
                             verborgen - mit \"👁 Anzeigen\" sichtbar machen.",
                            "On the target PC, only Abk-WingetApp has to be open. Remote access starts \
                             automatically. Every PC has a fixed connection code, shown at the top of \
                             the window (📋 copy, 🎲 new code) - it stays the same after a restart. On \
                             your PC click \"📡 Remote control\", pick the PC from the list (or enter \
                             its IP), enter the code the first time and connect. After that the app \
                             remembers the code (encrypted): in \"Previously connected\" just use \
                             \"🔑 Direkt verbinden\". You can select updates, search for programs and \
                             install or uninstall them there. While the connection exists, the target \
                             PC is locked. To let updates run on the target PC without any click, set \
                             up \"🛡 Start automatically with admin rights\" there once (burger menu). \
                             Remote access can be switched off in the burger menu. If you prefer a \
                             fixed password, set the environment variable WINGET_AGENT_PASSWORD (at \
                             least 12 characters). Security: the connection is encrypted with TLS 1.3. \
                             The code is never sent; both PCs prove to each other that they know it. \
                             The main PC remembers each target PC's certificate (🔒 fingerprint) and \
                             warns if it changes. The code is hidden at the top - use \"👁 Show\".",
                        ),
                    );
                    help_separator(ui);

                    help_heading(ui, pick(lang, "Statusleiste", "Status bar"));
                    help_text(
                        ui,
                        pick(
                            lang,
                            "Unten links: ob gerade ein Befehl läuft und ob der Fernzugriff auf diesen PC bereit ist (mit IP-Adresse). Unten rechts: die installierte winget-Version.",
                            "Bottom left: whether a command is running and whether remote access to this PC is ready (with IP address). Bottom right: the installed winget version.",
                        ),
                    );
                });
            });
        self.show_help = open;
    }

    fn show_timeline_window(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        let mut open = self.show_timeline;

        egui::Window::new(pick(lang, "🕒 Verlauf (Timeline)", "🕒 History (Timeline)"))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(760.0)
            .default_height(480.0)
            .show(ctx, |ui| {
                if VERSION_HISTORY.is_empty() {
                    ui.label(pick(lang, "Es ist noch kein Versionsverlauf hinterlegt.", "No version history available yet."));
                    return;
                }

                ui.columns(2, |columns| {
                    columns[0].label(egui::RichText::new(pick(lang, "Ältere Versionen", "Versions")).strong());
                    columns[0].add_space(4.0);
                    egui::ScrollArea::vertical()
                        .id_source("timeline_list")
                        .max_height(380.0)
                        .show(&mut columns[0], |ui| {
                            for (idx, entry) in VERSION_HISTORY.iter().enumerate() {
                                let selected = self.selected_timeline_index == Some(idx);
                                let label = format!("{}  ·  {}", entry.date, entry.version);
                                if ui.selectable_label(selected, label).clicked() {
                                    self.selected_timeline_index = Some(idx);
                                }
                                ui.add_space(8.0);
                                ui.separator();
                            }
                        });

                    columns[1].label(egui::RichText::new(pick(lang, "Was wurde geändert?", "What changed?")).strong());
                    columns[1].add_space(4.0);
                    match self
                        .selected_timeline_index
                        .and_then(|idx| VERSION_HISTORY.get(idx))
                    {
                        None => {
                            columns[1].label(
                                pick(
                                lang,
                                "Wähle links eine Version aus, um zu sehen, was geändert oder neu hinzugekommen ist.",
                                "Select a version on the left to see what changed or was added.",
                            ),
                            );
                        }
                        Some(entry) => {
                            egui::ScrollArea::vertical()
                                .id_source("timeline_changes")
                                .max_height(380.0)
                                .show(&mut columns[1], |ui| {
                                    ui.set_min_width(ui.available_width());
                                    for change in entry.changes {
                                        ui.label(format!("• {change}"));
                                        ui.add_space(4.0);
                                    }
                                });
                        }
                    }
                });
            });

        self.show_timeline = open;
    }

    fn show_upgrade_list_window(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        let mut open = self.show_upgrade_list;
        let mut install_clicked = false;

        egui::Window::new(pick(lang, "Verfügbare Updates auswählen", "Select available updates"))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(640.0)
            .default_height(480.0)
            .show(ctx, |ui| {
                if self.busy == Busy::ListUpgrades {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(pick(lang, "Updates werden ermittelt...", "Looking for updates..."));
                    });
                } else if self.upgrade_items.is_empty() {
                    if self.upgrades_loaded {
                        ui.label(egui::RichText::new(pick(lang, "✅ Keine Updates verfügbar.", "✅ No updates available.")).strong().size(18.0));
                    } else {
                        ui.label(pick(lang, "Es wurden keine Updates gefunden (oder die Ausgabe von winget konnte nicht gelesen werden). Prüfe ggf. den Terminal-Bereich.", "No updates were found (or winget's output could not be read). Check the terminal area if needed."));
                    }
                } else {
                    ui.horizontal(|ui| {
                        if ui.button(pick(lang, "Alle auswählen", "Select all")).clicked() {
                            for item in &mut self.upgrade_items {
                                item.selected = true;
                            }
                        }
                        if ui.button(pick(lang, "Keine auswählen", "Select none")).clicked() {
                            for item in &mut self.upgrade_items {
                                item.selected = false;
                            }
                        }
                    });
                    ui.add_space(8.0);
                    ui.separator();

                    egui::ScrollArea::vertical()
                        .max_height(320.0)
                        .show(ui, |ui| {
                            egui::Grid::new("upgrade_items_grid")
                                .num_columns(4)
                                .striped(true)
                                .spacing([12.0, 6.0])
                                .show(ui, |ui| {
                                    select_all_checkbox(ui, &mut self.upgrade_items);
                                    ui.label(egui::RichText::new(pick(lang, "Programm", "Program")).strong());
                                    ui.label(egui::RichText::new(pick(lang, "Installiert", "Installed")).strong());
                                    ui.label(egui::RichText::new(pick(lang, "Verfügbar", "Available")).strong());
                                    ui.end_row();

                                    for item in &mut self.upgrade_items {
                                        ui.checkbox(&mut item.selected, "");
                                        ui.label(&item.name);
                                        ui.label(&item.installed_version);
                                        ui.label(&item.available_version);
                                        ui.end_row();
                                    }
                                });
                        });

                    ui.add_space(12.0);
                    ui.separator();
                    ui.add_space(8.0);

                    let selected_count = self.upgrade_items.iter().filter(|i| i.selected).count();
                    ui.horizontal(|ui| {
                        let install_button = egui::Button::new(
                            egui::RichText::new(pick(
                                lang,
                                format!("⬆ {selected_count} Update(s) installieren"),
                                format!("⬆ Install {selected_count} update(s)"),
                            ))
                                .strong()
                                .color(egui::Color32::WHITE),
                        )
                        .fill(egui::Color32::from_rgb(40, 140, 90));

                        if ui
                            .add_enabled(selected_count > 0, install_button)
                            .clicked()
                        {
                            install_clicked = true;
                        }
                    });
                }
            });

        self.show_upgrade_list = open;
        if install_clicked {
            self.install_selected_upgrades();
        }
    }

    fn show_search_window(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        let mut open = self.show_search;
        let mut do_search = false;
        let mut next_page = false;

        egui::Window::new(pick(lang, "🔍 Paket suchen", "🔍 Search package"))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(620.0)
            .default_height(380.0)
            .min_width(480.0)
            .min_height(280.0)
            .max_width(760.0)
            .max_height(460.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(pick(lang, "Suchbegriff:", "Search term:"));
                    let resp = ui.text_edit_singleline(&mut self.search_query);
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        do_search = true;
                    }
                    if ui.add_enabled(!self.busy.is_active(), egui::Button::new(pick(lang, "Suchen", "Search"))).clicked() {
                        do_search = true;
                    }
                });

                ui.add_space(8.0);
                if self.busy == Busy::Search {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(pick(lang, "Suche läuft...", "Searching..."));
                    });
                }
                ui.separator();

                if self.search_results.is_empty() && self.busy != Busy::Search {
                    ui.label(pick(lang, "Noch keine Suchergebnisse. Suchbegriff eingeben und auf \"Suchen\" klicken.", "No results yet. Enter a search term and click \"Search\"."));
                } else {
                    let first = self.search_page * SEARCH_PAGE_SIZE + 1;
                    let last = (first - 1 + self.search_results.len()).min(self.search_all_results.len());
                    ui.label(egui::RichText::new(
                        pick(
                            lang,
                            format!("Treffer {first}-{last} von {} (alphabetisch)", self.search_all_results.len()),
                            format!("Results {first}-{last} of {} (alphabetical)", self.search_all_results.len()),
                        ),
                    ).strong());
                    ui.add_space(4.0);

                    egui::ScrollArea::vertical()
                        .max_height(190.0)
                        .max_width(720.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            egui::Grid::new("search_results_grid")
                                .num_columns(4)
                                .striped(true)
                                .spacing([12.0, 6.0])
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("Name").strong());
                                    ui.label(egui::RichText::new("Id").strong());
                                    ui.label(egui::RichText::new("Version").strong());
                                    ui.label(egui::RichText::new(pick(lang, "Quelle", "Source")).strong());
                                    ui.end_row();

                                    for item in &self.search_results {
                                        ui.label(&item.name);
                                        ui.label(&item.id);
                                        ui.label(&item.version);
                                        ui.label(&item.source);
                                        ui.end_row();
                                    }
                                });
                        });

                    ui.add_space(8.0);
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(self.search_page > 0, egui::Button::new(pick(lang, "← Zurück", "← Back")))
                            .clicked()
                        {
                            self.search_page -= 1;
                            next_page = true;
                        }

                        if ui
                            .add_enabled(self.search_has_more, egui::Button::new(pick(lang, "Weiter suchen →", "Next →")))
                            .clicked()
                        {
                            self.search_page += 1;
                            next_page = true;
                        }
                    });
                }
            });

        self.show_search = open;

        if do_search {
            self.run_search();
        } else if next_page {
            let start = self.search_page * SEARCH_PAGE_SIZE;
            self.search_results = self
                .search_all_results
                .iter()
                .skip(start)
                .take(SEARCH_PAGE_SIZE)
                .cloned()
                .collect();
            self.search_has_more = start + self.search_results.len() < self.search_all_results.len();
        }
    }

    fn show_install_window(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        let mut open = self.show_install;
        let mut do_search = false;
        let mut do_install = false;
        let mut do_load_more = false;

        egui::Window::new(pick(lang, "⬇ Paket installieren", "⬇ Install package"))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(460.0)
            .default_height(400.0)
            .show(ctx, |ui| {
                ui.label(pick(lang, "Paketname oder Suchbegriff eingeben:", "Enter a package name or search term:"));

                ui.horizontal(|ui| {
                    let resp = ui.text_edit_singleline(&mut self.install_query);
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        do_search = true;
                    }

                    if ui
                        .add_enabled(
                            !self.busy.is_active() && !self.install_query.trim().is_empty(),
                            egui::Button::new(pick(lang, "🔍 Online suchen", "🔍 Search online")),
                        )
                        .clicked()
                    {
                        do_search = true;
                    }
                });

                ui.label(
                    egui::RichText::new(
                        pick(lang, "Die Suche verwendet die eingerichteten winget-Quellen und sucht nach dem eingegebenen Begriff.", "The search uses the configured winget sources and looks for the entered term."),
                    )
                    .small(),
                );

                ui.add_space(8.0);

                if self.busy == Busy::InstallSearch {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(pick(lang, "Pakete werden online gesucht...", "Searching packages online..."));
                    });
                }

                if !self.install_results.is_empty() {
                    ui.separator();
                    ui.label(
                        egui::RichText::new(pick(
                            lang,
                            format!(
                                "Vorschläge (passende Treffer zuerst, alphabetisch) - {} von {}:",
                                self.install_results.len(),
                                self.install_all_results.len()
                            ),
                            format!(
                                "Suggestions (best matches first, alphabetical) - {} of {}:",
                                self.install_results.len(),
                                self.install_all_results.len()
                            ),
                        ))
                        .strong(),
                    );

                    egui::ScrollArea::vertical()
                        .max_height(180.0)
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            egui::Grid::new("install_results_grid")
                                .num_columns(5)
                                .striped(true)
                                .spacing([10.0, 6.0])
                                .show(ui, |ui| {
                                    ui.label(egui::RichText::new("Name").strong());
                                    ui.label(egui::RichText::new("Id").strong());
                                    ui.label(egui::RichText::new("Version").strong());
                                    ui.label(egui::RichText::new(pick(lang, "Quelle", "Source")).strong());
                                    ui.label("");
                                    ui.end_row();

                                    let install_results = self.install_results.clone();
                                    for item in &install_results {
                                        ui.label(&item.name);
                                        ui.label(&item.id);
                                        ui.label(&item.version);
                                        ui.label(&item.source);

                                        if ui.button(pick(lang, "Auswählen", "Select")).clicked() {
                                            self.install_query = item.id.clone();
                                        }
                                        ui.end_row();
                                    }
                                });
                        });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(
                                self.install_has_more,
                                egui::Button::new(pick(lang, "🔽 10 weitere laden", "🔽 Load 10 more")),
                            )
                            .clicked()
                        {
                            do_load_more = true;
                        }
                        if !self.install_has_more {
                            ui.label(
                                egui::RichText::new(pick(lang, "Alle Treffer geladen.", "All results loaded.")).small(),
                            );
                        }
                    });
                } else if self.busy != Busy::InstallSearch && !self.install_query.trim().is_empty() {
                    ui.label(pick(lang, "Noch keine Treffer. Suchbegriff eingeben und auf \"Online suchen\" klicken.", "No results yet. Enter a search term and click \"Search online\"."));
                }

                ui.separator();
                ui.add_space(8.0);

                let install_button = egui::Button::new(
                    egui::RichText::new(pick(lang, "⬇ Installieren", "⬇ Install"))
                        .strong()
                        .color(egui::Color32::WHITE),
                )
                .fill(self.accent_color);

                if ui
                    .add_enabled(
                        !self.busy.is_active() && !self.install_query.trim().is_empty(),
                        install_button,
                    )
                    .clicked()
                {
                    do_install = true;
                }

                if self.busy == Busy::Installing {
                    ui.add_space(8.0);
                    ui.label(pick(lang, "Installation läuft, bitte warten...", "Installing, please wait..."));
                    ui.add(
                        egui::ProgressBar::new(0.0)
                            .animate(true)
                            .text(pick(lang, "wird heruntergeladen / installiert", "downloading / installing")),
                    );
                }
            });

        self.show_install = open;

        if do_search {
            self.run_install_search();
        }
        if do_load_more {
            self.install_shown =
                (self.install_shown + INSTALL_PAGE_SIZE).min(self.install_all_results.len());
            self.install_results = self
                .install_all_results
                .iter()
                .take(self.install_shown)
                .cloned()
                .collect();
            self.install_has_more = self.install_all_results.len() > self.install_shown;
        }
        if do_install {
            self.run_install();
        }
    }

    fn show_uninstall_window(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        let mut open = self.show_uninstall;
        let mut load_clicked = false;
        let mut uninstall_target: Option<(String, String)> = None;

        egui::Window::new(pick(lang, "🗑 Paket deinstallieren", "🗑 Uninstall package"))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(660.0)
            .default_height(500.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(pick(lang, "Filtern:", "Filter:"));
                    ui.text_edit_singleline(&mut self.uninstall_query);
                    if ui
                        .add_enabled(!self.busy.is_active(), egui::Button::new(pick(lang, "🔄 Installierte Pakete laden", "🔄 Load installed packages")))
                        .clicked()
                    {
                        load_clicked = true;
                    }
                });
                ui.add_space(8.0);
                if self.busy == Busy::LoadInstalled {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(pick(lang, "Installierte Pakete werden geladen...", "Loading installed packages..."));
                    });
                }
                ui.separator();

                if self.installed_packages.is_empty() && self.busy != Busy::LoadInstalled {
                    ui.label(pick(lang, "Noch keine Liste geladen. Auf \"Installierte Pakete laden\" klicken.", "No list loaded yet. Click \"Load installed packages\"."));
                } else {
                    let filter = self.uninstall_query.to_lowercase();
                    egui::ScrollArea::vertical().max_height(340.0).show(ui, |ui| {
                        egui::Grid::new("uninstall_grid")
                            .num_columns(4)
                            .striped(true)
                            .spacing([12.0, 6.0])
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new("Name").strong());
                                ui.label(egui::RichText::new("Id").strong());
                                ui.label(egui::RichText::new("Version").strong());
                                ui.label("");
                                ui.end_row();
                                for item in &self.installed_packages {
                                    if !filter.is_empty()
                                        && !item.name.to_lowercase().contains(&filter)
                                        && !item.id.to_lowercase().contains(&filter)
                                    {
                                        continue;
                                    }
                                    ui.label(&item.name);
                                    ui.label(&item.id);
                                    ui.label(&item.version);
                                    let btn = egui::Button::new(pick(lang, "Deinstallieren", "Uninstall"))
                                        .fill(egui::Color32::from_rgb(200, 60, 60));
                                    if ui.add_enabled(!self.busy.is_active(), btn).clicked() {
                                        uninstall_target = Some((item.id.clone(), item.name.clone()));
                                    }
                                    ui.end_row();
                                }
                            });
                    });
                }

                if self.busy == Busy::Uninstalling {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(pick(lang, "Deinstallation läuft...", "Uninstalling..."));
                    });
                }
            });

        self.show_uninstall = open;
        if load_clicked {
            self.run_load_installed();
        }
        if let Some((id, name)) = uninstall_target {
            self.run_uninstall(id, name);
        }
    }

    fn show_details_window(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        let mut open = self.show_details;
        let mut do_details = false;

        egui::Window::new(pick(lang, "ℹ Paket-Details anzeigen", "ℹ Show package details"))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(620.0)
            .default_height(480.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(pick(lang, "Paketname oder Id:", "Package name or ID:"));
                    let resp = ui.text_edit_singleline(&mut self.details_query);
                    if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        do_details = true;
                    }
                    if ui.add_enabled(!self.busy.is_active(), egui::Button::new(pick(lang, "Details anzeigen", "Show details"))).clicked() {
                        do_details = true;
                    }
                });
                ui.add_space(8.0);
                if self.busy == Busy::Details {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(pick(lang, "Details werden abgerufen...", "Fetching details..."));
                    });
                }
                ui.separator();

                egui::ScrollArea::vertical().max_height(380.0).show(ui, |ui| {
                    if self.details_text.is_empty() {
                        ui.label(pick(lang, "Noch keine Details abgerufen.", "No details fetched yet."));
                    } else {
                        ui.label(egui::RichText::new(&self.details_text).monospace());
                    }
                });
            });

        self.show_details = open;
        if do_details {
            self.run_details();
        }
    }

    fn show_source_update_window(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        let mut open = self.show_source_update;
        let mut start = false;

        egui::Window::new(pick(lang, "🔄 Quellen aktualisieren", "🔄 Update sources"))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(600.0)
            .default_height(440.0)
            .show(ctx, |ui| {
                ui.label(pick(lang, "Aktualisiert die Paketlisten aller eingerichteten winget-Quellen (z. B. winget, msstore).", "Updates the package lists of all configured winget sources (e.g. winget, msstore)."));
                ui.add_space(8.0);
                let btn = egui::Button::new(
                    egui::RichText::new(pick(lang, "🔄 Jetzt aktualisieren", "🔄 Update now")).strong().color(egui::Color32::WHITE),
                )
                .fill(self.accent_color);
                if ui.add_enabled(!self.busy.is_active(), btn).clicked() {
                    start = true;
                }
                ui.add_space(8.0);
                if self.busy == Busy::SourceUpdate {
                    ui.add(
                        egui::ProgressBar::new(0.0)
                            .animate(true)
                            .text(pick(lang, "Quellen werden aktualisiert...", "Updating sources...")),
                    );
                    ui.add_space(8.0);
                }
                ui.separator();
                ui.label(egui::RichText::new(pick(lang, "Live-Ausgabe:", "Live output:")).strong());
                egui::ScrollArea::vertical()
                    .max_height(240.0)
                    .stick_to_bottom(true)
                    .show(ui, |ui| {
                        for line in &self.live_log {
                            ui.label(egui::RichText::new(line).monospace().small());
                        }
                    });
            });

        self.show_source_update = open;
        if start {
            self.run_source_update();
        }
    }

    fn show_export_window(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        let mut open = self.show_export;
        let mut start = false;

        egui::Window::new(pick(lang, "💾 Paketliste exportieren", "💾 Export package list"))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(560.0)
            .default_height(320.0)
            .show(ctx, |ui| {
                ui.label(pick(lang, "Zieldatei (vollständiger Pfad):", "Target file (full path):"));
                ui.text_edit_singleline(&mut self.export_path);
                ui.add_space(8.0);
                ui.label(pick(lang, "Dateiformat:", "File format:"));
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.export_format, FileFormat::WingetJson, pick(lang, "winget-Paketliste (JSON)", "winget package list (JSON)"));
                    ui.radio_value(&mut self.export_format, FileFormat::TextList, pick(lang, "Einfache Textliste (1 Paket-Id pro Zeile)", "Simple text list (1 package ID per line)"));
                });
                ui.add_space(8.0);
                let btn = egui::Button::new(
                    egui::RichText::new(pick(lang, "💾 Exportieren", "💾 Export")).strong().color(egui::Color32::WHITE),
                )
                .fill(self.accent_color);
                if ui
                    .add_enabled(!self.busy.is_active() && !self.export_path.trim().is_empty(), btn)
                    .clicked()
                {
                    start = true;
                }
                if self.busy == Busy::Export {
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(pick(lang, "Export läuft...", "Exporting..."));
                    });
                }
            });

        self.show_export = open;
        if start {
            self.run_export();
        }
    }

    fn show_import_window(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        let mut open = self.show_import;
        let mut start = false;

        egui::Window::new(pick(lang, "📥 Paketliste importieren", "📥 Import package list"))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(560.0)
            .default_height(360.0)
            .show(ctx, |ui| {
                ui.label(pick(lang, "Quelldatei (vollständiger Pfad):", "Source file (full path):"));
                ui.text_edit_singleline(&mut self.import_path);
                ui.add_space(8.0);
                ui.label(pick(lang, "Dateiformat:", "File format:"));
                ui.horizontal(|ui| {
                    ui.radio_value(&mut self.import_format, FileFormat::WingetJson, pick(lang, "winget-Paketliste (JSON)", "winget package list (JSON)"));
                    ui.radio_value(&mut self.import_format, FileFormat::TextList, pick(lang, "Einfache Textliste (1 Paket-Id pro Zeile)", "Simple text list (1 package ID per line)"));
                });
                ui.add_space(8.0);
                let btn = egui::Button::new(
                    egui::RichText::new(pick(lang, "📥 Importieren", "📥 Import")).strong().color(egui::Color32::WHITE),
                )
                .fill(self.accent_color);
                if ui
                    .add_enabled(!self.busy.is_active() && !self.import_path.trim().is_empty(), btn)
                    .clicked()
                {
                    start = true;
                }
                if self.busy == Busy::Import {
                    ui.add_space(8.0);
                    ui.label(pick(lang, "Import läuft, Fortschritt siehe Live-Ausgabe:", "Importing, see live output for progress:"));
                    egui::ScrollArea::vertical()
                        .max_height(160.0)
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            for line in &self.live_log {
                                ui.label(egui::RichText::new(line).monospace().small());
                            }
                        });
                }
            });

        self.show_import = open;
        if start {
            self.run_import();
        }
    }

    fn show_confirm_clear_window(&mut self, ctx: &egui::Context) {
        let lang = self.language;
        if !self.show_confirm_clear {
            return;
        }
        let mut open = true;
        let mut confirmed = false;
        let mut cancelled = false;

        egui::Window::new(pick(lang, "Terminal wirklich leeren?", "Really clear the terminal?"))
            .open(&mut open)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(pick(lang, "Soll der gesamte Inhalt des Terminals gelöscht werden?", "Should the entire terminal content be deleted?"));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(pick(lang, "Ja, leeren", "Yes, clear")).clicked() {
                        confirmed = true;
                    }
                    if ui.button(pick(lang, "Abbrechen", "Cancel")).clicked() {
                        cancelled = true;
                    }
                });
            });

        if !open {
            cancelled = true;
        }
        if confirmed {
            self.terminal_lines.clear();
            self.note("Terminal geleert.", "Terminal cleared.");
            self.show_confirm_clear = false;
        } else if cancelled {
            self.show_confirm_clear = false;
        }
    }
}

/// Trennlinie unter dem Tabellenkopf (nur Bindestriche, mindestens drei).
fn is_separator_line(line: &str) -> bool {
    line.len() >= 3 && line.chars().all(|c| c == '-')
}

/// Anzeige-Breite eines Zeichens in der Konsole, so wie winget sie beim
/// Ausrichten der Tabellen zählt: ostasiatische Schriftzeichen und Emoji
/// belegen zwei Spalten, kombinierende Zeichen keine, alles andere eine.
fn char_width(c: char) -> usize {
    let cp = c as u32;
    if (0x0300..=0x036F).contains(&cp)
        || (0x200B..=0x200F).contains(&cp)
        || (0x20D0..=0x20FF).contains(&cp)
        || cp == 0xFE0F
    {
        return 0;
    }
    let wide = (0x1100..=0x115F).contains(&cp)
        || (0x2E80..=0x303E).contains(&cp)
        || (0x3041..=0x33FF).contains(&cp)
        || (0x3400..=0x4DBF).contains(&cp)
        || (0x4E00..=0x9FFF).contains(&cp)
        || (0xA000..=0xA4CF).contains(&cp)
        || (0xAC00..=0xD7A3).contains(&cp)
        || (0xF900..=0xFAFF).contains(&cp)
        || (0xFE30..=0xFE4F).contains(&cp)
        || (0xFF00..=0xFF60).contains(&cp)
        || (0xFFE0..=0xFFE6).contains(&cp)
        || (0x1F300..=0x1F64F).contains(&cp)
        || (0x1F900..=0x1F9FF).contains(&cp)
        || (0x20000..=0x3FFFD).contains(&cp);
    if wide {
        2
    } else {
        1
    }
}

/// Spaltenanfänge (in Anzeige-Spalten) aus der Kopfzeile: Jedes Wort der
/// Kopfzeile ("Name", "ID", "Version", "Verfügbar", "Quelle") beginnt genau
/// dort, wo auch die Werte seiner Spalte beginnen.
fn header_columns(header: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut col = 0usize;
    let mut prev_space = true;
    for c in header.chars() {
        let is_space = c == ' ';
        if !is_space && prev_space {
            starts.push(col);
        }
        prev_space = is_space;
        col += char_width(c);
    }
    starts
}

/// Schneidet eine Datenzeile an den festen Spaltenanfängen auseinander.
///
/// winget richtet alle Spalten bündig aus; füllt ein Wert seine Spalte ganz
/// aus, steht davor nur EIN Leerzeichen (z. B. bei
/// "Microsoft Visual C++ … - 14.50.35719 Microsoft.VCRedist.2015+.x64").
/// Deshalb wird nach Position geschnitten statt nach Leerzeichen.
///
/// `None`, wenn die Zeile nicht zur Tabelle passt: Vor jeder Spaltengrenze,
/// die die Zeile erreicht, muss ein Leerzeichen stehen. Fußzeilen wie
/// "3 Aktualisierungen verfügbar." laufen mitten im Wort über eine Grenze.
fn slice_columns(line: &str, starts: &[usize]) -> Option<Vec<String>> {
    let mut fields = vec![String::new(); starts.len()];
    let mut col = 0usize;
    let mut idx = 0usize;
    let mut prev_space = true;
    for c in line.chars() {
        while idx + 1 < starts.len() && col >= starts[idx + 1] {
            if !prev_space {
                return None;
            }
            idx += 1;
        }
        fields[idx].push(c);
        prev_space = c == ' ';
        col += char_width(c);
    }
    Some(fields.into_iter().map(|f| f.trim().to_string()).collect())
}

/// Ist das eine brauchbare Paket-Id in einer Tabellenzeile? winget-Ids haben
/// keine Leerzeichen; nur lokale Einträge (`ARP\...`, `MSIX\...`) dürfen
/// welche enthalten, weil sie aus Registry-Schlüsseln stammen.
fn plausible_table_id(id: &str) -> bool {
    !id.is_empty()
        && (!id.chars().any(char::is_whitespace) || id.starts_with("ARP\\") || id.starts_with("MSIX\\"))
}

/// Zerlegt die Textausgabe von winget in Datenzeilen (je eine Liste von Spalten).
///
/// Sprachunabhängig: Der Tabellenkopf ist die Zeile direkt über der
/// Trennlinie `-----`. Aus ihm werden die Spaltenanfänge gelesen, danach wird
/// jede Zeile genau an diesen Positionen geschnitten. Mehrere Tabellen in
/// einer Ausgabe (z. B. "Pakete, die explizites Targeting erfordern") werden
/// jeweils mit ihrem eigenen Kopf gelesen.
fn table_rows(stdout: &str) -> Vec<Vec<String>> {
    let lines: Vec<&str> = stdout
        .lines()
        .map(|line| visible_part(line).trim_end())
        .filter(|line| !line.trim().is_empty() && !is_noise_line(line))
        .collect();

    let mut rows = Vec::new();
    let mut starts: Option<Vec<usize>> = None;
    for (i, line) in lines.iter().enumerate() {
        if is_separator_line(line.trim()) {
            continue;
        }
        // Kopfzeile = die Zeile direkt über der Trennlinie.
        if lines.get(i + 1).is_some_and(|next| is_separator_line(next.trim())) {
            let cols = header_columns(line);
            starts = (cols.len() >= 3).then_some(cols);
            continue;
        }
        match &starts {
            Some(starts) => {
                if let Some(cols) = slice_columns(line, starts) {
                    rows.push(cols);
                } else {
                    // Notlösung, falls eine Zeile Zeichen enthält, deren Breite
                    // anders gezählt wird: alte Trennung an Doppel-Leerzeichen,
                    // aber nur wenn das Ergebnis vollständig und plausibel ist.
                    let cols = split_columns(line.trim());
                    if cols.len() >= starts.len().saturating_sub(1)
                        && cols.get(1).is_some_and(|id| plausible_table_id(id))
                    {
                        rows.push(cols);
                    }
                }
            }
            None => {
                // Ohne Trennlinie (sehr alte winget-Versionen): alte Logik.
                let line = line.trim();
                if line.starts_with("Name") && (line.contains("Id") || line.contains("ID")) {
                    continue;
                }
                if line.contains("  ") {
                    rows.push(split_columns(line));
                }
            }
        }
    }
    rows
}

/// Parst die Tabellen-Textausgabe von `winget upgrade` in eine Liste einzelner Pakete.
fn parse_upgrade_output(stdout: &str) -> Vec<UpgradeItem> {
    table_rows(stdout)
        .into_iter()
        .filter(|cols| {
            cols.len() >= 4
                && !cols[0].is_empty()
                && plausible_table_id(&cols[1])
                && !cols[2].is_empty()
                && !cols[3].is_empty()
        })
        .map(|cols| UpgradeItem {
            name: cols[0].clone(),
            id: cols[1].clone(),
            installed_version: cols[2].clone(),
            available_version: cols[3].clone(),
            source: cols.get(4).cloned().unwrap_or_default(),
            selected: false,
        })
        .collect()
}

const SEARCH_PAGE_SIZE: usize = 50;
const INSTALL_PAGE_SIZE: usize = 10;

/// Parst Tabellen-Ausgaben wie `winget list` oder `winget search` in eine Liste von `PackageItem`s.
fn parse_package_table(stdout: &str) -> Vec<PackageItem> {
    let mut items: Vec<PackageItem> = table_rows(stdout)
        .into_iter()
        .filter(|cols| cols.len() >= 3 && !cols[0].is_empty() && plausible_table_id(&cols[1]))
        .map(|cols| PackageItem {
            name: cols[0].clone(),
            id: cols[1].clone(),
            version: cols[2].clone(),
            source: cols.last().cloned().unwrap_or_default(),
        })
        .collect();
    items.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    items
}

/// Sieht der Text wie eine winget-Paket-Id aus (z. B. `Git.Git`)? Einträge, die
/// nur lokal über die Systemsteuerung (`ARP\...`) oder als Store-Paket
/// (`MSIX\...`) bekannt sind, lassen sich nicht per Id installieren.
fn is_package_id(text: &str) -> bool {
    !text.is_empty()
        && text.contains('.')
        && !text.chars().any(char::is_whitespace)
        && !text.starts_with("ARP\\")
        && !text.starts_with("MSIX\\")
}

fn split_columns(line: &str) -> Vec<String> {
    let mut cols = Vec::new();
    let mut current = String::new();
    let mut space_run = 0usize;

    for c in line.chars() {
        if c == ' ' {
            space_run += 1;
            current.push(c);
        } else {
            if space_run >= 2 {
                let trimmed = current.trim().to_string();
                if !trimmed.is_empty() {
                    cols.push(trimmed);
                }
                current.clear();
            }
            space_run = 0;
            current.push(c);
        }
    }
    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        cols.push(trimmed);
    }
    cols
}

/// Symbol für einen Befehl in der rechten Leiste.
fn command_icon(args: &[&str]) -> &'static str {
    match args {
        ["upgrade", "--all"] => "⬆",
        ["upgrade"] => "✔",
        ["list"] => "📋",
        ["uninstall"] => "🗑",
        ["install"] => "⬇",
        ["search"] => "🔍",
        ["show"] => "ℹ",
        ["export"] => "💾",
        ["import"] => "📥",
        ["source", "update"] => "🔄",
        _ => "▶",
    }
}

/// Einheitlicher Button für die rechte Leiste (volle Breite, gleiche Höhe).
fn sidebar_button(ui: &mut egui::Ui, icon: &str, label: &str) -> egui::Response {
    let width = ui.available_width();
    ui.add(
        egui::Button::new(RichText::new(format!("{icon}   {label}")).size(15.0))
            .min_size(egui::vec2(width, 36.0)),
    )
}

fn help_heading(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(20.0).strong());
    ui.add_space(4.0);
}

fn help_subheading(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(16.0).strong());
}

fn help_text(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).size(16.0));
}

fn help_separator(ui: &mut egui::Ui) {
    ui.add_space(16.0);
    ui.separator();
    ui.add_space(12.0);
}

/// Kleine farbige "Pille" für die Statusleiste.
fn status_pill(ui: &mut egui::Ui, color: Color32, text: impl Into<String>) -> egui::Response {
    egui::Frame::none()
        .fill(color.gamma_multiply(0.16))
        .stroke(egui::Stroke::new(1.0_f32, color))
        .rounding(10.0)
        .inner_margin(egui::Margin::symmetric(9.0, 2.0))
        .show(ui, |ui| {
            ui.label(RichText::new(text.into()).color(color).small().strong());
        })
        .response
}

impl eframe::App for WingetApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.apply_style(ctx);
        self.poll_terminal_messages(ctx);
        self.poll_agent_events(ctx);
        self.poll_autostart(ctx);
        let lang = self.language;

        // Steuert gerade ein anderer PC diesen PC? Dann ist die Bedienung gesperrt.
        let locked = self.remote_session.is_some();
        let accent = self.accent_color;
        if locked {
            ctx.request_repaint_after(Duration::from_millis(400));
        }

        // ---------------- Kopfleiste ----------------
        let header_fill = if self.dark_mode {
            Color32::from_rgb(24, 26, 31)
        } else {
            Color32::WHITE
        };
        egui::TopBottomPanel::top("top_panel")
            .frame(
                egui::Frame::none()
                    .fill(header_fill)
                    .inner_margin(egui::Margin::symmetric(18.0, 10.0))
                    .stroke(ctx.style().visuals.widgets.noninteractive.bg_stroke),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("📦").size(30.0).color(accent));
                    ui.vertical(|ui| {
                        ui.spacing_mut().item_spacing.y = 0.0;
                        ui.label(RichText::new(format!("{APP_NAME} {APP_VERSION}")).size(22.0).strong());
                        ui.label(
                            RichText::new(self.t(
                                "Programme installieren, aktualisieren & entfernen",
                                "Install, update & remove apps",
                            ))
                            .small()
                            .weak(),
                        );
                    });
                    ui.add_space(24.0);

                    let theme_label = if self.dark_mode {
                        self.t("☀ Hell", "☀ Light")
                    } else {
                        self.t("🌙 Dunkel", "🌙 Dark")
                    };
                    if ui.button(theme_label).clicked() {
                        self.set_theme(!self.dark_mode);
                    }
                    let fs_label = if self.fullscreen {
                        self.t("🗗 Fenster", "🗗 Windowed")
                    } else {
                        self.t("🗖 Vollbild", "🗖 Fullscreen")
                    };
                    if ui.button(fs_label).clicked() {
                        self.fullscreen = !self.fullscreen;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.fullscreen));
                    }
                    if ui.button(self.t("❓ Hilfe", "❓ Help")).clicked() {
                        self.show_help = true;
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.menu_button(RichText::new("☰").size(20.0), |ui| {
                            ui.set_min_width(260.0);

                            ui.menu_button(self.t("🎨 Darstellung", "🎨 Appearance"), |ui| {
                                ui.label(self.t("Sprache / Language:", "Language:"));
                                ui.radio_value(&mut self.language, Language::De, "Deutsch");
                                ui.radio_value(&mut self.language, Language::En, "English");

                                ui.separator();
                                ui.label(self.t("Schriftgröße:", "Font size:"));
                                ui.add(egui::Slider::new(&mut self.font_size, 12.0..=24.0));

                                ui.separator();
                                ui.label(self.t("Akzentfarbe:", "Accent color:"));
                                ui.color_edit_button_srgba(&mut self.accent_color);
                            });

                            ui.separator();
                            let mut allow = self.allow_remote;
                            let toggle = ui
                                .add_enabled(
                                    !locked,
                                    egui::Checkbox::new(
                                        &mut allow,
                                        self.t(
                                            "📡 Fernzugriff auf diesen PC erlauben",
                                            "📡 Allow remote access to this PC",
                                        ),
                                    ),
                                )
                                .on_hover_text(self.t(
                                    "Wenn aktiv, kann ein anderer PC im Netzwerk diesen PC mit dem \
                                     Passwort fernsteuern (Updates, Installieren, Deinstallieren).",
                                    "If enabled, another PC on the network can control this PC \
                                     with the password.",
                                ));
                            if toggle.changed() {
                                self.set_remote_allowed(allow);
                            }

                            // Autostart mit Administratorrechten (nur Windows).
                            if cfg!(windows) {
                                let busy = self.autostart_busy;
                                if self.autostart == Some(true) {
                                    ui.label(
                                        RichText::new(self.t(
                                            "🛡 Startet mit Adminrechten ✔",
                                            "🛡 Starts with admin rights ✔",
                                        ))
                                        .color(GREEN),
                                    );
                                    if ui
                                        .add_enabled(
                                            !locked && !busy,
                                            egui::Button::new(self.t(
                                                "Autostart mit Adminrechten entfernen",
                                                "Remove start with admin rights",
                                            )),
                                        )
                                        .clicked()
                                    {
                                        ui.close_menu();
                                        self.teardown_autostart();
                                    }
                                } else if ui
                                    .add_enabled(
                                        !locked && !busy,
                                        egui::Button::new(self.t(
                                            "🛡 Mit Adminrechten automatisch starten …",
                                            "🛡 Start automatically with admin rights …",
                                        )),
                                    )
                                    .on_hover_text(self.t(
                                        "Einmalig einrichten (eine Windows-Abfrage mit \"Ja\" bestätigen). \
                                         Danach startet die App bei jeder Anmeldung mit \
                                         Administratorrechten - ferngesteuerte Updates laufen dann \
                                         ohne jeden Mausklick an diesem PC durch.",
                                        "Set up once (confirm one Windows prompt with \"Yes\"). After that \
                                         the app starts with administrator rights at every sign-in - \
                                         remote updates then run without any click on this PC.",
                                    ))
                                    .clicked()
                                {
                                    ui.close_menu();
                                    self.setup_autostart();
                                }
                            }
                            ui.separator();

                            ui.add_enabled_ui(!locked, |ui| {
                                if ui
                                    .button(localized_command(&SOURCE_LIST_COMMAND, lang).0)
                                    .clicked()
                                {
                                    ui.close_menu();
                                    self.run_winget_command(&SOURCE_LIST_COMMAND);
                                }
                                if ui
                                    .button(self.t("🎬 Demo-Updates laden", "🎬 Load Demo Upgrades"))
                                    .clicked()
                                {
                                    ui.close_menu();
                                    self.load_demo_upgrades();
                                }
                                if ui
                                    .button(self.t("🕒 Verlauf (Timeline)", "🕒 History (Timeline)"))
                                    .clicked()
                                {
                                    ui.close_menu();
                                    self.show_timeline = true;
                                }
                                if ui.button(self.t("📡 Remote-Steuerung", "📡 Remote control")).clicked() {
                                    ui.close_menu();
                                    self.remote.open = true;
                                }
                            });
                        });
                    });
                });
            });

        // ---------------- Statusleiste ----------------
        egui::TopBottomPanel::bottom("bottom_panel")
            .frame(
                egui::Frame::none()
                    .fill(header_fill)
                    .inner_margin(egui::Margin::symmetric(16.0, 6.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if self.busy.is_active() {
                        ui.spinner();
                        ui.label(self.t("Befehl läuft...", "Running command..."));
                    } else {
                        remote_ui::status_dot(ui, GREEN);
                        ui.label(RichText::new(self.t("Bereit", "Ready")).color(GREEN));
                    }
                    ui.separator();

                    match (&self.remote_session, &self.agent_status) {
                        (Some(s), _) => {
                            status_pill(
                                ui,
                                AMBER,
                                pick(
                                    lang,
                                    format!("🔒 Ferngesteuert von {}", s.controller),
                                    format!("🔒 Remote-controlled by {}", s.controller),
                                ),
                            );
                        }
                        (None, AgentStatus::Listening { ip, .. }) => {
                            let text = match ip {
                                Some(ip) => pick(
                                    lang,
                                    format!("📡 Fernzugriff bereit · IP {ip}"),
                                    format!("📡 Remote access ready · IP {ip}"),
                                ),
                                None => pick(
                                    lang,
                                    "📡 Fernzugriff bereit".to_string(),
                                    "📡 Remote access ready".to_string(),
                                ),
                            };
                            let hint = pick(
                                lang,
                                "Andere PCs können sich mit dieser IP und dem Verbindungscode \
                                 verbinden (steht oben in der Mitte des Fensters)."
                                    .to_string(),
                                "Other PCs can connect with this IP and the connection code \
                                 (shown at the top of the window)."
                                    .to_string(),
                            );
                            status_pill(ui, GREEN, text).on_hover_text(hint);
                        }
                        (None, AgentStatus::Failed(e)) => {
                            status_pill(ui, RED, pick(lang, "📡 Fernzugriff nicht verfügbar", "📡 Remote access unavailable")).on_hover_text(e.as_str());
                        }
                        (None, AgentStatus::Off) => {
                            status_pill(ui, Color32::GRAY, pick(lang, "📡 Fernzugriff aus", "📡 Remote access off"));
                        }
                    }
                    if let Some(host) = self.remote.connected_to() {
                        status_pill(
                            ui,
                            accent,
                            pick(lang, format!("🖧 Verbunden mit {host}"), format!("🖧 Connected to {host}")),
                        );
                    } else {
                        let found = self.remote.found_pcs();
                        if found > 0 {
                            status_pill(
                                ui,
                                GREEN,
                                pick(
                                    lang,
                                    format!("🔍 {found} PC(s) im Netzwerk"),
                                    format!("🔍 {found} PC(s) on the network"),
                                ),
                            )
                            .on_hover_text(pick(
                                lang,
                                "PCs mit der Abk-WingetApp, die im Netzwerk gefunden wurden. Zum Verbinden: Fernsteuerung öffnen.",
                                "PCs running Abk-WingetApp that were found on the network. To connect: open remote control.",
                            ));
                        }
                    }

                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let version_text = match &self.winget_version {
                            Some(v) => format!("winget {v}"),
                            None => "winget: ...".to_string(),
                        };
                        ui.label(RichText::new(version_text).weak());
                    });
                });
            });

        // ---------------- Rechte Leiste: Befehle ----------------
        egui::SidePanel::right("right_panel")
            .resizable(false)
            .exact_width(270.0)
            .frame(
                egui::Frame::none()
                    .fill(ctx.style().visuals.panel_fill)
                    .inner_margin(egui::Margin::same(14.0)),
            )
            .show(ctx, |ui| {
                ui.label(RichText::new(self.t("Befehle", "Commands")).size(18.0).strong());
                ui.add_space(4.0);

                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_enabled_ui(!locked && !self.busy.is_active(), |ui| {
                        for cmd in WINGET_COMMANDS {
                            let (label, help) = localized_command(cmd, lang);
                            if sidebar_button(ui, command_icon(cmd.args), label)
                                .on_hover_text(help)
                                .clicked()
                            {
                                match cmd.args {
                                    ["upgrade"] => {
                                        self.pending_select_all = false;
                                        self.run_list_upgrades();
                                    }
                                    ["upgrade", "--all"] => {
                                        self.pending_select_all = true;
                                        self.run_list_upgrades();
                                    }
                                    ["search"] => self.show_search = true,
                                    ["install"] => self.show_install = true,
                                    ["uninstall"] => self.show_uninstall = true,
                                    ["show"] => self.show_details = true,
                                    ["source", "update"] => self.show_source_update = true,
                                    ["export"] => self.show_export = true,
                                    ["import"] => self.show_import = true,
                                    _ => self.run_winget_command(cmd),
                                }
                            }
                        }
                    });

                    ui.add_space(6.0);
                    ui.separator();
                    ui.add_space(6.0);

                    // Remote-Button: abgesetzt und farbig, damit er sofort auffällt.
                    let width = ui.available_width();
                    let remote_btn = egui::Button::new(
                        RichText::new(self.t("📡   Remote-Steuerung", "📡   Remote control"))
                            .color(Color32::WHITE)
                            .strong()
                            .size(15.0),
                    )
                    .fill(Color32::from_rgb(110, 70, 180))
                    .min_size(egui::vec2(width, 40.0));
                    if ui
                        .add_enabled(!locked, remote_btn)
                        .on_hover_text(self.t(
                            "Andere PCs im Netzwerk aktualisieren, Programme installieren oder entfernen.",
                            "Update, install or remove apps on other PCs in your network.",
                        ))
                        .clicked()
                    {
                        self.remote.open = true;
                    }

                    ui.add_space(6.0);
                    ui.add_enabled_ui(!locked && !self.busy.is_active(), |ui| {
                        if sidebar_button(ui, "🗑", self.t("Terminal leeren", "Clear terminal")).clicked() {
                            self.show_confirm_clear = true;
                        }
                    });
                });
            });

        // ---------------- Mitte: Hinweis + Terminal ----------------
        let mut copy_code: Option<String> = None;
        let mut regen_code = false;
        let mut toggle_code = false;
        let mut setup_admin = false;
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(ctx.style().visuals.panel_fill)
                    .inner_margin(egui::Margin::same(14.0)),
            )
            .show(ctx, |ui| {
                if let Some(session) = &self.remote_session {
                    egui::Frame::none()
                        .fill(AMBER.gamma_multiply(0.18))
                        .stroke(egui::Stroke::new(1.5_f32, AMBER))
                        .rounding(10.0)
                        .inner_margin(egui::Margin::same(14.0))
                        .show(ui, |ui| {
                            ui.set_min_width(ui.available_width());
                            ui.horizontal(|ui| {
                                ui.label(RichText::new("🔒").size(30.0));
                                ui.vertical(|ui| {
                                    ui.label(
                                        RichText::new(pick(
                                            lang,
                                            format!(
                                                "Dieser PC wird gerade von {} ferngesteuert",
                                                session.controller
                                            ),
                                            format!(
                                                "This PC is currently being controlled by {}",
                                                session.controller
                                            ),
                                        ))
                                        .size(18.0)
                                        .strong(),
                                    );
                                    ui.label(pick(
                                        lang,
                                        format!(
                                            "Verbunden von {}. Alle Befehle sind gesperrt, bis die Verbindung getrennt wird.",
                                            session.ip
                                        ),
                                        format!(
                                            "Connected from {}. All commands are locked until the connection is closed.",
                                            session.ip
                                        ),
                                    ));
                                    if let Some(current) = &session.current {
                                        ui.horizontal(|ui| {
                                            ui.spinner();
                                            ui.label(
                                                RichText::new(pick(
                                                    lang,
                                                    format!("Wird gerade ausgeführt: {current}"),
                                                    format!("Currently running: {current}"),
                                                ))
                                                    .strong(),
                                            );
                                        });
                                    }
                                });
                            });
                        });
                    ui.add_space(10.0);
                }

                // Verbindungscode dieses PCs: Den tippt man auf dem Haupt-PC ein.
                if self.remote_session.is_none() {
                    if let AgentStatus::Listening {
                        ip,
                        password,
                        admin,
                        fingerprint,
                    } = &self.agent_status
                    {
                        let show_code = self.show_code;
                        egui::Frame::none()
                            .fill(accent.gamma_multiply(0.12))
                            .stroke(egui::Stroke::new(1.5_f32, accent))
                            .rounding(10.0)
                            .inner_margin(egui::Margin::symmetric(14.0, 10.0))
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("🔑").size(28.0));
                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = 2.0;
                                        ui.label(
                                            RichText::new(pick(
                                                lang,
                                                "Verbindungscode dieses PCs",
                                                "Connection code of this PC",
                                            ))
                                            .strong(),
                                        );
                                        let shown = if show_code {
                                            password.clone()
                                        } else {
                                            mask_code(password)
                                        };
                                        ui.label(
                                            RichText::new(shown)
                                                .monospace()
                                                .size(26.0)
                                                .strong()
                                                .color(accent),
                                        );
                                        ui.label(
                                            RichText::new(format!(
                                                "🔒 {} {}",
                                                pick(lang, "Zertifikat:", "Certificate:"),
                                                tls::short_fingerprint(fingerprint)
                                            ))
                                            .monospace()
                                            .small(),
                                        )
                                        .on_hover_text(pick(
                                            lang,
                                            "Fingerabdruck des Sicherheits-Zertifikats dieses PCs. Der Haupt-PC \
                                             zeigt ihn nach dem Verbinden in \"Bereits verbunden\" an - beide \
                                             müssen übereinstimmen.",
                                            "Fingerprint of this PC's security certificate. The main PC shows it \
                                             in \"Previously connected\" after connecting - both must match.",
                                        ));
                                        let hint = match ip {
                                            Some(ip) => pick(
                                                lang,
                                                format!(
                                                    "Auf dem Haupt-PC im Remote-Fenster diesen PC wählen (IP {ip}) und den Code eingeben."
                                                ),
                                                format!(
                                                    "On the main PC, pick this PC in the remote window (IP {ip}) and enter the code."
                                                ),
                                            ),
                                            None => pick(
                                                lang,
                                                "Auf dem Haupt-PC im Remote-Fenster diesen PC wählen und den Code eingeben."
                                                    .to_string(),
                                                "On the main PC, pick this PC in the remote window and enter the code."
                                                    .to_string(),
                                            ),
                                        };
                                        ui.label(RichText::new(hint).small().weak());
                                        if !*admin && cfg!(windows) {
                                            ui.add_space(4.0);
                                            ui.horizontal(|ui| {
                                                ui.label(
                                                    RichText::new(pick(
                                                        lang,
                                                        "⚠ Ohne Adminrechte: Manche Updates brauchen hier einen Mausklick.",
                                                        "⚠ No admin rights: some updates need a click here.",
                                                    ))
                                                    .color(AMBER)
                                                    .small(),
                                                );
                                                let busy = self.autostart_busy;
                                                if ui
                                                    .add_enabled(
                                                        !busy,
                                                        egui::Button::new(
                                                            RichText::new(pick(
                                                                lang,
                                                                "🛡 Einmalig einrichten",
                                                                "🛡 Set up once",
                                                            ))
                                                            .small(),
                                                        ),
                                                    )
                                                    .on_hover_text(pick(
                                                        lang,
                                                        "Die App startet danach bei jeder Anmeldung mit \
                                                         Administratorrechten. Dafür einmal die \
                                                         Windows-Abfrage mit \"Ja\" bestätigen.",
                                                        "Afterwards the app starts with administrator \
                                                         rights at every sign-in. Confirm the Windows \
                                                         prompt once with \"Yes\".",
                                                    ))
                                                    .clicked()
                                                {
                                                    setup_admin = true;
                                                }
                                                if busy {
                                                    ui.spinner();
                                                }
                                            });
                                        }
                                    });
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            if ui
                                                .button(pick(lang, "🎲 Neu erzeugen", "🎲 New code"))
                                                .on_hover_text(pick(
                                                    lang,
                                                    "Erzeugt einen neuen Code. Der alte gilt dann nicht mehr.",
                                                    "Generates a new code. The old one stops working.",
                                                ))
                                                .clicked()
                                            {
                                                regen_code = true;
                                            }
                                            if ui.button(pick(lang, "📋 Kopieren", "📋 Copy")).clicked() {
                                                copy_code = Some(password.clone());
                                            }
                                            let (label, hint) = if show_code {
                                                (
                                                    pick(lang, "🙈 Verbergen", "🙈 Hide"),
                                                    pick(lang, "Code wieder verbergen.", "Hide the code again."),
                                                )
                                            } else {
                                                (
                                                    pick(lang, "👁 Anzeigen", "👁 Show"),
                                                    pick(
                                                        lang,
                                                        "Code im Klartext anzeigen (z. B. zum Abtippen). Vorsicht bei \
                                                         Bildschirmfreigabe.",
                                                        "Show the code in plain text (e.g. to type it). Careful \
                                                         when sharing your screen.",
                                                    ),
                                                )
                                            };
                                            if ui.button(label).on_hover_text(hint).clicked() {
                                                toggle_code = true;
                                            }
                                        },
                                    );
                                });
                            });
                        ui.add_space(10.0);
                    }
                }

                egui::Frame::none()
                    .fill(TERM_BG)
                    .rounding(10.0)
                    .inner_margin(egui::Margin::same(14.0))
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .auto_shrink([false, false])
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                ui.set_min_width(ui.available_width());
                                for line in &self.terminal_lines {
                                    ui.label(
                                        RichText::new(line)
                                            .monospace()
                                            .color(terminal_line_color(line)),
                                    );
                                }
                            });
                    });
            });

        if let Some(code) = copy_code {
            ctx.copy_text(code);
        }
        if toggle_code {
            self.show_code = !self.show_code;
        }
        if setup_admin {
            self.setup_autostart();
        }
        if regen_code {
            if let Some(agent) = &self.agent {
                let new_code = agent.new_password();
                if let AgentStatus::Listening { password, .. } = &mut self.agent_status {
                    *password = new_code;
                }
                self.note("🎲 Neuer Verbindungscode erzeugt.", "🎲 New connection code generated.");
            }
        }

        // ---------------- Fenster ----------------
        // Während der Fernsteuerung bleiben alle lokalen Fenster zu; sie
        // erscheinen nach dem Trennen wieder so, wie sie waren.
        if !locked {
            if self.show_help {
                self.show_help_window(ctx);
            }
            if self.show_timeline {
                self.show_timeline_window(ctx);
            }
            if self.show_upgrade_list {
                self.show_upgrade_list_window(ctx);
            }
            if self.show_search {
                self.show_search_window(ctx);
            }
            if self.show_install {
                self.show_install_window(ctx);
            }
            if self.show_uninstall {
                self.show_uninstall_window(ctx);
            }
            if self.show_details {
                self.show_details_window(ctx);
            }
            if self.show_source_update {
                self.show_source_update_window(ctx);
            }
            if self.show_export {
                self.show_export_window(ctx);
            }
            if self.show_import {
                self.show_import_window(ctx);
            }
            if self.show_confirm_clear {
                self.show_confirm_clear_window(ctx);
            }
        }

        // Remote-Fenster (für die Steuerung ANDERER PCs).
        self.remote.show(ctx, accent, !locked);
    }
}

/// Öffnet für den `--agent`-Modus ein Konsolenfenster (die App selbst ist
/// unter Windows ein reines Fenster-Programm ohne Konsole).
#[cfg(windows)]
fn open_console() {
    #[link(name = "kernel32")]
    extern "system" {
        fn AllocConsole() -> i32;
    }
    // SAFETY: AllocConsole hat keine Vorbedingungen; schlägt es fehl (schon
    // eine Konsole vorhanden), passiert einfach nichts.
    unsafe {
        AllocConsole();
    }
}

#[cfg(not(windows))]
fn open_console() {}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // Betrieb ohne Oberfläche (nur noch selten nötig: Der Agent läuft
    // automatisch mit, sobald die App geöffnet ist).
    if let Some(agent_index) = args.iter().position(|arg| arg == "--agent") {
        open_console();
        let addr = args.get(agent_index + 1).map(String::as_str);
        if let Err(error) = agent::run_agent_cli(addr) {
            eprintln!("Agent konnte nicht gestartet werden: {error}");
            eprintln!("(Enter zum Schließen)");
            let _ = std::io::stdin().read_line(&mut String::new());
            std::process::exit(1);
        }
        return Ok(());
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 820.0])
            .with_min_inner_size([960.0, 620.0])
            .with_title(format!("{APP_NAME} {APP_VERSION}")),
        ..Default::default()
    };

    eframe::run_native(
        APP_NAME,
        options,
        Box::new(|cc| Ok(Box::new(WingetApp::new(cc)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_is_masked_but_keeps_groups() {
        assert_eq!(mask_code("3FA9-27BC-91D4-E0A1-5C7E"), "••••-••••-••••-••••-••••");
        assert_eq!(mask_code("eigenes Passwort"), "••••••• ••••••••");
    }

    /// So kommt die `winget upgrade`-Ausgabe zeilenweise vom Agent an
    /// (deutsche Spaltenköpfe, Fortschritts-Spinner bereits entfernt).
    #[test]
    fn remote_upgrade_output_is_parsed() {
        let raw = "Name                     ID                          Version      Verfügbar    Quelle\n\
----------------------------------------------------------------------------------------\n\
Google Chrome            Google.Chrome               124.0.6367.91  126.0.6478.63  winget\n\
7-Zip 23.01 (x64)        7zip.7zip                   23.01        24.07        winget\n\
3 Aktualisierungen verfügbar.";
        let items = parse_upgrade_output(raw);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id, "Google.Chrome");
        assert_eq!(items[0].available_version, "126.0.6478.63");
        assert_eq!(items[1].name, "7-Zip 23.01 (x64)");
        assert_eq!(items[1].id, "7zip.7zip");
    }

    /// Lokale `winget`-Ausgabe enthält Spinner (`\r`) und Fortschrittsbalken -
    /// die dürfen weder als Paket erkannt werden noch die Kopfzeile verdecken.
    #[test]
    fn spinner_and_progress_bars_are_ignored() {
        let raw = "   - \r   \\ \rName      Id             Version  Verfügbar  Quelle\n\
------------------------------------------------------------\n\
  ██████████████▒▒▒▒▒▒  1.00 MB / 2.00 MB\n\
Git       Git.Git        2.44.0   2.45.1     winget\n";
        let items = parse_upgrade_output(raw);
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].id, "Git.Git");
    }

    /// Kopfzeilen in anderen Sprachen dürfen nicht als Paket erkannt werden:
    /// Der Kopf wird an der Trennlinie darunter erkannt, nicht am Wort "Name".
    #[test]
    fn headers_in_other_languages_are_skipped() {
        let en = "Name   Id        Version  Available  Source\n\
-------------------------------------------------\n\
Git    Git.Git   2.44.0   2.45.1     winget\n\
1 upgrades available.";
        let fr = "Nom    ID        Version  Disponible  Source\n\
--------------------------------------------------\n\
Git    Git.Git   2.44.0   2.45.1      winget\n";
        for raw in [en, fr] {
            let items = parse_upgrade_output(raw);
            assert_eq!(items.len(), 1, "falsche Anzahl für:\n{raw}");
            assert_eq!(items[0].id, "Git.Git");
            assert_eq!(items[0].source, "winget");
        }
    }

    #[test]
    fn package_table_is_parsed_and_sorted() {
        let raw = "Name        Id           Version  Quelle\n\
------------------------------------------\n\
Zoom        Zoom.Zoom    5.0      winget\n\
7-Zip       7zip.7zip    23.01    winget\n";
        let items = parse_package_table(raw);
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].name, "7-Zip");
        assert_eq!(items[1].id, "Zoom.Zoom");
    }

    /// Echte winget-Ausgabe: Füllt ein Wert seine Spalte ganz aus, steht bis
    /// zur nächsten Spalte nur EIN Leerzeichen. Genau das hat in 0.5.1 Name+Id
    /// bzw. Id+Version zusammengeklebt (VC++ Redistributable, .NET Runtime).
    #[test]
    fn single_space_columns_are_split_by_position() {
        let raw = "Name                                                         ID                                 Version       Verfügbar     Quelle\n\
---------------------------------------------------------------------------------------------------------------------------------------\n\
Microsoft Visual C++ v14 Redistributable (x64) - 14.50.35719 Microsoft.VCRedist.2015+.x64       14.44.35211.0 14.50.35719.0 winget\n\
Microsoft Visual C++ v14 Redistributable (x86) - 14.50.35719 Microsoft.VCRedist.2015+.x86       14.44.35211.0 14.50.35719.0 winget\n\
Microsoft Windows Desktop Runtime - 10.0.5 (x64)             Microsoft.DotNet.DesktopRuntime.10 10.0.5        10.0.6        winget\n\
3 Aktualisierungen verfügbar.\n";
        let items = parse_upgrade_output(raw);
        assert_eq!(items.len(), 3, "Fußzeile darf kein Paket sein");
        assert_eq!(items[0].name, "Microsoft Visual C++ v14 Redistributable (x64) - 14.50.35719");
        assert_eq!(items[0].id, "Microsoft.VCRedist.2015+.x64");
        assert_eq!(items[0].installed_version, "14.44.35211.0");
        assert_eq!(items[0].available_version, "14.50.35719.0");
        assert_eq!(items[1].id, "Microsoft.VCRedist.2015+.x86");
        assert_eq!(items[2].id, "Microsoft.DotNet.DesktopRuntime.10");
        assert_eq!(items[2].installed_version, "10.0.5");
        assert_eq!(items[2].available_version, "10.0.6");
        assert_eq!(items[2].source, "winget");
        for item in &items {
            assert!(crate::protocol::is_valid_package_id(&item.id), "ungültig: {}", item.id);
        }
    }

    #[test]
    fn search_with_empty_match_column_keeps_source() {
        let raw = "Name                    ID                                Version   Übereinstimmung  Quelle\n------------------------------------------------------------------------------------------\nMozilla Firefox         Mozilla.Firefox                   131.0                      winget\nFirefox Developer Ed.   Mozilla.Firefox.DeveloperEdition  132.0b9   Tag: firefox     winget";
        let items = parse_package_table(raw);
        assert_eq!(items.len(), 2);
        let dev = items.iter().find(|i| i.id == "Mozilla.Firefox.DeveloperEdition").unwrap();
        assert_eq!(dev.version, "132.0b9");
        assert_eq!(dev.source, "winget");
        let ff = items.iter().find(|i| i.id == "Mozilla.Firefox").unwrap();
        assert_eq!(ff.source, "winget");
    }

    #[test]
    fn list_with_arp_ids_and_wide_characters() {
        let raw = "Name            ID                                      Version   Verfügbar Quelle\n------------------------------------------------------------------------------------\nGit             Git.Git                                 2.44.0    2.45.1    winget\nIntel Treiber   ARP\\Machine\\X64\\Intel Driver Pack 1     1.2.3\n微信            Tencent.WeChat                          3.9.10              winget\nVisual Studio…  Microsoft.VisualStudio.2022.Community   17.9.0              winget";
        let items = parse_package_table(raw);
        assert_eq!(items.len(), 4, "{:?}", items.iter().map(|i| &i.id).collect::<Vec<_>>());
        let arp = items.iter().find(|i| i.name == "Intel Treiber").unwrap();
        assert_eq!(arp.id, "ARP\\Machine\\X64\\Intel Driver Pack 1");
        assert_eq!(arp.version, "1.2.3");
        let wechat = items.iter().find(|i| i.id == "Tencent.WeChat").unwrap();
        assert_eq!(wechat.name, "微信");
        assert_eq!(wechat.version, "3.9.10");
        assert!(items.iter().any(|i| i.id == "Microsoft.VisualStudio.2022.Community"));
    }

    #[test]
    fn second_table_with_own_header_is_read() {
        let raw = "Name        ID          Version  Verfügbar Quelle\n--------------------------------------------------\nGit         Git.Git     2.44.0   2.45.1    winget\n1 Aktualisierungen verfügbar.\nDie folgenden Pakete haben ein Upgrade verfügbar, erfordern jedoch ein explizites Targeting für das Upgrade:\nName            ID                  Version  Verfügbar Quelle\n--------------------------------------------------------------\nDiscord         Discord.Discord     1.0.9163 1.0.9170  winget";
        let items = parse_upgrade_output(raw);
        let ids: Vec<_> = items.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["Git.Git", "Discord.Discord"]);
        assert_eq!(items[1].available_version, "1.0.9170");
    }

    /// Schreibt die erzeugten PowerShell-Skripte in einen Ordner, damit sie
    /// mit PowerShell auf Syntaxfehler geprüft werden können.
    #[test]
    fn dump_powershell_scripts() {
        let Ok(dir) = std::env::var("ABK_DUMP_SCRIPTS") else { return };
        let install = autostart_install_script("C:\\Program Files\\Abk's App\\winget-app.exe", "BUERO\\Max");
        std::fs::write(format!("{dir}/install.ps1"), &install).unwrap();
        std::fs::write(format!("{dir}/remove.ps1"), autostart_remove_script()).unwrap();
        std::fs::write(format!("{dir}/elevate.ps1"), elevate_script(&ps_encode(&install))).unwrap();
    }

    /// Werte unabhängig mit Python berechnet (base64 von UTF-16LE).
    #[test]
    fn powershell_encoding_matches_reference() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
        assert_eq!(base64(b""), "");
        assert_eq!(ps_encode("exit 0"), "ZQB4AGkAdAAgADAA");
        // Pfad mit Leerzeichen, Apostroph und Umlaut übersteht das Quoting.
        let script = format!("$p = {}; ä", ps_quote("C:\\Program Files\\Abk's"));
        assert_eq!(
            ps_encode(&script),
            "JABwACAAPQAgACcAQwA6AFwAUAByAG8AZwByAGEAbQAgAEYAaQBsAGUAcwBcAEEAYgBrACcAJwBzACcAOwAgAOQA"
        );
    }

    #[test]
    fn select_all_toggles_between_all_and_none() {
        let item = |selected| UpgradeItem {
            selected,
            ..Default::default()
        };
        // Teilweise angehakt -> ein Klick hakt alle an.
        let mut items = vec![item(true), item(false), item(false)];
        toggle_all(&mut items);
        assert!(items.iter().all(|i| i.selected));
        // Alle angehakt -> ein Klick hakt alle ab ("vice versa").
        toggle_all(&mut items);
        assert!(items.iter().all(|i| !i.selected));
        // Keins angehakt -> alle an.
        toggle_all(&mut items);
        assert!(items.iter().all(|i| i.selected));
        // Leere Liste: nichts passiert, kein Absturz.
        toggle_all(&mut []);
    }

    #[test]
    fn only_real_winget_ids_are_accepted() {
        assert!(is_package_id("Git.Git"));
        assert!(is_package_id("Microsoft.VisualStudioCode"));
        assert!(!is_package_id("7-Zip 23.01 (x64)"));
        assert!(!is_package_id("Firefox"));
        assert!(!is_package_id("ARP\\Machine\\X64\\Foo.Bar"));
        assert!(!is_package_id("MSIX\\Some.App_1.0"));
        assert!(!is_package_id(""));
    }
}
