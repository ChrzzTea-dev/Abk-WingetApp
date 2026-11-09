//! Verschlüsselte Verbindung (TLS 1.3) zwischen Haupt-PC und Ziel-PC.
//!
//! - Jeder Ziel-PC erzeugt beim ersten Start ein eigenes, selbstsigniertes
//!   Zertifikat (ECDSA P-256). Der private Schlüssel wird wie der
//!   Verbindungscode mit DPAPI verschlüsselt gespeichert.
//! - Der Haupt-PC prüft bei jeder Verbindung die TLS-Signatur (der Ziel-PC
//!   muss den privaten Schlüssel wirklich besitzen) und vergleicht danach den
//!   Fingerabdruck (SHA-256) des Zertifikats mit dem gespeicherten Wert
//!   ("Trust on first use", Pinning).
//! - Die Anmeldung (HMAC) wird zusätzlich an diesen Fingerabdruck gebunden
//!   (Channel Binding, siehe `protocol::compute_auth_response`). Ein Angreifer
//!   in der Mitte, der sein eigenes Zertifikat vorzeigt, kann eine abgefangene
//!   Anmeldung daher nicht an den echten Ziel-PC weiterreichen.
//!
//! Kryptografie: rustls mit dem "ring"-Anbieter, nur TLS 1.3.

use crate::protocol::{app_data_dir, hex_encode, open_secret, seal_secret};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection,
    SignatureScheme, StreamOwned,
};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Name, der im TLS-Handshake angegeben wird. Er wird nicht geprüft - die
/// Identität des Ziel-PCs ergibt sich aus dem Fingerabdruck.
const TLS_SERVER_NAME: &str = "abk-wingetapp.local";

pub type ClientTls = StreamOwned<ClientConnection, TcpStream>;
pub type ServerTls = StreamOwned<ServerConnection, TcpStream>;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn tls_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("TLS: {e}"))
}

/// Fingerabdruck eines Zertifikats: SHA-256 über das DER, als Hex (64 Zeichen).
pub fn fingerprint(cert_der: &[u8]) -> String {
    hex_encode(&Sha256::digest(cert_der))
}

/// Kurzform zum Anzeigen und Vergleichen am Telefon, z. B. "3FA9 27BC 91D4 E0A1".
pub fn short_fingerprint(fp: &str) -> String {
    fp.to_uppercase()
        .as_bytes()
        .chunks(4)
        .take(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Ziel-PC: eigenes Zertifikat
// ---------------------------------------------------------------------------

/// Zertifikat + privater Schlüssel eines Ziel-PCs.
pub struct AgentIdentity {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    pub fingerprint: String,
}

impl AgentIdentity {
    /// Erzeugt ein neues selbstsigniertes Zertifikat (ECDSA P-256).
    pub fn generate() -> io::Result<Self> {
        let key = rcgen::KeyPair::generate().map_err(tls_err)?;
        let params = rcgen::CertificateParams::new(vec![TLS_SERVER_NAME.to_string()])
            .map_err(tls_err)?;
        let cert = params.self_signed(&key).map_err(tls_err)?;
        let cert_der = cert.der().to_vec();
        Ok(Self {
            fingerprint: fingerprint(&cert_der),
            cert_der,
            key_der: key.serialize_der(),
        })
    }

    /// Lädt das gespeicherte Zertifikat oder erzeugt (und speichert) beim
    /// ersten Start ein neues. Ohne Speicherort gibt es ein flüchtiges.
    pub fn load_or_create(dir: Option<&Path>) -> io::Result<Self> {
        let Some(dir) = dir else {
            return Self::generate();
        };
        let (cert_path, key_path) = identity_paths(dir);
        if let Some(identity) = Self::load(&cert_path, &key_path) {
            return Ok(identity);
        }
        let identity = Self::generate()?;
        if let Err(e) = identity.save(&cert_path, &key_path) {
            eprintln!("TLS-Zertifikat konnte nicht gespeichert werden: {e}");
        }
        Ok(identity)
    }

    fn load(cert_path: &Path, key_path: &Path) -> Option<Self> {
        let cert_der = std::fs::read(cert_path).ok()?;
        let sealed = std::fs::read_to_string(key_path).ok()?;
        let key_der = open_secret(&sealed)?;
        let identity = Self {
            fingerprint: fingerprint(&cert_der),
            cert_der,
            key_der,
        };
        // Passen Schlüssel und Zertifikat zusammen? Sonst neu erzeugen.
        identity.server_config().ok().map(|_| identity)
    }

    fn save(&self, cert_path: &Path, key_path: &Path) -> io::Result<()> {
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let sealed = seal_secret(&self.key_der)
            .ok_or_else(|| io::Error::other("Schlüssel konnte nicht verschlüsselt werden"))?;
        std::fs::write(key_path, sealed)?;
        std::fs::write(cert_path, &self.cert_der)
    }

    /// TLS-Server-Konfiguration: nur TLS 1.3, dieses Zertifikat.
    pub fn server_config(&self) -> io::Result<Arc<ServerConfig>> {
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_der.clone()));
        let config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(tls_err)?
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(self.cert_der.clone())], key)
            .map_err(tls_err)?;
        Ok(Arc::new(config))
    }
}

/// Speicherorte: `tls-zertifikat.der` (öffentlich) und `tls-schluessel.dat`
/// (privater Schlüssel, DPAPI-verschlüsselt).
fn identity_paths(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join("tls-zertifikat.der"), dir.join("tls-schluessel.dat"))
}

/// Standard-Speicherort für das Zertifikat des Ziel-PCs.
pub fn identity_dir() -> Option<PathBuf> {
    app_data_dir()
}

/// Nimmt eine Verbindung als TLS-Server an (Handshake mit dem Zeitlimit, das
/// am Socket gesetzt ist).
pub fn accept(tcp: TcpStream, config: Arc<ServerConfig>) -> io::Result<ServerTls> {
    let conn = ServerConnection::new(config).map_err(tls_err)?;
    let mut tls = StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    Ok(tls)
}

// ---------------------------------------------------------------------------
// Haupt-PC: Verbindung aufbauen
// ---------------------------------------------------------------------------

/// Prüft die TLS-Signatur (der Ziel-PC muss den privaten Schlüssel zum
/// Zertifikat besitzen), akzeptiert aber jedes Zertifikat. Ob es das RICHTIGE
/// ist, entscheidet danach der Fingerabdruck-Vergleich (Pinning) und die
/// gegenseitige Anmeldung mit dem Verbindungscode.
#[derive(Debug)]
struct PinningVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinningVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn client_config() -> io::Result<Arc<ClientConfig>> {
    let provider = provider();
    let config = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_err)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinningVerifier { provider }))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Baut die TLS-Verbindung auf und liefert sie zusammen mit dem
/// Fingerabdruck des Zertifikats, das der Ziel-PC vorgezeigt hat.
pub fn connect(tcp: TcpStream) -> io::Result<(ClientTls, String)> {
    let name = ServerName::try_from(TLS_SERVER_NAME).map_err(tls_err)?;
    let conn = ClientConnection::new(client_config()?, name).map_err(tls_err)?;
    let mut tls = StreamOwned::new(conn, tcp);
    while tls.conn.is_handshaking() {
        tls.conn.complete_io(&mut tls.sock)?;
    }
    let fp = tls
        .conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert| fingerprint(cert.as_ref()))
        .ok_or_else(|| tls_err("kein Zertifikat erhalten"))?;
    Ok((tls, fp))
}

// ---------------------------------------------------------------------------
// Zeilen lesen ohne Datenverlust bei Zeitüberschreitung
// ---------------------------------------------------------------------------

/// Liest JSON-Zeilen. Anders als `BufRead::read_line` gehen bei einer
/// Zeitüberschreitung keine halb gelesenen Daten verloren - wichtig, weil die
/// Verbindung im Haupt-PC mit kurzem Zeitlimit abgefragt wird, damit
/// zwischendurch geschrieben werden kann.
#[derive(Default)]
pub struct LineReader {
    buf: Vec<u8>,
}

/// Ergebnis von [`LineReader::poll_line`].
pub enum Polled {
    Line(String),
    /// Gerade keine vollständige Zeile (Zeitlimit) - später erneut versuchen.
    Pending,
    /// Gegenseite hat die Verbindung sauber beendet.
    Closed,
}

impl LineReader {
    pub fn poll_line<R: Read>(&mut self, src: &mut R, max_len: usize) -> io::Result<Polled> {
        loop {
            if let Some(pos) = self.buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = self.buf.drain(..=pos).collect();
                let text = String::from_utf8(line)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "kein UTF-8"))?;
                return Ok(Polled::Line(text));
            }
            if self.buf.len() > max_len {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Nachricht ist zu groß"));
            }
            let mut chunk = [0u8; 8192];
            match src.read(&mut chunk) {
                Ok(0) => return Ok(Polled::Closed),
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                    ) =>
                {
                    return Ok(Polled::Pending)
                }
                // rustls meldet ein abruptes Ende ohne close_notify so.
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(Polled::Closed),
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn identity_is_stored_and_reused() {
        let dir = std::env::temp_dir().join(format!("abk-tls-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let first = AgentIdentity::load_or_create(Some(&dir)).unwrap();
        let again = AgentIdentity::load_or_create(Some(&dir)).unwrap();
        assert_eq!(first.fingerprint, again.fingerprint, "Zertifikat muss erhalten bleiben");
        assert_eq!(first.fingerprint.len(), 64);
        // Der private Schlüssel liegt nie im Klartext auf der Platte.
        let stored = std::fs::read(dir.join("tls-schluessel.dat")).unwrap();
        assert!(!stored.windows(again.key_der.len()).any(|w| w == again.key_der.as_slice()));
        // Kaputte Schlüsseldatei -> neues Zertifikat statt Absturz.
        std::fs::write(dir.join("tls-schluessel.dat"), "kaputt").unwrap();
        let fresh = AgentIdentity::load_or_create(Some(&dir)).unwrap();
        assert_ne!(fresh.fingerprint, first.fingerprint);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tls_roundtrip_reports_fingerprint_and_encrypts() {
        let identity = AgentIdentity::generate().unwrap();
        let expected = identity.fingerprint.clone();
        let config = identity.server_config().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let mut tls = accept(tcp, config).unwrap();
            let mut reader = LineReader::default();
            let line = loop {
                if let Polled::Line(l) = reader.poll_line(&mut tls, 1024).unwrap() {
                    break l;
                }
            };
            tls.write_all(line.to_uppercase().as_bytes()).unwrap();
            tls.flush().unwrap();
        });
        let (mut tls, fp) = connect(TcpStream::connect(addr).unwrap()).unwrap();
        assert_eq!(fp, expected);
        tls.write_all(b"geheimer inhalt\n").unwrap();
        tls.flush().unwrap();
        let mut reader = LineReader::default();
        let answer = loop {
            match reader.poll_line(&mut tls, 1024).unwrap() {
                Polled::Line(l) => break l,
                Polled::Closed => panic!("zu früh beendet"),
                Polled::Pending => {}
            }
        };
        assert_eq!(answer, "GEHEIMER INHALT\n");
        server.join().unwrap();
    }

    #[test]
    fn line_reader_keeps_partial_lines() {
        struct Chunks(Vec<io::Result<Vec<u8>>>);
        impl Read for Chunks {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                match self.0.remove(0) {
                    Ok(data) => {
                        out[..data.len()].copy_from_slice(&data);
                        Ok(data.len())
                    }
                    Err(e) => Err(e),
                }
            }
        }
        let mut src = Chunks(vec![
            Ok(b"{\"a\":".to_vec()),
            Err(io::Error::new(io::ErrorKind::TimedOut, "t")),
            Ok(b"1}\n{\"b\"".to_vec()),
        ]);
        let mut r = LineReader::default();
        assert!(matches!(r.poll_line(&mut src, 100).unwrap(), Polled::Pending));
        match r.poll_line(&mut src, 100).unwrap() {
            Polled::Line(l) => assert_eq!(l, "{\"a\":1}\n"),
            _ => panic!("Zeile erwartet"),
        }
        assert!(matches!(r.poll_line(&mut src, 100).unwrap(), Polled::Closed));
    }

    #[test]
    fn short_fingerprint_is_readable() {
        assert_eq!(short_fingerprint("3fa927bc91d4e0a1ffff"), "3FA9 27BC 91D4 E0A1");
    }
}
