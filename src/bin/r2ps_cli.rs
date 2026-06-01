use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};
use p256::{pkcs8::DecodePrivateKey, pkcs8::DecodePublicKey, PublicKey, SecretKey};
use r2ps_client::{
    error::{R2psError, Result},
    PakeClient, R2psClient, Transport,
};

/// R2PS command-line client for remote PAKE-protected services.
#[derive(Parser)]
#[command(name = "r2ps-cli", version, about)]
struct Cli {
    /// R2PS server endpoint URL (e.g. https://r2ps.example.com/r2ps)
    #[arg(long, env = "R2PS_URL")]
    url: String,

    /// Client identity
    #[arg(long, env = "R2PS_CLIENT_ID")]
    client_id: String,

    /// Security context
    #[arg(long, env = "R2PS_CONTEXT")]
    context: String,

    /// Path to client private key (SEC1 PEM or raw 32-byte hex)
    #[arg(long, env = "R2PS_CLIENT_KEY")]
    client_key: PathBuf,

    /// Path to server public key (SEC1 PEM or uncompressed hex)
    #[arg(long, env = "R2PS_SERVER_PUB")]
    server_pub: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register 2FA credentials with the server
    Register,

    /// Authenticate and establish a 2FA session
    Auth,

    /// Generate a remote P-256 key pair (requires prior auth)
    Keygen {
        /// EC curve name
        #[arg(long, default_value = "P-256")]
        curve: String,
    },

    /// List remote HSM keys (requires prior auth)
    ListKeys {
        /// Filter by curve names (e.g. P-256,P-384). Empty = all.
        #[arg(long, value_delimiter = ',')]
        curves: Vec<String>,
    },

    /// Sign a hash using a remote key (requires prior auth)
    Sign {
        /// Key identifier (kid) — hex-encoded compressed public key
        #[arg(long)]
        kid: String,

        /// Hex-encoded hash to sign
        #[arg(long)]
        hash: String,
    },

    /// Perform ECDH key agreement using a remote key (requires prior auth)
    Ecdh {
        /// Key identifier (kid) — hex-encoded compressed public key
        #[arg(long)]
        kid: String,

        /// Peer public key in SPKI DER base64
        #[arg(long)]
        peer_pub: String,
    },

    /// Probe server health
    Health,
}

// --- HTTP Transport using ureq ---

struct HttpTransport {
    url: String,
}

impl Transport for HttpTransport {
    fn send(&self, body: &[u8]) -> Result<Vec<u8>> {
        let resp = ureq::post(&self.url)
            .set("Content-Type", "application/jose")
            .send_bytes(body)
            .map_err(|e| R2psError::Transport(e.to_string()))?;

        let mut buf = Vec::new();
        resp.into_reader()
            .read_to_end(&mut buf)
            .map_err(|e| R2psError::Transport(e.to_string()))?;
        Ok(buf)
    }
}

// --- Stub PAKE client (prompts for PIN, no real OPAQUE yet) ---

struct StubPakeClient;

impl PakeClient for StubPakeClient {
    fn registration_init(&mut self, password: &[u8]) -> Result<Vec<u8>> {
        // Placeholder: a real implementation needs an OPAQUE crate
        let _ = password;
        Err(R2psError::Pake(
            "OPAQUE not yet integrated — provide a PakeClient implementation".into(),
        ))
    }

    fn registration_finalize(&mut self, _server_resp: &[u8]) -> Result<Vec<u8>> {
        Err(R2psError::Pake("stub".into()))
    }

    fn auth_init(&mut self, password: &[u8]) -> Result<Vec<u8>> {
        let _ = password;
        Err(R2psError::Pake(
            "OPAQUE not yet integrated — provide a PakeClient implementation".into(),
        ))
    }

    fn auth_finalize(&mut self, _server_resp: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        Err(R2psError::Pake("stub".into()))
    }
}

// --- Key loading helpers ---

fn load_secret_key(path: &PathBuf) -> SecretKey {
    let data = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!("error: cannot read client key {}: {e}", path.display());
        process::exit(1);
    });
    let trimmed = data.trim();

    // Try hex (32 bytes = 64 hex chars)
    if let Ok(bytes) = hex::decode(trimmed) {
        if bytes.len() == 32 {
            return SecretKey::from_slice(&bytes).unwrap_or_else(|e| {
                eprintln!("error: invalid secret key bytes: {e}");
                process::exit(1);
            });
        }
    }

    // Try SEC1/PKCS8 PEM
    if trimmed.starts_with("-----") {
        // Strip PEM armor and decode base64
        let b64: String = trimmed
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        if let Ok(der) = base64ct::Base64::decode_vec(&b64) {
            // Try as raw 32-byte key in the DER
            if der.len() >= 32 {
                // SEC1 EC private key: the raw key is the last 32 bytes of the
                // inner OCTET STRING. For simplicity, try from PKCS8 first.
                if let Ok(sk) = SecretKey::from_sec1_der(&der) {
                    return sk;
                }
                if let Ok(sk) = SecretKey::from_pkcs8_der(&der) {
                    return sk;
                }
            }
        }
    }

    eprintln!(
        "error: cannot parse client key from {} (expected 64-char hex or PEM)",
        path.display()
    );
    process::exit(1);
}

fn load_public_key(path: &PathBuf) -> PublicKey {
    let data = fs::read_to_string(path).unwrap_or_else(|e| {
        eprintln!(
            "error: cannot read server public key {}: {e}",
            path.display()
        );
        process::exit(1);
    });
    let trimmed = data.trim();

    // Try hex (65 bytes uncompressed = 130 hex chars, or 33 compressed = 66)
    if let Ok(bytes) = hex::decode(trimmed) {
        if bytes.len() == 65 || bytes.len() == 33 {
            return PublicKey::from_sec1_bytes(&bytes).unwrap_or_else(|e| {
                eprintln!("error: invalid public key bytes: {e}");
                process::exit(1);
            });
        }
    }

    // Try PEM
    if trimmed.starts_with("-----") {
        let b64: String = trimmed
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        if let Ok(der) = base64ct::Base64::decode_vec(&b64) {
            if let Ok(pk) = PublicKey::from_public_key_der(&der) {
                return pk;
            }
        }
    }

    eprintln!(
        "error: cannot parse server public key from {} (expected hex or PEM)",
        path.display()
    );
    process::exit(1);
}

use base64ct::Encoding;
use std::io::Read;

fn main() {
    let cli = Cli::parse();

    // Health check doesn't need crypto
    if matches!(cli.command, Command::Health) {
        let health_url = cli.url.trim_end_matches("/r2ps").to_string() + "/healthz";
        match ureq::get(&health_url).call() {
            Ok(resp) => {
                let mut body = String::new();
                resp.into_reader().read_to_string(&mut body).ok();
                println!("{body}");
            }
            Err(e) => {
                eprintln!("error: health check failed: {e}");
                process::exit(1);
            }
        }
        return;
    }

    let client_key = load_secret_key(&cli.client_key);
    let server_pub = load_public_key(&cli.server_pub);

    let transport = HttpTransport {
        url: cli.url.clone(),
    };
    let pake = StubPakeClient;

    let mut client = R2psClient::new(
        cli.client_id,
        cli.context,
        client_key,
        server_pub,
        transport,
        pake,
    );

    match cli.command {
        Command::Health => unreachable!(),

        Command::Register => {
            let pin = rpassword::prompt_password("PIN: ").unwrap_or_else(|e| {
                eprintln!("error: cannot read PIN: {e}");
                process::exit(1);
            });
            match client.register(pin.as_bytes()) {
                Ok(()) => println!("registration complete"),
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            }
        }

        Command::Auth => {
            let pin = rpassword::prompt_password("PIN: ").unwrap_or_else(|e| {
                eprintln!("error: cannot read PIN: {e}");
                process::exit(1);
            });
            match client.authenticate(pin.as_bytes()) {
                Ok(()) => {
                    println!("authenticated");
                    if let Some(sid) = client.session_id() {
                        println!("session_id: {sid}");
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            }
        }

        Command::Keygen { curve } => {
            let pin = rpassword::prompt_password("PIN: ").unwrap_or_else(|e| {
                eprintln!("error: cannot read PIN: {e}");
                process::exit(1);
            });
            if let Err(e) = client.authenticate(pin.as_bytes()) {
                eprintln!("error: authentication failed: {e}");
                process::exit(1);
            }

            // Step 1: Create key
            let req = serde_json::json!({ "curve": curve });

            match client.call_service("p256_generate", &req) {
                Ok(resp) => {
                    if let Some(key) = resp.get("created_key") {
                        println!("created_key: {}", key);
                    }

                    // Step 2: List keys to find the new kid
                    let list_req = serde_json::json!({ "curve": [curve] });

                    if let Ok(list_resp) = client.call_service("hsm_list_keys", &list_req) {
                        if let Some(key_info) = list_resp.get("key_info").and_then(|v| v.as_array())
                        {
                            if let Some(newest) = key_info.iter().max_by_key(|k| {
                                k.get("creation_time").and_then(|v| v.as_i64()).unwrap_or(0)
                            }) {
                                if let Some(kid) = newest.get("kid").and_then(|v| v.as_str()) {
                                    println!("kid: {kid}");
                                }
                                if let Some(pk) = newest.get("public_key").and_then(|v| v.as_str())
                                {
                                    println!("public_key: {pk}");
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: keygen failed: {e}");
                    process::exit(1);
                }
            }
        }

        Command::ListKeys { curves } => {
            let pin = rpassword::prompt_password("PIN: ").unwrap_or_else(|e| {
                eprintln!("error: cannot read PIN: {e}");
                process::exit(1);
            });
            if let Err(e) = client.authenticate(pin.as_bytes()) {
                eprintln!("error: authentication failed: {e}");
                process::exit(1);
            }

            let req = serde_json::json!({ "curve": curves });

            match client.call_service("hsm_list_keys", &req) {
                Ok(resp) => {
                    if let Some(key_info) = resp.get("key_info").and_then(|v| v.as_array()) {
                        for ki in key_info {
                            println!(
                                "kid={} curve={} created={} pub={}",
                                ki.get("kid").and_then(|v| v.as_str()).unwrap_or(""),
                                ki.get("curve_name").and_then(|v| v.as_str()).unwrap_or(""),
                                ki.get("creation_time")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(0),
                                ki.get("public_key").and_then(|v| v.as_str()).unwrap_or(""),
                            );
                        }
                        if key_info.is_empty() {
                            println!("(no keys)");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: list-keys failed: {e}");
                    process::exit(1);
                }
            }
        }

        Command::Sign {
            kid: sign_kid,
            hash,
        } => {
            let pin = rpassword::prompt_password("PIN: ").unwrap_or_else(|e| {
                eprintln!("error: cannot read PIN: {e}");
                process::exit(1);
            });
            if let Err(e) = client.authenticate(pin.as_bytes()) {
                eprintln!("error: authentication failed: {e}");
                process::exit(1);
            }

            let hash_bytes = hex::decode(&hash).unwrap_or_else(|e| {
                eprintln!("error: invalid hex hash: {e}");
                process::exit(1);
            });

            let req = serde_json::json!({
                "kid": sign_kid,
                "tbs_hash": base64ct::Base64::encode_string(&hash_bytes),
            });

            match client.call_service("sign_ecdsa", &req) {
                Ok(resp) => {
                    if let Some(sig) = resp.as_str() {
                        if let Ok(sig_bytes) = base64ct::Base64::decode_vec(sig) {
                            println!("{}", hex::encode(&sig_bytes));
                        } else {
                            println!("{sig}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: sign failed: {e}");
                    process::exit(1);
                }
            }
        }

        Command::Ecdh {
            kid: ecdh_kid,
            peer_pub,
        } => {
            let pin = rpassword::prompt_password("PIN: ").unwrap_or_else(|e| {
                eprintln!("error: cannot read PIN: {e}");
                process::exit(1);
            });
            if let Err(e) = client.authenticate(pin.as_bytes()) {
                eprintln!("error: authentication failed: {e}");
                process::exit(1);
            }

            let req = serde_json::json!({
                "kid": ecdh_kid,
                "public_key": peer_pub,
            });

            match client.call_service("agree_ecdh", &req) {
                Ok(resp) => {
                    if let Some(secret) = resp.as_str() {
                        if let Ok(secret_bytes) = base64ct::Base64::decode_vec(secret) {
                            println!("{}", hex::encode(&secret_bytes));
                        } else {
                            println!("{secret}");
                        }
                    }
                }
                Err(e) => {
                    eprintln!("error: ecdh failed: {e}");
                    process::exit(1);
                }
            }
        }
    }
}
