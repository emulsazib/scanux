//! Development PKI. NEVER use these keys outside a dev machine: production
//! roots are offline/HSM-held and the command-signing key lives in KMS.
//!
//!   devpki init   --out deploy/pki/out
//!   devpki device --out deploy/pki/out --tenant <uuid> --device <id>
//!   devpki bundle --out deploy/pki/out --device <id> --gateway https://host:7443 > enroll.json
//!       (then on the PC, elevated: scanu-sensor.exe enroll enroll.json)

use clap::{Parser, Subcommand};
use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
use ed25519_dalek::pkcs8::{EncodePrivateKey, EncodePublicKey};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
    KeyPair, KeyUsagePurpose, SanType,
};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "deploy/pki/out")]
    out: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// CA, gateway server cert, command-signing key.
    Init,
    /// Enrollment bundle (JSON on stdout) for `scanu-sensor.exe enroll`. Contains the device private key.
    Bundle {
        #[arg(long)]
        device: String,
        #[arg(long)]
        gateway: String,
        /// TLS name in the gateway cert, if it differs from the URL host.
        #[arg(long)]
        tls_name: Option<String>,
    },
    /// Device client cert bound to a tenant via a SPIFFE URI SAN.
    Device {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        device: String,
    },
}

type R<T> = Result<T, Box<dyn std::error::Error>>;

fn write(p: &Path, s: &str) -> R<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(p, s)?;
    println!("wrote {}", p.display());
    Ok(())
}

fn ca_issuer(out: &Path) -> R<Issuer<'static, KeyPair>> {
    let key = KeyPair::from_pem(&std::fs::read_to_string(out.join("ca.key"))?)?;
    Ok(Issuer::from_ca_cert_pem(&std::fs::read_to_string(out.join("ca.pem"))?, key)?)
}

fn main() -> R<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Init => {
            let mut p = CertificateParams::new(Vec::<String>::new())?;
            p.distinguished_name = DistinguishedName::new();
            p.distinguished_name.push(DnType::CommonName, "Scanu Dev Root CA");
            p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let ca_key = KeyPair::generate()?;
            let ca = p.self_signed(&ca_key)?;
            write(&cli.out.join("ca.pem"), &ca.pem())?;
            write(&cli.out.join("ca.key"), &ca_key.serialize_pem())?;

            let issuer = ca_issuer(&cli.out)?;
            let mut g = CertificateParams::new(vec!["localhost".to_string(), "gateway".to_string()])?;
            g.subject_alt_names.push(SanType::IpAddress("127.0.0.1".parse()?));
            g.distinguished_name.push(DnType::CommonName, "scanu-gateway");
            g.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let gk = KeyPair::generate()?;
            write(&cli.out.join("gateway.pem"), &g.signed_by(&gk, &issuer)?.pem())?;
            write(&cli.out.join("gateway.key"), &gk.serialize_pem())?;

            let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
            let vk = sk.verifying_key();
            let key_id = format!("cmd-{}", &hex::encode(Sha256::digest(vk.as_bytes()))[..12]);
            // PKCS#8 v1 (no embedded public key): what OpenSSL writes and every consumer parses.
            let v1 = ed25519_dalek::pkcs8::KeypairBytes { secret_key: sk.to_bytes(), public_key: None };
            write(&cli.out.join("cmd-signing.key.pem"), &v1.to_pkcs8_pem(LineEnding::LF)?)?;
            write(&cli.out.join("cmd-signing.pub.pem"), &vk.to_public_key_pem(LineEnding::LF)?)?;
            write(&cli.out.join("cmd-signing.key_id"), &key_id)?;
        }
        Cmd::Bundle { device, gateway, tls_name } => {
            let read = |p: PathBuf| std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()));
            let dev = cli.out.join("devices");
            let bundle = serde_json::json!({
                "device_id": device,
                "gateway": gateway,
                "gateway_tls_name": tls_name,
                "ca_pem": read(cli.out.join("ca.pem"))?,
                "device_cert_pem": read(dev.join(format!("{device}.pem")))?,
                "device_key_pem": read(dev.join(format!("{device}.key")))?,
                "cmd_signing_pub_pem": read(cli.out.join("cmd-signing.pub.pem"))?,
                "cmd_signing_key_id": read(cli.out.join("cmd-signing.key_id"))?.trim(),
            });
            println!("{}", serde_json::to_string_pretty(&bundle)?);
        }
        Cmd::Device { tenant, device } => {
            if !tenant.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                || !device.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            {
                return Err("tenant/device must be [A-Za-z0-9-]".into());
            }
            let issuer = ca_issuer(&cli.out)?;
            let mut d = CertificateParams::new(Vec::<String>::new())?;
            d.subject_alt_names
                .push(SanType::URI(format!("spiffe://scanu/tenant/{tenant}/device/{device}").try_into()?));
            d.distinguished_name.push(DnType::CommonName, device.clone());
            d.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
            let dk = KeyPair::generate()?;
            let dir = cli.out.join("devices");
            write(&dir.join(format!("{device}.pem")), &d.signed_by(&dk, &issuer)?.pem())?;
            write(&dir.join(format!("{device}.key")), &dk.serialize_pem())?;
        }
    }
    Ok(())
}
