//! Device identity comes only from the verified client certificate:
//! URI SAN `spiffe://scanu/tenant/<tenant_id>/device/<device_id>`.

use tonic::{Request, Status};
use x509_parser::prelude::*;

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceIdentity {
    pub tenant_id: String,
    pub device_id: String,
}

pub fn parse_spiffe(uri: &str) -> Option<DeviceIdentity> {
    let rest = uri.strip_prefix("spiffe://scanu/tenant/")?;
    let (tenant, rest) = rest.split_once("/device/")?;
    let ok = |s: &str| !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
    (ok(tenant) && ok(rest)).then(|| DeviceIdentity { tenant_id: tenant.into(), device_id: rest.into() })
}

pub fn from_der(der: &[u8]) -> Option<DeviceIdentity> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;
    let san = cert.subject_alternative_name().ok()??;
    san.value.general_names.iter().find_map(|g| match g {
        GeneralName::URI(u) => parse_spiffe(u),
        _ => None,
    })
}

pub fn from_request<T>(req: &Request<T>) -> Result<DeviceIdentity, Status> {
    let certs = req.peer_certs().ok_or_else(|| Status::unauthenticated("client certificate required"))?;
    let leaf = certs.first().ok_or_else(|| Status::unauthenticated("empty certificate chain"))?;
    from_der(leaf.as_ref()).ok_or_else(|| Status::permission_denied("certificate has no scanu device identity"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_well_formed_identities() {
        assert_eq!(
            parse_spiffe("spiffe://scanu/tenant/t-1/device/dev-9"),
            Some(DeviceIdentity { tenant_id: "t-1".into(), device_id: "dev-9".into() })
        );
        for bad in [
            "spiffe://other/tenant/t/device/d",
            "spiffe://scanu/tenant//device/d",
            "spiffe://scanu/tenant/t/device/d/../../x",
            "spiffe://scanu/tenant/t'or 1=1/device/d",
        ] {
            assert!(parse_spiffe(bad).is_none(), "{bad}");
        }
    }
}
