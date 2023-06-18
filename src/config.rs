use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct DomainRequest {
    pub root: String,
    pub hosts: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct CertificateRequest {
    pub name: String,
    #[serde(alias = "domain")]
    pub domains: Vec<DomainRequest>,
}

#[derive(Debug, Deserialize)]
pub struct PorkbunKeys {
    pub public: String,
    pub secret: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DNSRecordsAPI {
    Porkbun {
        #[serde(alias = "key")]
        keys: PorkbunKeys,
    },

    Cloudflare {}
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(alias = "directory")]
    pub output_directory: String,
    pub staging: Option<bool>,
    #[serde(alias = "api")]
    pub dns_api: DNSRecordsAPI,
    #[serde(alias = "certificate")]
    pub certs: Vec<CertificateRequest>,
}