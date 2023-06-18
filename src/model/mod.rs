pub mod signed_json;
pub mod account;
pub mod order;
pub mod authorization;

use serde::{Serialize, Deserialize};
use ureq::Response;
use sha2::{Digest, Sha256};
use base64ct::{Base64UrlUnpadded, Encoding};

pub(crate) const USIZE_LEN: usize = std::mem::size_of::<usize>();

/// Consolidates errors of a few types.
#[derive(Debug)]
pub enum Error {
    HttpIo(String),
    HttpGet(Response),
    HttpHead(Response),
    HttpPost(Response),
    ResponseIntoJson(String),
    ResponseIntoString(String),
    ResponseLacksLocation(Response),
    CertificateSerialize(String),
    CertificateUnavailable,
    JsonToVec(String),
    JsonFromBytes(String),
    SigningKeyFromBytes(String),
    ParseFromBytes(String),
}

/// Supported ACME challenge types.
pub enum ChallengeType {
    DNS,
}

impl Into<&str> for ChallengeType {
    fn into(self) -> &'static str {
        match self {
            Self::DNS => "dns-01",
        }
    }
}

/// An enum of supported Certificate Authority ACME APIs.
pub enum CertificateAuthority {
    LetsEncryptStaging,
    LetsEncryptProduction,
}

impl Into<&str> for CertificateAuthority {
    fn into(self) -> &'static str {
        match self {
            Self::LetsEncryptStaging => "https://acme-staging-v02.api.letsencrypt.org/directory",
            Self::LetsEncryptProduction => "https://acme-v02.api.letsencrypt.org/directory",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum Payload<'a> {
    #[serde(rename_all = "camelCase")]
    NewAccount {
        contact: &'a [String],
        terms_of_service_agreed: bool,
    },

    NewOrder {
        identifiers: &'a [Identifier],
    },

    Finalize {
        csr: String,
    },

    EmptyObject {},

    Empty
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct Identifier {
    pub r#type: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
    pub revoke_cert: String,

    pub account: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    pub r#type: String,
    pub url: String,
    pub token: String,
    pub status: Option<String>,
    pub validated: Option<String>,
    #[serde(skip)]
    pub domain: String,
    #[serde(skip)]
    pub response: String,
}

fn to_json_vec<T: Serialize>(data: &T) -> Result<Vec<u8>, Error> {
    serde_json::to_vec(&data)
        .map_err(|e| Error::JsonToVec(e.to_string()))
}

fn from_json_bytes<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T, Error> {
    serde_json::from_slice(&data)
        .map_err(|e| Error::JsonFromBytes(e.to_string()))
}

/// Make a simple HTTP HEAD request, returning the value of the given header.
fn http_head(url: &str) -> Result<Response, Error> {
    ureq::head(url)
        .call()
            .map_err(|e| {
                let e_str = e.to_string();

                if let Some(response) = e.into_response() {
                    Error::HttpHead(response)
                } else {
                    Error::HttpIo(e_str)
                }
            })
}

/// Make a simple HTTP GET request.
fn http_get(url: &str) -> Result<Response, Error> {
    ureq::get(url)
        .call()
            .map_err(|e| {
                let e_str = e.to_string();

                if let Some(response) = e.into_response() {
                    Error::HttpGet(response)
                } else {
                    Error::HttpIo(e_str)
                }
            })
}

fn http_post(url: &str, signed_json: signed_json::SignedJson) -> Result<Response, Error> {
    ureq::post(url)
        .set("content-type", "application/jose+json")
        .send_json(signed_json)
            .map_err(|e| {
                let e_str = e.to_string();

                if let Some(response) = e.into_response() {
                    Error::HttpPost(response)
                } else {
                    Error::HttpIo(e_str)
                }
            })
}

/// Make a simple HTTP GET request, attempting to parse the JSON response into a struct.
fn get_as_json<T: for<'a> Deserialize<'a>>(url: &str) -> Result<T, Error> {
    http_get(url)?
        .into_json()
            .map_err(|e| Error::ResponseIntoJson(e.to_string()))
}