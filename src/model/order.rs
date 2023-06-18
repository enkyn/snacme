use super::*;
use super::account::*;
use super::authorization::*;

use rcgen::{CertificateParams, DistinguishedName};
use rcgen::Certificate;

pub enum OrderStatus {
    Invalid,
    Pending,
    Ready,
    Processing,
    Valid,
}

impl From<&str> for OrderStatus {
    fn from(s: &str) -> Self {
        match s {
            "pending" => Self::Pending,
            "ready" => Self::Ready,
            "processing" => Self::Processing,
            "valid" => Self::Valid,
            _ => Self::Invalid,
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct OrderData {
    pub status: String,
    expires: String,
    pub identifiers: Vec<Identifier>,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

pub struct Order<'a> {
    pub(crate) url: String,
    pub(crate) data: OrderData,
    pub(crate) account: &'a Account,
    pub(crate) certificate: Option<Certificate>,
}

impl<'a> Order<'a> {
    /// Retrieve [Authorization]s for this [Order], returning only those that match the given [ChallengeType].
    pub fn authorize(&self, ct: ChallengeType) -> Result<Vec<Authorization>, Error> {
        let challenge_type: &str = ct.into();
        let mut authorizations = Vec::new();
        for auth_url in &self.data.authorizations {
            let auth_data: AuthData = self.account.post_as_json(&auth_url, Payload::Empty)?;
            
            for challenge in &auth_data.challenges {
                if challenge.r#type == challenge_type {
                    let mut challenge = challenge.clone();
                    let response = format!("{}.{}", challenge.token,
                        self.account.crypto.thumbprint);
                    
                    challenge.domain = auth_data.identifier.value.clone();
                    challenge.response = Base64UrlUnpadded::encode_string(&Sha256::digest(response));

                    authorizations.push(Authorization {
                        url: auth_url,
                        data: auth_data,
                        challenge: challenge,
                    });

                    break;
                }
            }
        }

        Ok(authorizations)
    }

    /// Notify the server of challenge readiness for the given [Authorization]s.
    pub fn ready(&self, authorizations: Vec<Authorization>) -> Result<Vec<Challenge>, Error> {
        let mut challenges = Vec::new();

        for auth in authorizations {
            let mut challenge: Challenge = self.account.post_as_json(&auth.challenge.url, Payload::EmptyObject {})?;
            challenge.domain = auth.challenge.domain.clone();

            challenges.push(challenge);
        }

        Ok(challenges)
    }

    /// Check the current [Order] status.
    pub fn status(&mut self) -> Result<OrderStatus, Error> {
        self.data = self.account.post_as_json(&self.url, Payload::Empty)?;

        Ok(OrderStatus::from(self.data.status.as_str()))
    }

    /// Ask the server to finalize/complete the order and start generating a certificate.
    pub fn finalize(&mut self) -> Result<(), Error> {
        let identifiers: Vec<String> = self.data.identifiers.iter()
            .map(|id| id.value.to_string())
            .collect();
        
        // Generate a Certificate Signing Request.
        let mut cert_params = CertificateParams::new(identifiers);
        cert_params.distinguished_name = DistinguishedName::new();
        self.certificate = Certificate::from_params(cert_params).ok();

        if let Some(ref cert) = self.certificate {
            let cert_der = cert.serialize_request_der()
                .map_err(|e| Error::CertificateSerialize(e.to_string()))?;
            let csr = Base64UrlUnpadded::encode_string(&cert_der);

            self.data = self.account.post_as_json(&self.data.finalize,
                Payload::Finalize { csr })?;
        }

        Ok(())
    }

    /// Download the certificate, returning the PEM encoded certificate and DER encoded private key.
    pub fn download(&self) -> Result<(String, Vec<u8>), Error> {
        if let OrderStatus::Valid = OrderStatus::from(self.data.status.as_str()) {
            if let Some(cert_url) = self.data.certificate.clone() {
                let response = self.account.post(&cert_url, Payload::Empty)?;
                let private_key = self.certificate.as_ref().unwrap()
                    .serialize_private_key_der();

                let cert_pem = response.into_string()
                    .map_err(|e| Error::ResponseIntoString(e.to_string()))?;
                
                return Ok((cert_pem, private_key));
            }
        }

        Err(Error::CertificateUnavailable)
    }
}