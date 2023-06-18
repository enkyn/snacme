use serde::{Serialize, Deserialize};

enum Endpoint<'a> {
    Ping,

    RecordCreate(&'a str), // domain

    RecordEditId(String, String), // domain, record ID
    RecordDeleteId(String, String),
    RecordRetrieveId(String, Option<String>),

    RecordEditType(String, Option<String>, &'static str),
    RecordDeleteType(&'a str, Option<&'a str>, &'static str),
    RecordRetrieveType(String, Option<String>, &'static str),
}

impl<'a> Into<String> for Endpoint<'a> {
    fn into(self) -> String {
        match self {
            Self::Ping => {
                "https://porkbun.com/api/json/v3/ping".to_string()
            },
            Self::RecordCreate(domain) => {
                format!("https://porkbun.com/api/json/v3/dns/create/{domain}")
            },

            Self::RecordEditId(domain, id) => {
                format!("https://porkbun.com/api/json/v3/dns/edit/{domain}/{id}")
            },
            Self::RecordDeleteId(domain, id) => {
                format!("https://porkbun.com/api/json/v3/dns/delete/{domain}/{id}")
            },
            Self::RecordRetrieveId(domain, id) => {
                format!("https://porkbun.com/api/json/v3/dns/retrieve/{domain}/{id}",
                    id = id.unwrap_or(String::new()))
            },

            Self::RecordEditType(domain, subdomain, r#type) => {
                format!("https://porkbun.com/api/json/v3/dns/editByNameType/{domain}/{type}/{subdomain}",
                    subdomain = subdomain.unwrap_or(String::new()))
            },
            Self::RecordDeleteType(domain, subdomain, r#type) => {
                format!("https://porkbun.com/api/json/v3/dns/deleteByNameType/{domain}/{type}/{subdomain}",
                    subdomain = subdomain.unwrap_or(""))
            },
            Self::RecordRetrieveType(domain, subdomain, r#type) => {
                format!("https://porkbun.com/api/json/v3/dns/retrieveByNameType/{domain}/{type}/{subdomain}",
                    subdomain = subdomain.unwrap_or(String::new()))
            },
        }
    }
}

#[derive(Serialize)]
struct Keys {
    secretapikey: String,
    apikey: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum Payload<'a> {
    Ping(&'a Keys),

    RecordCreate {
        #[serde(flatten)]
        keys: &'a Keys,
        name: Option<&'a str>,
        r#type: &'static str,
        content: &'a str,
        ttl: Option<&'static str>,
        prio: Option<&'a str>,
    },

    RecordDelete(&'a Keys),
}

#[derive(Debug, Deserialize)]
struct Record {
    id: String,
    name: String,
    r#type: String,
    content: String,
    ttl: String,
    prio: String,
    notes: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PbResponse {
    status: String,
    pub your_ip: Option<String>,
    pub records: Option<Vec<Record>>,
    pub id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct PbError {
    status: String,
    pub message: String,
}

/// Just enough of an interface to the Porkbun API to create and delete DNS records.
pub struct PorkbunAPI {
    keys: Keys,
    agent: ureq::Agent,
}

impl PorkbunAPI {
    /// Use the given keys for Porkbun API access.
    pub fn new(secret_key: String, public_key: String) -> Self {
        let agent = ureq::AgentBuilder::new()
            .middleware(json_header)
            .build();
        
        Self {
            keys: Keys {
                secretapikey: secret_key,
                apikey: public_key,
            },
            agent: agent,
        }
    }

    /// Ping the Porkbun API, returning your IP address.
    pub fn ping(&self) -> Result<String, String> {
        let endpoint: String = Endpoint::Ping.into();

        self.agent.post(&endpoint)
            .send_json(Payload::Ping(&self.keys))
            .map(|r| {
                let response: PbResponse = r.into_json().unwrap();
                response.your_ip.unwrap()
            })
            .map_err(|e| {
                let response: PbError = e.into_response().unwrap().into_json().unwrap();
                response.message
            })
    }

    /// Create a TXT record, returning the record ID.
    pub fn create(&self, subdomain: Option<&str>, domain: &str, value: &str) -> Result<u64, String> {
        let endpoint: String = Endpoint::RecordCreate(domain).into();

        self.agent.post(&endpoint)
            .send_json(Payload::RecordCreate {
                keys: &self.keys,
                name: subdomain,
                r#type: "TXT",
                content: value,
                ttl: None,
                prio: None,
            })
            .map(|r| {
                let response: PbResponse = r.into_json().unwrap();
                response.id.unwrap()
            })
            .map_err(|e| {
                let response: PbError = e.into_response().unwrap().into_json().unwrap();
                response.message
            })
    }

    /// Delete a TXT record.
    pub fn delete(&self, subdomain: Option<&str>, domain: &str) -> Result<(), String> {
        let endpoint: String = Endpoint::RecordDeleteType(domain, subdomain, "TXT").into();

        self.agent.post(&endpoint)
            .send_json(Payload::RecordDelete(&self.keys))
            .map(|r| {
                let _response: PbResponse = r.into_json().unwrap();
            })
            .map_err(|e| {
                let response: PbError = e.into_response().unwrap().into_json().unwrap();
                response.message
            })
    }
}

fn json_header(req: ureq::Request, next: ureq::MiddlewareNext) -> Result<ureq::Response, ureq::Error> {
    next.handle(req.set("content-type", "application/json"))
}