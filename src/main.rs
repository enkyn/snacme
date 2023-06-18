mod api;
mod config;
mod model;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use api::porkbun::PorkbunAPI;
use config::{CertificateRequest, Config, DNSRecordsAPI, DomainRequest};
use model::account::Account;
use model::authorization::AuthStatus;
use model::{CertificateAuthority, ChallengeType};
use model::order::OrderStatus;

/// Attempt to convert the argument at `index` to a [PathBuf].
fn arg_as_path(index: usize) -> Option<PathBuf> {
    std::env::args()
        .nth(index)
        .map(|s| {
            let path = PathBuf::from(s);
            if path.is_file() {
                path
            } else {
                eprintln!("Provided path at argument {} was invalid!", index);
                std::process::exit(1);
            }
        })
}

/// Load a configuration file from the path specified by the binary's first argument.
fn get_config() -> Result<Config, String> {
    if let Some(path) = arg_as_path(1) {
        let config_string = std::fs::read_to_string(path)
            .map_err(|e| e.to_string())?;

        return toml::from_str(&config_string)
            .map_err(|e| e.to_string());
    } else {
        return Err(format!("Must specify the path to a configuration file!"));
    }
}

/// Load an account file from the path specified by the binary's second argument.
/// If that fails for some reason, attempt to just generate an account.
fn get_account(authority: CertificateAuthority) -> Result<Account, String> {
    if let Some(path) = arg_as_path(2) {
        let account_bytes = std::fs::read(path)
            .map_err(|e| e.to_string())?;

        return Account::try_from(account_bytes.as_slice())
            .map_err(|e| format!("{:?}", e));
    } else {
        return Account::generate(authority)
            .map_err(|e| format!("{:?}", e));
    }
}

/// Convert a vector of [CertificateRequest]s to a simpler form.
fn convert_requests(requests: &Vec<CertificateRequest>) -> Vec<(&str, Vec<(String, usize)>)> {
    let mut converted = Vec::new();

    for cert_request in requests {
        let mut domains = Vec::new();

        for DomainRequest { root, hosts } in &cert_request.domains {
            if let Some(hosts) = hosts {
                domains.extend(hosts.iter().map(|sub| {
                    if sub == "." {
                        (root.clone(), 0)
                    } else {
                        (format!("{sub}.{root}"), sub.len())
                    }
                }));
            } else {
                domains.push((root.clone(), 0));
            }
        }

        converted.push((cert_request.name.as_str(), domains));
    }

    converted
}

fn main() {
    let config: Config = get_config()
        .expect("Failed to load configuration file");

    // Convert the requested certificates into easier to work with forms.
    //   cert_requests: Certificates<Domains<(Domain, SubdomainSplitIndex)>>
    //   split_requests: Certificates<Domains<(Root, Option<Subdomain>)>>
    let cert_requests: Vec<(&str, Vec<(String, usize)>)> = convert_requests(&config.certs);
    let cert_map: Vec<Vec<(&str, String)>> = cert_requests.iter()
        .map(|(_, request)| {
            request.iter()
                .map(|(domain, sub_index)| {
                    let mut subdomain = String::from("_acme-challenge");
                    if *sub_index == 0 {
                        (domain.as_str(), subdomain)
                    } else {
                        let (sub, root) = domain.split_at(*sub_index);
                        subdomain.push_str(&format!(".{sub}"));

                        (root.strip_prefix('.').unwrap(), subdomain)
                    }
                })
                .collect()
        })
        .collect();
    
    // Load the DNS records API to use for this configuration.
    let dns_api = match config.dns_api {
        DNSRecordsAPI::Porkbun { keys } => PorkbunAPI::new(keys.secret, keys.public),
        _ => unimplemented!("Specified DNS API is currently unimplemented!")
    };

    // Generate/load an account.
    let mut account = match config.staging.unwrap_or(false) {
        true => get_account(CertificateAuthority::LetsEncryptStaging)
            .expect("Failed to generate/load staging account"),
        false => get_account(CertificateAuthority::LetsEncryptProduction)
            .expect("Failed to generate/load production account"),
    };

    // For each requested certificate...
    for (cert_index, (cert_name, requested_domains)) in cert_requests.iter().enumerate() {
        // Collect the domains needed for the order.
        let domains: Vec<&str> = requested_domains.iter()
            .map(|(domain, _)| domain.as_str())
            .collect();

        // Create the order, associated with the previously created account.
        let mut order = account.create_order(&domains)
            .expect("Failed to create an order");

        // Retrieve authorizations for the order.
        let authorizations = order.authorize(ChallengeType::DNS)
            .expect("Failed to retrieve order authorizations");

        // Create the necessary TXT DNS records.
        for authorization in authorizations.iter() {
            match authorization.status() {

                // Authorization pending, attempt to create the necessary TXT DNS record.
                AuthStatus::Pending => {
                    let challenge = &authorization.challenge;
                    let split_request_index = requested_domains.iter()
                        .position(|(domain, _)| domain == &challenge.domain);

                    if let Some(index) = split_request_index {
                        let (root, sub) = &cert_map[cert_index][index];

                        dns_api.create(Some(sub), root, &challenge.response)
                            .expect(&format!("Failed to create DNS TXT record for {}", root));
                    }

                },

                AuthStatus::Invalid => {
                    eprintln!("Authorization for {} became invalid, exiting...", authorization.challenge.domain);
                    std::process::exit(2);
                },

                AuthStatus::Valid => continue,
            }
        }

        // Wait a little bit for DNS records to propagate.
        std::thread::sleep(Duration::from_secs(20));

        // Notify that TXT DNS records are ready to be checked.
        order.ready(authorizations)
            .expect("Failed to notify of DNS records readiness");

        // Loop while waiting for order completion.
        let start_time = Instant::now();
        let mut wait_time = Duration::from_secs(5);
        while let Ok(status) = order.status() {
            match status {
                OrderStatus::Pending | OrderStatus::Processing => {
                    // Wait a little longer next time.
                    if wait_time.as_secs() < 60 {
                        wait_time += Duration::from_secs(5);
                    }
                },

                OrderStatus::Ready => {
                    order.finalize()
                        .expect("Failed to finalize order");
                },

                // Order became invalid, just delete the previously created DNS records.
                OrderStatus::Invalid => {
                    eprintln!("Order became invalid. Reverting created TXT DNS records and exiting...");

                    for (root, sub) in &cert_map[cert_index] {
                        dns_api.delete(Some(sub), root)
                            .expect(&format!("Failed to delete DNS TXT record for {}", root));
                    }

                    break;
                },

                OrderStatus::Valid => {
                    let output_dir = PathBuf::from(&config.output_directory);
                    let (cert, key) = order.download()
                        .expect("Failed to download the certificate");

                    println!("Order for '{cert_name}' complete! Writing files...");

                    // Attempt to create the output directory.
                    std::fs::create_dir_all(&output_dir)
                        .expect("Failed to create output directory");

                    // Attempt to write the certificate and private key files.
                    std::fs::write(output_dir.join(format!("{cert_name}.pem")), cert.as_bytes())
                        .expect("Failed to write PEM encoded certificate file");
                    std::fs::write(output_dir.join(format!("{cert_name}.der")), &key)
                        .expect("Failed to write DER encoded private key file");

                    for (root, sub) in &cert_map[cert_index] {
                        dns_api.delete(Some(sub), root)
                            .expect(&format!("Failed to delete DNS TXT record for {}", root));
                    }

                    println!("Done!");
                    
                    break;
                }
            }

            // Exit if waiting for order completion took more than 5 minutes.
            if start_time.elapsed().as_secs() > 300 {
                eprintln!("Order took longer than 5 minutes to complete.");
                eprintln!("Reverting created TXT DNS records and exiting...");

                for (root, sub) in &cert_map[cert_index] {
                    dns_api.delete(Some(sub), root)
                        .expect(&format!("Failed to delete DNS TXT record for {}", root));
                }

                break;
            }
        }
    }
}