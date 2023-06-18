## snacme
A tool to request TLS certificates from the Let's Encrypt certificate authority using the 'dns-01' ACME challenge type.

It currently only supports the Porkbun API for DNS record updates. If a domain has API access enabled through Porkbun's Domain Management page, and the configuration file (see 'config.toml.example') is properly configured, the tool can simply be run to request certificates. This setup enables easy automation via e.g. `cron`.

Want something more tested/proven? Check out [Certbot](https://certbot.eff.org/) (of which I'm unaffiliated).

Usage of this tool currently implies acceptance of:
- The Porkbun Terms of Service and API Agreement
- The Let's Encrypt Terms of Service

Certificate related files are output as:
- a PEM encoded certificate
- a DER encoded private key

Basic usage:
- Copy the 'config.toml.example' somewhere (perhaps remove the '.example' part too) and edit it as necessary.
- Run this tool with `cargo run \[/path/to/config_file\]` from within this project directory to request the specified certificates.

Potential future features:
- Cloudflare DNS API support
- Better error handling
- Refactoring to enable use as a library
- Simplify usability of configuration file

References:
- [\[RFC 8555\] Automatic Certificate Management Environment (ACME)](https://www.rfc-editor.org/rfc/rfc8555.html)
- [\[RFC 7638\] JSON Web Key Thumbprint](https://www.rfc-editor.org/rfc/rfc7638)
- [\[RFC 7517\] JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)