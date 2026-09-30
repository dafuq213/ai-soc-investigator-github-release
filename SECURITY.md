# Security policy

## Reporting a vulnerability

Do not open a public issue containing credentials, alert payloads, hostnames,
usernames, internal addresses, or investigation reports. Report security issues
privately to the repository owner.

## Sensitive local data

The application stores reports, evidence packets, prompt audits, and usage data
under `data/`. Local Wazuh and model credentials belong in `.wazuh.local.env`
and `.env`. These paths are excluded from Git and must remain excluded in forks.

Use read-only Wazuh Indexer credentials and rotate a credential immediately if
it is accidentally committed or shared.
