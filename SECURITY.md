# Security

## Secrets

- Never commit .env or real credentials.
- Use .env.example only for placeholder, non-secret configuration.
- Rotate any credential that is accidentally exposed.
- CI runs Gitleaks to detect committed secrets.

## Reporting

Report suspected vulnerabilities privately to the project maintainer. Include
steps to reproduce and avoid sharing sensitive data in public issues.
