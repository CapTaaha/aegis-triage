# AegisTriage

## Secure analysis configuration

The analysis API is disabled by default. Configure these server-only Nitro environment variables before enabling it:

- `NITRO_ANALYSIS_API_KEY`: a random administrator key of at least 32 characters.
- `NITRO_ANALYSIS_REPOSITORIES`: comma-separated exact HTTPS repository URLs, such as `https://github.com/juice-shop/juice-shop`.
- `NITRO_ANALYSIS_LOCAL_ROOTS`: comma-separated absolute directories that may contain local analysis targets. Leave empty in network-accessible deployments to disable local-folder analysis.
- `NITRO_ANALYSIS_WEBSITE_HOSTS`: comma-separated exact hostnames approved for passive crawling.

The acknowledgement checkbox records operator intent only; authorization is enforced by the server key and server-managed target lists. Analysis responses contain only short, redacted finding excerpts rather than complete function source.
