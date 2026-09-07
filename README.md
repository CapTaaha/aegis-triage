# AegisTriage

## Secure analysis configuration

The analysis API is disabled by default. Configure these server-only Nitro environment variables before enabling it:

- `NITRO_ANALYSIS_API_KEY`: a random administrator key of at least 32 characters.
- `NITRO_ANALYSIS_WORKER_SECRET`: a different random value of at least 32 characters, used only between the Nitro API and the Vercel Python function.
- `NITRO_ANALYSIS_REPOSITORIES`: comma-separated exact HTTPS repository URLs, such as `https://github.com/juice-shop/juice-shop`.
- `NITRO_ANALYSIS_LOCAL_ROOTS`: comma-separated absolute directories that may contain local analysis targets. Leave empty in network-accessible deployments to disable local-folder analysis.
- `NITRO_ANALYSIS_WEBSITE_HOSTS`: comma-separated exact hostnames approved for passive crawling.

On Vercel, repository analysis runs in the dedicated Python function and uses the pure-Python Dulwich client, so it does not depend on a `python3` or `git` executable inside the Node.js function. Local-folder analysis is intentionally unavailable on Vercel because serverless filesystems are ephemeral and must not expose deployment files.

The acknowledgement checkbox records operator intent only; authorization is enforced by the server key and server-managed target lists. Analysis responses contain only short, redacted finding excerpts rather than complete function source.
