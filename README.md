A mini process reader using Cloudflare's Clef to quickly triage possible malware. Note that this is a PoC and obviously should not be used in a production environment.

Usage:
1. Create `.env` with `ACCOUNT_ID` and `API_TOKEN` for your Cloudflare account
2. In an elevated command prompt, run `go build .`, then the created executable
