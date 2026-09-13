# PassForge

A lightweight, self-hosted password analysis and secure passphrase generation application. Password analysis, SHA-1 hashing, HIBP suffix matching, and passphrase generation occur locally in the browser.

## Features

* **Local Password Strength Evaluation:** Runs the vendored zxcvbn 4.4.2 library inside the browser.
* **Privacy-Preserving Breach Detection:** Hashes the password in the browser and sends only the first 5 SHA-1 characters to the PassForge HIBP proxy. The complete hash and plaintext password never reach the PassForge server or HIBP.
* **Estimated Guess Entropy:** Derives an estimated bit value from zxcvbn's password-guess estimate rather than assuming randomly selected characters.
* **Local Secure Passphrase Generator:** Uses the browser's cryptographically secure random-number generator with verified EFF Large and Short Wordlists.
* **Batch Generation:** Generates up to 10 passphrases without transmitting the generated values to the server.
* **Progressive Web App Support:** Installable on supported mobile and desktop browsers.
* **Dark Mode & System Theme Sync:** Supports automatic and manually selected themes.

## Privacy Architecture

PassForge does not submit plaintext passwords, complete password hashes, or generated passphrases to its Flask server.

For a breach check:

1. The browser calculates the password's SHA-1 hash locally.
2. The browser sends only the first 5 hash characters to PassForge.
3. PassForge requests the corresponding padded HIBP k-Anonymity range.
4. The browser compares the remaining 35 hash characters locally.

Passphrase generation also occurs entirely in the browser. The server supplies only wordlists that passed bundled SHA-256 and entry-count verification.

Use only a PassForge instance you trust. HTTPS is recommended whenever traffic crosses an untrusted network because the browser application itself must be delivered without tampering.

## Installation

### Unraid (Community Applications)

PassForge is available through Unraid Community Applications. Search for **PassForge** in the Unraid Apps tab to install it.

## Environment Variables

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `5000` | Port the internal Gunicorn / Flask web server listens on. |
| `REDIS_URL` | *(blank)* | Full Redis connection URI (e.g., `redis://:secret@192.0.2.10:6379/0`). Overrides individual host/port variables when populated. |
| `REDIS_HOST` | *(blank)* | Redis host or IP address. Used when `REDIS_URL` is empty or omitted. |
| `REDIS_PORT` | `6379` | Redis port number. Used when `REDIS_URL` is empty or omitted. |
| `REDIS_PASSWORD` | *(blank)* | Optional Redis authentication password (for host/port configuration). |
| `REDIS_DB` | `0` | Redis database index. |
| `TRUSTED_PROXY_HOPS` | `0` | Number of trusted reverse-proxy hops in `X-Forwarded-For` (0–10). Leave at `0` for direct deployments. |

### Redis Connection Resolution Logic

The application establishes its cache and rate-limiting store using a tiered fallback strategy:

1. **Explicit URL (`REDIS_URL`)**: Checked first. If present and non-empty, the app connects directly via this URI.
2. **Host & Port Fallback (`REDIS_HOST` / `REDIS_PORT`)**: If `REDIS_URL` is an empty string (`""`) or unset, the app builds a connection string formatted as `redis://:[PASSWORD]@[HOST]:[PORT]/[DB]`.
3. **In-Memory Mode (`memory://`)**: If no Redis URL or host is configured, PassForge uses in-memory rate-limit storage. If Redis is explicitly configured but unavailable, PassForge does not automatically fall back to in-memory storage.

In-memory rate-limit counters are local to each Gunicorn worker. Configure Redis
when limits must be shared across workers or application instances.

### Reverse Proxy Client Addresses

PassForge uses the direct network peer for rate limiting by default and ignores
`X-Forwarded-For`, `Forwarded`, and `X-Real-IP`. When PassForge is reachable
only through a known reverse-proxy chain, set `TRUSTED_PROXY_HOPS` to the exact
number of trusted proxies (maximum 10). PassForge then selects the client IP at
that right-hand boundary from `X-Forwarded-For`; entries farther to the left do
not affect the limiter key.

Do not enable proxy trust if clients can connect directly to PassForge. The
reverse proxy must append each peer address to `X-Forwarded-For`, and network
controls must prevent clients from bypassing the configured trusted proxies.
Invalid `TRUSTED_PROXY_HOPS` values prevent the application from starting.

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the LICENSE file for details.
