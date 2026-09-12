# PassForge

A lightweight, secure web application for evaluating password strength, calculating entropy, checking against known data breaches via the Have I Been Pwned API, and generating secure passphrases. Built with Flask, Python, and Tailwind CSS, featuring local k-Anonymity privacy protection.

## Features

* **Password Strength Evaluation:** Powered by zxcvbn for robust, pattern-based strength checks with detailed cracking scenario breakdowns.
* **Breach Detection:** Checks passwords securely using the Have I Been Pwned (HIBP) API via k-Anonymity (only the first 5 characters of the SHA-1 hash are sent).
* **Entropy Calculation:** Real-time mathematical entropy calculation based on character set size and length.
* **Secure Passphrase Generator:** Generates memorable, high-entropy passphrases using the EFF Large and Short Wordlists with custom separators and batch options.
* **Progressive Web App (PWA) Support:** Installable directly to mobile or desktop home screens with offline static asset caching via service worker.
* **Dark Mode & System Theme Sync:** Automatically detects system color preferences with manual toggle override and `localStorage` persistence.
* **Privacy-First:** Passwords are analyzed by your PassForge instance. For HIBP breach checks, PassForge hashes the password locally and sends only the first 5 characters of the SHA-1 hash to Have I Been Pwned; the plaintext password is never sent to HIBP.

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

### Redis Connection Resolution Logic

The application establishes its cache and rate-limiting store using a tiered fallback strategy:

1. **Explicit URL (`REDIS_URL`)**: Checked first. If present and non-empty, the app connects directly via this URI.
2. **Host & Port Fallback (`REDIS_HOST` / `REDIS_PORT`)**: If `REDIS_URL` is an empty string (`""`) or unset, the app builds a connection string formatted as `redis://:[PASSWORD]@[HOST]:[PORT]/[DB]`.
3. **In-Memory Mode (`memory://`)**: If no Redis URL or host is configured, PassForge uses in-memory rate-limit storage. If Redis is explicitly configured but unavailable, PassForge does not automatically fall back to in-memory storage.

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the LICENSE file for details.
