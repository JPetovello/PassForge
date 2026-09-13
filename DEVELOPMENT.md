# PassForge Development Notes

This document describes the architecture, privacy model, security assumptions,
maintenance requirements, and testing expectations for PassForge.

It is intended for contributors, future maintainers, and anyone modifying or
forking the project.

PassForge deliberately keeps sensitive password and passphrase operations in
the user's browser. Changes that appear convenient from a server-architecture
perspective can weaken that privacy model, so contributors should understand
the boundaries described here before modifying application behavior.

## Core Privacy Invariant

The most important design rule in PassForge is:

> No plaintext password, full password hash, generated password, or generated
> passphrase may be transmitted to PassForge, HIBP, analytics, logging,
> caching, or another service.

This is an architectural requirement, not merely a UI promise.

Any proposed change that violates this invariant should be treated as a design
regression.

## Architecture Overview

PassForge is split deliberately between browser-side security logic and a small
Flask backend.

### Browser responsibilities

The browser performs the sensitive work:

- Password analysis using the vendored `zxcvbn` library.
- SHA-1 hashing using the vendored `js-sha1` library.
- Splitting the SHA-1 result into the five-character HIBP prefix and the
  remaining suffix.
- Comparing the returned HIBP suffix data locally.
- Passphrase generation.
- Cryptographically secure random selection.
- Random numeric separator generation.
- Rendering generated results.
- Clipboard interaction.

Plaintext passwords and generated passphrases are therefore intended to remain
inside the browser.

### Flask backend responsibilities

The Flask application provides infrastructure rather than password-processing
logic:

- Serves the main application page.
- Serves static assets.
- Serves verified wordlists.
- Proxies HIBP range queries using only a five-character SHA-1 prefix.
- Applies request rate limiting.
- Applies security headers.
- Exposes `/healthz`.
- Serves the service worker and PWA-related resources.

The backend must not become a second implementation of password analysis or
generation.

## Password Analysis Flow

Password analysis is intentionally browser-side.

The expected sequence is:

1. The user enters a password.
2. No request is made merely because the password changed.
3. Browser-side `zxcvbn` evaluates the password.
4. Browser-side SHA-1 produces the password hash.
5. The browser separates the first five hexadecimal characters from the
   remaining SHA-1 suffix.
6. Only the five-character prefix is sent in a JSON body to `POST /api/hibp`,
   keeping it out of the application request path and normal access logs.
7. PassForge requests the corresponding HIBP range response.
8. The browser compares the full suffix locally.
9. The plaintext password and full SHA-1 hash never leave the browser.

Do not move SHA-1 hashing, zxcvbn evaluation, or suffix matching into Flask.

Do not send the HIBP suffix to the server.

## HIBP Privacy Model

PassForge uses the Have I Been Pwned password range API model.

The backend receives only the five-character SHA-1 prefix required for the
range lookup.

The outbound HIBP request uses the `Add-Padding: true` header.

The returned range is processed by the browser, which performs the final suffix
match locally.

Although the plaintext password is not transmitted, the five-character prefix
is visible to the PassForge server in the HIBP request body. It is deliberately
kept out of the request URL so normal access logs do not record it. Application
and reverse-proxy configurations must not log API request bodies.

HTTPS is also important. The application's privacy guarantees depend on the
browser receiving the intended JavaScript without modification.

## Removed Server-Side APIs

Historical versions of PasswordCheckerWeb/PassForge included server-side
password processing.

Those endpoints are intentionally gone.

In particular:

- `/api/evaluate`
- `/api/generate`

must remain unavailable.

Regression tests exist specifically to ensure these routes do not silently
return.

Do not restore them as compatibility aliases.

Do not create replacement routes that accept plaintext passwords or generated
passphrases.

## Browser Security Dependencies

The security-sensitive browser libraries are vendored locally rather than
loaded from a CDN.

Current architecture depends on:

- `zxcvbn`
- `js-sha1`

Their corresponding license files are also kept with the vendored assets.

Using local copies reduces dependence on third-party runtime JavaScript and
helps keep the deployed security boundary reviewable.

When updating a vendored dependency:

1. Verify the upstream source and version.
2. Update the vendored file.
3. Preserve or update its license information.
4. Review any associated integrity or hash metadata.
5. Run the complete browser test suite.
6. Reconfirm that no sensitive operation was moved onto the server.

Do not casually replace these files with CDN references.

## Passphrase Generation

Passphrase generation is performed in the browser.

The browser loads a verified wordlist from PassForge and caches the parsed list
within the page for reuse.

Generated passphrases are not sent back to Flask.

### Randomness

Security-sensitive random choices use `crypto.getRandomValues()`.

Selection logic uses rejection sampling rather than simple modulo reduction in
order to avoid modulo bias.

Do not replace the current random-number generation with `Math.random()`.

Do not replace rejection sampling with naive `% wordlist.length` selection
without proving that the replacement preserves unbiased selection.

Random numeric separators also use the browser CSPRNG.

## Wordlists

PassForge treats its wordlists as verified application data.

At startup the backend verifies expected properties such as:

- SHA-256 checksum.
- Expected source line count.
- Expected parsed word count.

An invalid wordlist should not silently become available to clients.

When replacing or updating a wordlist, update all coordinated metadata rather
than changing only the text file.

Review:

- Source provenance.
- SHA-256 value.
- Expected line count.
- Expected parsed count.
- Licensing or attribution requirements.
- Tests that depend on the list.

The browser currently supports passphrase lengths from 3 through 10 words.

Word selection is performed with replacement.

## Redis and Rate Limiting

Redis is optional.

PassForge uses Flask-Limiter for rate limiting.

When Redis is configured, the limiter can use Redis-backed storage. Without
Redis, the application falls back to in-memory rate limiting.

That distinction matters under Gunicorn:

- Redis-backed rate limiting can be shared by workers.
- In-memory rate limiting is per process.
- Multiple Gunicorn workers therefore do not share a single global in-memory
  limit.

The HIBP route has a dedicated rate limit of 15 requests per
minute.

Application defaults also apply broader hourly and daily limits.

Health and wordlist resources are exempt where required by the application.

### Redis configuration

Redis configuration can be supplied using `REDIS_URL` or the supported
host, port, password, and database settings.

Do not log complete Redis connection URLs because they may contain credentials.

Be cautious when changing Redis URL parsing, TLS behavior, or `rediss://`
support.

## Health Endpoint

PassForge exposes `/healthz`.

The endpoint reports application health and optional Redis state.

Expected states include:

- Redis disabled.
- Redis connected.
- Redis unresponsive or error.

Redis probe failure currently produces a degraded health payload while the HTTP
response remains successful.

This distinction is intentional in the current implementation and should not be
changed casually because container health checks and external monitoring may
depend on it.

The Docker health check assumes the application is available on port `5000`.

Gunicorn can honor a configurable application port, so changing the runtime
port without coordinating the Docker health check can cause an otherwise
working container to be reported unhealthy.

## Container Runtime Filesystem and Privileges

The production image preserves the established non-root runtime identity
`99:100`. Files copied into `/app` remain root-owned and have group/other write
permissions removed, so the application process can read source, templates,
static assets, wordlists, and configuration without being able to alter them.
PassForge does not persist application data and does not require `/app/data` or
another writable application directory.

Python bytecode generation is disabled in the image. PassForge does not use
Gunicorn's local runtime-management socket, so it is disabled. Gunicorn still
uses an unlinked temporary file for worker heartbeat state, while `HOME` and
`TMPDIR` both point to `/tmp`. Therefore a hardened deployment can use a
read-only root filesystem with only an ephemeral `/tmp` tmpfs:

    --read-only
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777

PassForge binds to an unprivileged port and uses ordinary network connections;
it does not require Linux capabilities or privilege escalation. Deployments
should also apply:

    --cap-drop=ALL
    --security-opt=no-new-privileges:true

These are container-runtime controls and cannot be enforced by the Dockerfile.
For Unraid, supply equivalent extra parameters in the container template or
runtime configuration. Do not mount writable storage over `/app`. Redis is an
optional external service and does not create a local persistence requirement.

If future functionality introduces file writes, identify and mount only the
specific required path rather than making the image root or `/app` writable.
Re-run the container smoke tests under the restrictions above before release.

## Service Worker and PWA Behavior

The service worker lives at `static/sw.js`.

Current behavior is intentionally limited.

### API requests

Requests whose paths begin with `/api/` are never handled by the service-worker
cache.

Sensitive API behavior must remain outside service-worker caching.

### Navigation

Page navigation uses the network first.

If network navigation fails, the service worker may fall back to its cached
root page.

This allows limited offline behavior without making the service worker the
authoritative source for normal application updates.

### Static resources

Other static resources may be served from cache when already available.

When changing service-worker caching behavior, consider:

- Whether sensitive data could enter a cache.
- Whether stale application JavaScript could continue running.
- Whether cache names need to change.
- Whether all precached paths actually exist.
- Whether `cache.addAll()` can cause installation failure.
- Whether an update preserves the privacy architecture.

Do not add password data, generated passphrases, HIBP responses, or API
responses to persistent service-worker caches.

The service-worker cache identifier is independent of the PassForge release
version. A cache name such as `passforge-v3` is an internal cache generation,
not "PassForge version 3."

## Browser Concurrency and HIBP Responses

Password checks are asynchronous.

The browser contains protections so that an older HIBP response cannot
overwrite a newer password analysis.

Editing a password also invalidates an outstanding response.

Preserve these stale-response protections when modifying the password-analysis
workflow.

A request completing successfully is not sufficient reason to apply its result
if the user has already changed the password.

## Clipboard Behavior

Generated secrets can be copied to the clipboard.

Clipboard clearing is best-effort only.

Browsers and operating systems vary in how clipboard access behaves, so the
application must not claim that copied secrets can always be forcibly erased
after a fixed period.

Do not treat the clipboard as secure persistent storage.

## Security Headers

The Flask application applies security headers including protections such as:

- Frame embedding restrictions.
- MIME sniffing protection.
- Referrer policy.
- Content Security Policy.

Changes to templates, JavaScript, fonts, images, or other resources may require
corresponding CSP review.

Each response receives a cryptographically random CSP nonce. Every inline
`script` and `style` element in the main template must carry that nonce. Inline
scripts are not permitted through `unsafe-inline`.

The current UI still uses inline `style` attributes and JavaScript
`element.style` assignments for presentation state. The policy therefore keeps
`style-src 'unsafe-inline'` as a compatibility fallback and explicitly permits
style attributes. Browsers that support CSP Level 3 restrict `style` elements
to same-origin styles or the response nonce through `style-src-elem`. Removing
the remaining style allowance requires replacing every inline style attribute
and dynamic style assignment with stylesheet classes and testing the complete
UI across the supported browsers.

Browser connections are restricted to same-origin resources. HIBP communication
from the browser still goes through same-origin `POST /api/hibp`; only the
backend contacts the external HIBP service.

Avoid weakening CSP simply to make a new dependency easier to load.

In particular, think carefully before:

- Allowing arbitrary external scripts.
- Adding broad wildcard sources.
- Adding new inline script behavior.
- Moving security dependencies to third-party CDNs.

## Input Boundaries

The application places limits on accepted input sizes.

Password input is currently bounded to prevent unnecessarily large inputs from
being processed.

If limits change, review both:

- Browser behavior.
- Server/request-handling behavior.

Do not assume that a browser-side input restriction alone is a security
boundary.

## Reverse Proxies

Rate limiting derives client identity from the direct request address by
default. In this mode PassForge ignores `X-Forwarded-For`, `Forwarded`, and
`X-Real-IP`, so a direct client cannot rotate those headers to evade its rate
limit.

Proxy awareness is opt-in through `TRUSTED_PROXY_HOPS`, which accepts an integer
from 0 through 10 and defaults to 0. Set it to the exact number of trusted
reverse proxies between the client and PassForge. The limiter uses the IP at
that right-hand boundary in `X-Forwarded-For`; entries farther left remain
untrusted. Every value in the trusted segment must be a valid IPv4 or IPv6
address. A missing, short, or malformed header safely falls back to the direct
peer address.

Only enable this setting when network controls prevent direct access to
PassForge and every configured proxy appends its direct peer address to
`X-Forwarded-For`. Otherwise a client that bypasses the trusted proxy chain can
spoof its limiter identity. `Forwarded` and `X-Real-IP` are not used.

Malformed or out-of-range `TRUSTED_PROXY_HOPS` values stop application startup
instead of silently changing the trust boundary.

## Testing

PassForge contains both Python tests and browser-focused Node tests.

Run both suites before committing behavior changes.

### Python

From the repository root:

    .venv/bin/python -m pytest -q

### Browser/Node

    npm test

The browser tests cover privacy-critical behavior including:

- Typing does not send password data.
- Analysis sends only the five-character HIBP prefix.
- Full HIBP suffix matching remains local.
- Stale HIBP responses cannot overwrite newer state.
- Editing invalidates outstanding HIBP responses.
- HIBP failures do not destroy local analysis.
- Generated passphrases do not appear in requests.
- Loaded wordlists are reused.
- Numeric separators use a browser CSPRNG.
- Random selection avoids modulo bias.
- Batch output avoids unsafe HTML-string insertion.

Treat failures in these tests as possible privacy or security regressions, not
merely UI failures.

### Additional validation

A useful repository check is:

    git diff --check

Security and release automation also includes tools such as:

- Bandit.
- pip-audit.
- npm audit.
- Trivy.

A dependency or image finding should be reviewed in context rather than hidden
or automatically ignored.

## Inline JavaScript Tests

Some browser tests extract JavaScript from the HTML template using known marker
strings.

That means moving or substantially restructuring inline JavaScript can require
coordinated test changes even when runtime behavior is unchanged.

Do not weaken a privacy regression test simply because a refactor makes its
current extraction method inconvenient.

Prefer updating the test so that the invariant remains covered.

## Python Dependencies

`requirements.in` is the human-maintained list of direct application
dependencies. `requirements.lock` is generated from it and records the exact
transitive dependency set with acceptable SHA-256 hashes.

Application and container installs must use the lock with hash enforcement:

    python -m pip install --require-hashes --only-binary=:all: -r requirements.lock

To intentionally update or regenerate the lock:

1. Update `requirements.in` deliberately.
2. Create and activate a Python 3.13 environment. Lock generation must use
   Python 3.13 so dependency markers match the container and CI runtime.
3. Install the pinned lock generator outside the runtime image:

       python -m pip install pip-tools==7.6.1

4. Generate the lock:

       python -m piptools compile --generate-hashes --resolver=backtracking --strip-extras \
         --output-file=requirements.lock requirements.in

5. Review the complete lock diff and verify that every version change was
   intended.
6. Run the Python, browser, dependency-audit, and container-build checks.

Do not hand-edit generated package entries or hashes in `requirements.lock`.
The Dockerfile deliberately requires binary wheels so an unexpected source
build cannot silently reintroduce mutable compiler and Alpine build-package
inputs. The publishing target is Linux/amd64 Alpine; verify compatible
musllinux wheels before accepting a dependency update.

## Release and CI Considerations

PassForge's CI workflow performs tests and security checks before publication.

Contributors should be aware that changes reaching `main` can have release or
image-publication consequences depending on the workflow trigger.

Therefore:

- Do not use `main` as a disposable experimentation branch.
- Review the complete diff before pushing.
- Run Python and Node tests first.
- Review security checks.
- Confirm that documentation-only changes do not unintentionally include
  generated or unrelated files.
- Treat release tags deliberately.

The `v*` tag namespace is release-sensitive.

Do not create release tags merely for testing.

## Production Safety

Development and production should remain separate.

A development task should not require modifying, restarting, rebuilding, or
replacing a running PassForge container unless deployment is explicitly part of
the task.

Prefer this workflow:

1. Modify the development repository.
2. Review the diff.
3. Run tests.
4. Commit.
5. Run CI and security validation.
6. Deliberately release or deploy.

Do not debug application source by editing files inside a running production
container.

## Important Maintenance Traps

Before accepting a change, specifically ask whether it does any of the
following:

- Sends plaintext passwords to Flask.
- Sends generated secrets to Flask.
- Sends the full SHA-1 hash to Flask or HIBP.
- Sends the HIBP suffix to Flask.
- Restores `/api/evaluate`.
- Restores `/api/generate`.
- Moves zxcvbn processing server-side.
- Moves SHA-1 processing server-side.
- Moves HIBP suffix matching server-side.
- Uses `Math.random()` for secret generation.
- Introduces modulo-biased random selection.
- Logs credentials or complete Redis URLs.
- Adds a CDN-hosted security dependency.
- Caches API responses in the service worker.
- Caches passwords or generated passphrases.
- Changes a wordlist without updating verification metadata.
- Changes the runtime port without updating container health behavior.
- Assumes in-memory rate limiting is shared across workers.
- Trusts forwarded client IP headers without a trusted-proxy design.
- Weakens security or privacy regression tests to make a refactor pass.

If so, the change deserves explicit security review.

## Areas Requiring Deliberate Design Before Changing

The following areas are not necessarily bugs, but they should not be changed
incidentally:

- Service-worker and offline behavior.
- Cache-generation strategy.
- `/healthz` degraded-state HTTP semantics.
- Docker health-check port assumptions.
- Redis TLS and connection behavior.
- Reverse-proxy client-IP handling.
- Python dependency reproducibility.
- Browser support policy.
- Content Security Policy.
- Main-branch publication behavior.
- Real-browser end-to-end privacy testing.

Changes in these areas should be treated as design decisions rather than
drive-by cleanup.

## Contributor Rule of Thumb

When deciding where new functionality belongs, ask:

> Does this operation require knowledge of a plaintext password, a generated
> secret, or the private portion of a password hash?

If yes, it almost certainly belongs in the browser.

The backend should remain a small supporting service that can operate without
learning the user's secrets.

Privacy by architecture is the defining property of PassForge. Preserve it.
