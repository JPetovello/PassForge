import os
import re
import hashlib
import ipaddress
import secrets
import requests
import redis
from flask import Flask, g, render_template, request, jsonify, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# 1. Restrict maximum request payload size to 1 MB (prevents DoS/memory overload)
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_PAYLOAD_BYTES', 1 * 1024 * 1024))

# 2. Set up Rate Limiting & Redis Connection (Handles empty env vars from Docker/Unraid)
def resolve_redis_url():
    """Resolve Redis configuration from environment variables."""
    raw_redis_url = os.environ.get("REDIS_URL", "").strip() or None

    if raw_redis_url:
        return raw_redis_url

    redis_host = os.environ.get("REDIS_HOST", "").strip()
    redis_port = os.environ.get("REDIS_PORT", "6379").strip()
    redis_password = os.environ.get("REDIS_PASSWORD", "").strip()
    redis_db = os.environ.get("REDIS_DB", "0").strip() or "0"

    if redis_host:
        auth = f":{redis_password}@" if redis_password else ""
        return f"redis://{auth}{redis_host}:{redis_port}/{redis_db}"

    return "memory://"


REDIS_URL = resolve_redis_url()

RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "200 per day;50 per hour")
MAX_TRUSTED_PROXY_HOPS = 10


def resolve_trusted_proxy_hops():
    """Return the explicitly configured number of trusted reverse proxies."""
    raw_value = os.environ.get("TRUSTED_PROXY_HOPS", "0").strip()

    try:
        trusted_hops = int(raw_value)
    except ValueError as exc:
        raise ValueError(
            "TRUSTED_PROXY_HOPS must be an integer from 0 through "
            f"{MAX_TRUSTED_PROXY_HOPS}."
        ) from exc

    if not 0 <= trusted_hops <= MAX_TRUSTED_PROXY_HOPS:
        raise ValueError(
            "TRUSTED_PROXY_HOPS must be an integer from 0 through "
            f"{MAX_TRUSTED_PROXY_HOPS}."
        )

    return trusted_hops


TRUSTED_PROXY_HOPS = resolve_trusted_proxy_hops()


def get_rate_limit_client_address():
    """Resolve a limiter key without implicitly trusting forwarding headers."""
    direct_address = get_remote_address()

    if TRUSTED_PROXY_HOPS == 0:
        return direct_address

    forwarded_for = request.headers.get("X-Forwarded-For", "")
    forwarded_chain = [item.strip() for item in forwarded_for.split(",")]

    if len(forwarded_chain) < TRUSTED_PROXY_HOPS:
        return direct_address

    trusted_segment = forwarded_chain[-TRUSTED_PROXY_HOPS:]
    try:
        normalized_segment = [
            str(ipaddress.ip_address(address))
            for address in trusted_segment
        ]
    except ValueError:
        return direct_address

    return normalized_segment[0]

limiter = Limiter(
    get_rate_limit_client_address,
    app=app,
    default_limits=[RATELIMIT_DEFAULT],
    storage_uri=REDIS_URL
)

# Custom 429 Rate Limit Error Handler
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": "Rate limit exceeded",
        "message": "Too many requests. Please slow down and try again later."
    }), 429

# Optional direct Redis client for general app caching/state
redis_client = None
if REDIS_URL.startswith("redis://"):
    try:
        redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        redis_client.ping()
        print("[Redis] Successfully connected to configured Redis instance.")
    except Exception as e:
        print(f"[Redis Warning] Could not connect to configured Redis instance ({type(e).__name__}).")

# Load and verify bundled EFF wordlists at app startup
EFF_LARGE_SHA256 = "addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e"
EFF_SHORT_SHA256 = "8f5ca830b8bffb6fe39c9736c024a00a6a6411adb3f83a9be8bfeeb6e067ae69"

EFF_LARGE_LINES = 7776
EFF_SHORT_LINES = 1296

EFF_LARGE_WORDS = []
EFF_SHORT_WORDS = []

def load_wordlist(filename, expected_sha256, expected_lines):
    """Load a bundled wordlist only when its contents pass integrity checks."""
    filepath = os.path.join(os.path.dirname(__file__), filename)

    if not os.path.exists(filepath):
        print(f"[Wordlist Error] {filename} is missing.")
        return []

    try:
        with open(filepath, 'rb') as f:
            raw_data = f.read()

        file_digest = hashlib.sha256(raw_data).hexdigest()

        if file_digest != expected_sha256:
            print(
                f"[Wordlist Error] SHA-256 verification failed for {filename}. "
                f"Expected {expected_sha256}, got {file_digest}."
            )
            return []

        text = raw_data.decode('utf-8')
        lines = text.splitlines()

        if len(lines) != expected_lines:
            print(
                f"[Wordlist Error] Line-count verification failed for {filename}. "
                f"Expected {expected_lines}, got {len(lines)}."
            )
            return []

        words = []
        for line in lines:
            parts = line.strip().split(maxsplit=1)
            if len(parts) >= 2:
                words.append(parts[1])
            elif parts:
                words.append(parts[0])

        if len(words) != expected_lines:
            print(
                f"[Wordlist Error] Parsed entry-count verification failed for {filename}. "
                f"Expected {expected_lines}, got {len(words)}."
            )
            return []

        print(
            f"[Wordlist] Verified {filename} "
            f"({expected_lines} entries, SHA-256: {file_digest})"
        )
        return words

    except Exception as e:
        print(f"[Wordlist Error] Failed to load {filename}: {e}")
        return []

EFF_LARGE_WORDS = load_wordlist(
    'eff_large_wordlist.txt',
    EFF_LARGE_SHA256,
    EFF_LARGE_LINES,
)

EFF_SHORT_WORDS = load_wordlist(
    'eff_short_wordlist.txt',
    EFF_SHORT_SHA256,
    EFF_SHORT_LINES,
)

if not EFF_LARGE_WORDS:
    print("[Wordlist Warning] EFF Large list not found. Large-list generation is unavailable until eff_large_wordlist.txt is installed.")

if not EFF_SHORT_WORDS:
    print("[Wordlist Warning] EFF Short list not found. Short-list generation is unavailable until eff_short_wordlist.txt is installed.")

# -------------------------------------------------------------------
# Input Security & Sanitization Helper
# -------------------------------------------------------------------
def sanitize_input(user_input: str) -> str:
    """Sanitizes incoming input payloads to prevent control character injection."""
    if not isinstance(user_input, str) or not user_input:
        return ""
    max_length = 512
    user_input = user_input[:max_length]
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', user_input)
    return sanitized.strip()


def get_csp_nonce():
    """Return this response's CSP nonce, creating it if needed."""
    nonce = getattr(g, "csp_nonce", None)
    if nonce is None:
        nonce = secrets.token_urlsafe(16)
        g.csp_nonce = nonce
    return nonce


@app.before_request
def create_csp_nonce():
    """Create a fresh nonce for this response's permitted inline assets."""
    get_csp_nonce()


@app.after_request
def apply_security_headers(response):
    """Attach standard production security headers to all responses."""
    nonce = get_csp_nonce()
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "base-uri 'none'; "
        "connect-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        "script-src-attr 'none'; "
        "style-src 'self' 'unsafe-inline'; "
        "style-src-attr 'unsafe-inline'; "
        f"style-src-elem 'self' 'nonce-{nonce}'; "
        "worker-src 'self'"
    )
    return response

def fetch_hibp_range(prefix):
    """Fetch a padded HIBP hash range using only a validated five-character prefix."""
    if not re.fullmatch(r'^[0-9A-F]{5}$', prefix):
        return None
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {'User-Agent': 'PassForge-Homelab-App', 'Add-Padding': 'true'}

    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code != 200:
            print(f"[HIBP Error] API returned HTTP {res.status_code}")
            return None
        return res.text
    except Exception as e:
        print(f"[HIBP Error] {e}")
        return None


@app.route('/', methods=['GET'])
def index():
    return render_template(
        'index.html',
        csp_nonce=g.csp_nonce,
        large_wordlist_size=len(EFF_LARGE_WORDS),
        short_wordlist_size=len(EFF_SHORT_WORDS),
    )

@app.route('/sw.js')
def service_worker():
    static_dir = os.path.join(app.root_path, 'static')
    return send_from_directory(
        static_dir,
        'sw.js',
        mimetype='application/javascript',
        max_age=0,
    )

@app.route('/favicon.ico')
def favicon():
    static_dir = os.path.join(app.root_path, 'static')
    if os.path.exists(os.path.join(static_dir, 'favicon.ico')):
        return send_from_directory(static_dir, 'favicon.ico', mimetype='image/vnd.microsoft.icon')
    return '', 204

@app.route('/robots.txt')
def robots():
    return "User-agent: *\nDisallow: /", 200, {'Content-Type': 'text/plain'}

@app.route('/wordlists/<list_type>.txt', methods=['GET'])
@limiter.exempt
def wordlist(list_type):
    """Serve only wordlists that passed startup integrity verification."""
    wordlists = {
        'large': EFF_LARGE_WORDS,
        'short': EFF_SHORT_WORDS,
    }
    if list_type not in wordlists:
        return jsonify({'error': 'Invalid wordlist type'}), 404

    words = wordlists[list_type]
    if not words:
        return jsonify({'error': f'EFF {list_type.title()} wordlist is unavailable'}), 503

    response = app.response_class(
        '\n'.join(words) + '\n',
        mimetype='text/plain',
    )
    response.headers['Cache-Control'] = 'public, max-age=86400'
    return response

@app.route('/healthz', methods=['GET'])
@limiter.exempt
def healthcheck():
    health_status = {
        "status": "healthy",
        "redis": "disabled"
    }

    if redis_client is not None:
        try:
            if redis_client.ping():
                health_status["redis"] = "connected"
            else:
                health_status["redis"] = "unresponsive"
                health_status["status"] = "degraded"
        except Exception as e:
            health_status["redis"] = f"error: internal failure"
            health_status["status"] = "degraded"

    status_code = 200 if health_status["status"] in ["healthy", "degraded"] else 500
    return jsonify(health_status), status_code

@app.route('/api/hibp', methods=['POST'])
@limiter.limit("15 per minute")
def hibp_range():
    """Proxy a padded HIBP range lookup without receiving a password or full hash."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or set(payload) != {'prefix'}:
        return jsonify({'error': 'Invalid SHA-1 prefix format'}), 400

    prefix = payload.get('prefix')
    if not isinstance(prefix, str):
        return jsonify({'error': 'Invalid SHA-1 prefix format'}), 400

    normalized_prefix = prefix.upper()
    if not re.fullmatch(r'^[0-9A-F]{5}$', normalized_prefix):
        return jsonify({'error': 'Invalid SHA-1 prefix format'}), 400

    range_text = fetch_hibp_range(normalized_prefix)
    if range_text is None:
        return jsonify({'error': 'HIBP check unavailable'}), 503

    return range_text, 200, {'Content-Type': 'text/plain; charset=utf-8'}

@app.errorhandler(400)
def bad_request_error(error):
    return jsonify({"error": "Bad Request", "message": "The request payload or parameters were malformed."}), 400

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"error": "Not Found", "message": "The requested endpoint does not exist."}), 404

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal Server Error: {error}")
    return jsonify({"error": "An internal error occurred."}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
