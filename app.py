import os
import re
import secrets
import hashlib
import math
import requests
import redis
from flask import Flask, render_template, request, jsonify, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import zxcvbn

app = Flask(__name__)

# 1. Restrict maximum request payload size to 1 MB (prevents DoS/memory overload)
app.config['MAX_CONTENT_LENGTH'] = int(os.environ.get('MAX_PAYLOAD_BYTES', 1 * 1024 * 1024))

# 2. Set up Rate Limiting & Redis Connection (Handles empty env vars from Docker/Unraid)
raw_redis_url = os.environ.get("REDIS_URL", "").strip() or None

if not raw_redis_url:
    redis_host = os.environ.get("REDIS_HOST", "").strip()
    redis_port = os.environ.get("REDIS_PORT", "6379").strip()
    redis_password = os.environ.get("REDIS_PASSWORD", "").strip()

    if redis_host:
        auth = f":{redis_password}@" if redis_password else ""
        REDIS_URL = f"redis://{auth}{redis_host}:{redis_port}/0"
    else:
        REDIS_URL = "memory://"
else:
    REDIS_URL = raw_redis_url

RATELIMIT_DEFAULT = os.environ.get("RATELIMIT_DEFAULT", "200 per day;50 per hour")

limiter = Limiter(
    get_remote_address,
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
        print(f"[Redis] Successfully connected to Redis instance ({REDIS_URL}).")
    except Exception as e:
        print(f"[Redis Warning] Could not connect to Redis ({REDIS_URL}): {e}")

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

@app.after_request
def apply_security_headers(response):
    """Attach standard production security headers to all responses."""
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';"
    return response

def check_hibp_by_prefix(prefix, suffix):
    """Check HIBP via k-Anonymity using pre-computed prefix and suffix with strict format validation."""
    if not re.fullmatch(r'^[0-9A-F]{5}$', prefix) or not re.fullmatch(r'^[0-9A-F]{35}$', suffix):
        return 0

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {'User-Agent': 'PassForge-Homelab-App'}
    
    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code != 200:
            print(f"[HIBP Error] API returned HTTP {res.status_code}")
            return None

        for line in res.text.splitlines():
            if ':' in line:
                h, count = line.split(':', 1)
                if h.strip() == suffix:
                    return int(count)
    except Exception as e:
        print(f"[HIBP Error] {e}")
        return None

    return 0

def check_hibp(password):
    """Check password leak count via Have I Been Pwned API using k-Anonymity."""
    sha1_password = hashlib.sha1(password.encode('utf-8'), usedforsecurity=False).hexdigest().upper()
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]
    return check_hibp_by_prefix(prefix, suffix)

def calculate_entropy(password):
    charset_size = 0
    if any(c.islower() for c in password): charset_size += 26
    if any(c.isupper() for c in password): charset_size += 26
    if any(c.isdigit() for c in password): charset_size += 10
    if any(not c.isalnum() for c in password): charset_size += 32
    
    if charset_size == 0 or len(password) == 0:
        return 0
    
    return round(len(password) * math.log2(charset_size))

@app.route('/', methods=['GET'])
def index():
    return render_template(
        'index.html',
        large_wordlist_size=len(EFF_LARGE_WORDS),
        short_wordlist_size=len(EFF_SHORT_WORDS),
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

@app.route('/api/evaluate', methods=['POST'])
@limiter.limit("15 per minute")
def evaluate_password():
    data = request.get_json() or {}
    
    sha1_prefix = sanitize_input(data.get('sha1_prefix', '')).upper()
    sha1_suffix = sanitize_input(data.get('sha1_suffix', '')).upper()

    raw_password = data.get('password', '')
    password = raw_password if isinstance(raw_password, str) else ''

    if not password and not (sha1_prefix and sha1_suffix):
        return jsonify({'error': 'No evaluation data provided'}), 400

    if not password:
        if (
            not re.fullmatch(r'^[0-9A-F]{5}$', sha1_prefix)
            or not re.fullmatch(r'^[0-9A-F]{35}$', sha1_suffix)
        ):
            return jsonify({'error': 'Invalid SHA-1 prefix or suffix format'}), 400

    if password:
        if len(password) > 256:
            return jsonify({'error': 'Password exceeds maximum allowed length of 256 characters'}), 400
        results = zxcvbn.zxcvbn(password)
        pwned_count = check_hibp(password)
        entropy_val = calculate_entropy(password)
    else:
        pwned_count = check_hibp_by_prefix(sha1_prefix, sha1_suffix)
        results = {'score': 0, 'feedback': {}, 'crack_times_display': {}}
        entropy_val = 0

    raw_crack_times = results.get('crack_times_display', {})
    capitalized_crack_times = {k: v.title() for k, v in raw_crack_times.items()}

    return jsonify({
        'score': results.get('score', 0),
        'entropy': entropy_val,
        'feedback': results.get('feedback', {}),
        'crack_times_display': capitalized_crack_times,
        'hibp': {
            'available': pwned_count is not None,
            'found': pwned_count is not None and pwned_count > 0,
            'count': pwned_count
        }
    })

@app.route('/api/generate', methods=['GET'])
@limiter.limit("30 per minute")
def generate_passphrase():
    try:
        num_words = int(request.args.get('words', 4))
    except (ValueError, TypeError):
        num_words = 4

    num_words = max(3, min(num_words, 10))

    try:
        batch_count = int(request.args.get('count', 1))
    except (ValueError, TypeError):
        batch_count = 1

    batch_count = max(1, min(batch_count, 10))

    list_type = request.args.get('wordlist', 'large').lower()

    if list_type not in {'large', 'short'}:
        return jsonify({'error': 'Invalid wordlist type'}), 400

    if list_type == 'large' and not EFF_LARGE_WORDS:
        return jsonify({'error': 'EFF Large wordlist is not installed'}), 503

    if list_type == 'short' and not EFF_SHORT_WORDS:
        return jsonify({'error': 'EFF Short wordlist is not installed'}), 503

    word_pool = EFF_SHORT_WORDS if list_type == 'short' else EFF_LARGE_WORDS

    raw_sep = request.args.get('separator', '-')
    allowed_separators = {'-': '-', '_': '_', '.': '.', 'space': ' ', 'number': 'num'}

    if raw_sep not in allowed_separators:
        return jsonify({'error': 'Invalid separator'}), 400

    separator_mode = allowed_separators[raw_sep]

    bits_per_word = math.log2(len(word_pool))
    theoretical_entropy = num_words * bits_per_word

    if separator_mode == 'num':
        theoretical_entropy += (num_words - 1) * math.log2(10)

    theoretical_entropy = round(theoretical_entropy, 1)

    passphrases = []
    for _ in range(batch_count):
        selected_words = [secrets.choice(word_pool) for _ in range(num_words)]
        if separator_mode == 'num':
            passphrase = "".join(f"{word}{secrets.choice('0123456789')}" for word in selected_words[:-1]) + selected_words[-1]
        else:
            passphrase = separator_mode.join(selected_words)
        passphrases.append(passphrase)

    return jsonify({
        'passphrase': passphrases[0],
        'passphrases': passphrases,
        'count': batch_count,
        'words': num_words,
        'entropy_bits': theoretical_entropy,
        'wordlist_type': list_type
    })

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
