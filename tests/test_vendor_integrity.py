import hashlib
from pathlib import Path

EXPECTED_HASHES = {
    "static/vendor/zxcvbn-4.4.2.js":
        "f42c651f40506acb6b662490f338dd47a5951d3312039c4ab8fe5090484f351a",
    "static/vendor/zxcvbn-LICENSE.txt":
        "8fd6c9ffe44291acd207a4d3cf7d6db5ac05f585ee1cf45db9fc6b153b08990f",
    "static/vendor/js-sha1-0.7.0.min.js":
        "7e9641a4754bde92fcf899a8b011bcea97712d6958dccabf79b95c79506e19c4",
    "static/vendor/js-sha1-LICENSE.txt":
        "2472a2fdd1f3e5c01096b9cc1ae326c2436645b5d2841005d3a07285cc9c4e80",
}


def test_vendored_browser_dependencies_match_verified_files():
    for filename, expected_hash in EXPECTED_HASHES.items():
        contents = Path(filename).read_bytes()
        assert hashlib.sha256(contents).hexdigest() == expected_hash
