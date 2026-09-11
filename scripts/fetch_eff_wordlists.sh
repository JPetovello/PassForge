#!/bin/sh
set -eu

cd "$(dirname "$0")/.."

LARGE_URL='https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt'
SHORT_URL='https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt'

LARGE_SHA256='addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e'
SHORT_SHA256='8f5ca830b8bffb6fe39c9736c024a00a6a6411adb3f83a9be8bfeeb6e067ae69'

LARGE_LINES=7776
SHORT_LINES=1296

LARGE_TMP='eff_large_wordlist.txt.tmp'
SHORT_TMP='eff_short_wordlist.txt.tmp'

cleanup() {
    rm -f "$LARGE_TMP" "$SHORT_TMP"
}

trap cleanup EXIT INT TERM

download() {
    url="$1"
    destination="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fL "$url" -o "$destination"
    elif command -v wget >/dev/null 2>&1; then
        wget -O "$destination" "$url"
    else
        echo 'curl or wget is required' >&2
        exit 1
    fi
}

verify() {
    file="$1"
    expected_hash="$2"
    expected_lines="$3"

    actual_hash="$(sha256sum "$file" | awk '{print $1}')"
    actual_lines="$(wc -l < "$file")"

    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "SHA-256 verification failed for $file" >&2
        echo "Expected: $expected_hash" >&2
        echo "Actual:   $actual_hash" >&2
        exit 1
    fi

    if [ "$actual_lines" -ne "$expected_lines" ]; then
        echo "Line-count verification failed for $file" >&2
        echo "Expected: $expected_lines" >&2
        echo "Actual:   $actual_lines" >&2
        exit 1
    fi
}

download "$LARGE_URL" "$LARGE_TMP"
download "$SHORT_URL" "$SHORT_TMP"

verify "$LARGE_TMP" "$LARGE_SHA256" "$LARGE_LINES"
verify "$SHORT_TMP" "$SHORT_SHA256" "$SHORT_LINES"

mv "$LARGE_TMP" eff_large_wordlist.txt
mv "$SHORT_TMP" eff_short_wordlist.txt

trap - EXIT INT TERM

echo 'EFF wordlists installed and SHA-256/line counts verified.'
