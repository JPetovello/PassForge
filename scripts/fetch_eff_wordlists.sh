#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
LARGE='https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt'
SHORT='https://www.eff.org/files/2016/09/08/eff_short_wordlist_1.txt'
if command -v curl >/dev/null 2>&1; then
  curl -fL "$LARGE" -o eff_large_wordlist.txt
  curl -fL "$SHORT" -o eff_short_wordlist.txt
elif command -v wget >/dev/null 2>&1; then
  wget -O eff_large_wordlist.txt "$LARGE"
  wget -O eff_short_wordlist.txt "$SHORT"
else
  echo 'curl or wget is required' >&2
  exit 1
fi
[ "$(wc -l < eff_large_wordlist.txt)" -eq 7776 ]
[ "$(wc -l < eff_short_wordlist.txt)" -eq 1296 ]
echo 'EFF wordlists installed and line counts verified.'
