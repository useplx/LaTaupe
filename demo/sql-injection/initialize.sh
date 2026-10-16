#!/bin/sh
set -eu

base="${DVWA_URL:-http://127.0.0.1:3000}"
cookies="$(mktemp)"
trap 'rm -f "$cookies"' EXIT

attempt=0
while ! page="$(curl --fail --silent --show-error --cookie-jar "$cookies" "$base/setup.php")"; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 30 ]; then
        echo "DVWA did not become ready at $base" >&2
        exit 1
    fi
    sleep 1
done

token="$(printf '%s' "$page" | sed -n "s/.*name='user_token' value='\([^']*\)'.*/\1/p")"
if [ -z "$token" ]; then
    echo "DVWA setup token was not found" >&2
    exit 1
fi

curl --fail --silent --show-error --location \
    --cookie "$cookies" \
    --data-urlencode 'create_db=Create / Reset Database' \
    --data-urlencode "user_token=$token" \
    "$base/setup.php" >/dev/null

curl --fail --silent --show-error --cookie 'security=low' \
    "$base/vulnerabilities/sqli/?id=1&Submit=Submit" |
    grep --quiet 'First name: admin'

echo "DVWA database initialized at $base"
