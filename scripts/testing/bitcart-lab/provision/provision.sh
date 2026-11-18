#!/bin/sh
# Configure Bitcart for the lab: one admin, watch-only wallets, one USD store,
# and an invoice-only token for Arkfile. Safe to run again.
set -eu

# Refuse rootful containers (initial user namespace maps all 4294967295 UIDs at 0 -> 0).
if [ -r /proc/self/uid_map ] && awk '$1 == 0 && $2 == 0 && $3 == 4294967295 { exit 0 } END { exit 1 }' /proc/self/uid_map; then
    echo "[X] Refusing to start in a rootful container (host root user namespace detected)." >&2
    echo "    Run this lab only with rootless Podman via: bash scripts/testing/bitcart-lab/paylab.sh up" >&2
    exit 1
fi

apk add --no-cache curl jq >/dev/null

API="${BITCART_API:-https://bitcart.lab:19080/api}"
CACERT="${BITCART_CACERT:-/ca/ca.crt}"
ENV_FILE=/lab-config/bitcart.env
EMAIL="${BITCART_ADMIN_EMAIL:-admin@bitcart.lab}"

if [ -z "${BITCART_ADMIN_PASSWORD:-}" ] || [ -z "${BTC_XPUB:-}" ]; then
    echo "BITCART_ADMIN_PASSWORD and BTC_XPUB are required in lab.env" >&2
    exit 1
fi

case "$BTC_XPUB" in
    xprv*|yprv*|zprv*|tprv*|uprv*|vprv*)
        echo "BTC_XPUB looks like a private key. Provide an extended public key." >&2
        exit 1
        ;;
esac

speed=${BITCART_TX_SPEED:-1}
case "$speed" in
    ''|*[!0-9]*) echo "BITCART_TX_SPEED must be a positive integer" >&2; exit 1 ;;
esac
if [ "$speed" -lt 1 ]; then
    echo "BITCART_TX_SPEED must be at least 1" >&2
    exit 1
fi

cryptos=$(printf '%s' "${BITCART_CRYPTOS:-btc}" | tr '[:upper:]' '[:lower:]')
want_xmr=0
case ",$cryptos," in
    *,xmr,*) want_xmr=1 ;;
esac

curl_api() {
    curl -fsS --cacert "$CACERT" "$@"
}

wait_api() {
    i=0
    while [ "$i" -lt 90 ]; do
        if curl_api -o /dev/null "$API/cryptos" 2>/dev/null || curl_api -o /dev/null "$API/manage/policies" 2>/dev/null; then
            echo "bitcart API is up"
            return 0
        fi
        i=$((i + 1))
        sleep 2
    done
    echo "bitcart API did not become ready" >&2
    exit 1
}

token_of() {
    # Login or limited-token responses use access_token or token.
    printf '%s' "$1" | jq -r 'if type == "object" then (.access_token // .token // empty) else empty end' 2>/dev/null || true
}

json_id_of() {
    printf '%s' "$1" | jq -r 'if type == "object" then (.id // empty) else empty end' 2>/dev/null || true
}

json_rows_of() {
    rows=$(printf '%s' "$1" | jq -c 'if type=="array" then . elif (type=="object" and (.result | type=="array")) then .result else [] end' 2>/dev/null || true)
    if [ -z "$rows" ]; then
        rows="[]"
    fi
    printf '%s' "$rows"
}

settings_ok() {
    body=$1
    printf '%s' "$body" | jq -e --argjson speed "$speed" --argjson want_xmr "$want_xmr" '
        type == "object"
        and .checkout_settings.transaction_speed == $speed
        and .checkout_settings.underpaid_percentage == 0
        and .checkout_settings.email_required == false
        and .checkout_settings.allow_anonymous_invoice_creation == false
        and (.default_currency | ascii_upcase) == "USD"
        and ((.currency_data // {}) | has("btc"))
        and ($want_xmr == 0 or ((.currency_data // {}) | has("xmr")))
    ' >/dev/null 2>&1
}

wait_api

if [ -f "$ENV_FILE" ]; then
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    if [ -n "${ARKFILE_BITCART_STORE_ID:-}" ] && [ -n "${ARKFILE_BITCART_API_TOKEN:-}" ]; then
        code=$(curl -sS -o /tmp/store.json -w '%{http_code}' --cacert "$CACERT" \
            -H "Authorization: Bearer ${ARKFILE_BITCART_API_TOKEN}" \
            "$API/stores/${ARKFILE_BITCART_STORE_ID}" || true)
        count=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$CACERT" \
            -H "Authorization: Bearer ${ARKFILE_BITCART_API_TOKEN}" \
            "$API/invoices/count" || true)
        if [ "$code" = "200" ] && [ "$count" = "200" ] && settings_ok "$(cat /tmp/store.json)"; then
            chmod 0600 "$ENV_FILE"
            echo "existing invoice token and store are valid"
            exit 0
        fi
        echo "stored token or store settings need to be updated"
    fi
fi

create_user=$(curl -sS -w '\n%{http_code}' --cacert "$CACERT" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg email "$EMAIL" --arg password "$BITCART_ADMIN_PASSWORD" \
        '{email:$email,password:$password,captcha_code:""}')" \
    "$API/users" || true)
user_body=$(printf '%s' "$create_user" | sed '$d')
user_code=$(printf '%s' "$create_user" | tail -n 1)
admin_token=$(token_of "$user_body")

if [ -z "$admin_token" ]; then
    login=$(curl -sS --cacert "$CACERT" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg email "$EMAIL" --arg password "$BITCART_ADMIN_PASSWORD" \
            '{email:$email,password:$password,permissions:["full_control"]}')" \
        "$API/token" || true)
    admin_token=$(token_of "$login")
    if [ -z "$admin_token" ]; then
        echo "could not register or authenticate the Bitcart admin (user HTTP ${user_code})" >&2
        echo "$user_body" >&2
        echo "$login" >&2
        echo "Open https://bitcart.lab:19080/ if the API shape differs, then re-run provision." >&2
        exit 1
    fi
fi

auth() {
    curl -sS --cacert "$CACERT" -H "Authorization: Bearer ${admin_token}" -H 'Content-Type: application/json' "$@"
}

wallets_json=$(auth "$API/wallets" || true)
wallet_rows=$(json_rows_of "$wallets_json")

find_wallet() {
    currency=$1
    printf '%s' "$wallet_rows" | jq -r --arg c "$currency" '[.[] | select((.currency // "" | ascii_downcase)==$c)][0].id // empty' 2>/dev/null || true
}

btc_id=$(find_wallet btc)
if [ -z "$btc_id" ]; then
    created=$(auth -d "$(jq -nc --arg xpub "$BTC_XPUB" \
        '{name:"lab-btc",xpub:$xpub,currency:"btc",lightning_enabled:false}')" \
        "$API/wallets" || true)
    btc_id=$(json_id_of "$created")
    if [ -z "$btc_id" ]; then
        echo "bitcoin wallet was not created" >&2
        echo "$created" >&2
        echo "Check the extended public key, then open https://bitcart.lab:19080/ and re-run provision." >&2
        exit 1
    fi
fi

xmr_id=""
if [ "$want_xmr" -eq 1 ]; then
    if [ -z "${XMR_ADDRESS:-}" ] || [ -z "${XMR_PRIVATE_VIEW_KEY:-}" ]; then
        echo "XMR_ADDRESS and XMR_PRIVATE_VIEW_KEY are required when BITCART_CRYPTOS includes xmr" >&2
        exit 1
    fi
    xmr_id=$(find_wallet xmr)
    if [ -z "$xmr_id" ]; then
        extra=$(jq -nc --arg address "$XMR_ADDRESS" '{address:$address}')
        if [ -n "${XMR_RESTORE_HEIGHT:-}" ]; then
            extra=$(printf '%s' "$extra" | jq --argjson h "$XMR_RESTORE_HEIGHT" '. + {restore_height:$h}')
        fi
        created=$(auth -d "$(jq -nc --arg key "$XMR_PRIVATE_VIEW_KEY" --argjson extra "$extra" \
            '{name:"lab-xmr",xpub:$key,currency:"xmr",additional_xpub_data:$extra}')" \
            "$API/wallets" || true)
        xmr_id=$(json_id_of "$created")
        if [ -z "$xmr_id" ] && [ -n "${XMR_RESTORE_HEIGHT:-}" ]; then
            echo "retrying monero wallet without restore_height"
            created=$(auth -d "$(jq -nc --arg key "$XMR_PRIVATE_VIEW_KEY" --arg address "$XMR_ADDRESS" \
                '{name:"lab-xmr",xpub:$key,currency:"xmr",additional_xpub_data:{address:$address}}')" \
                "$API/wallets" || true)
            xmr_id=$(json_id_of "$created")
        fi
        if [ -z "$xmr_id" ]; then
            echo "monero wallet was not created" >&2
            echo "$created" >&2
            exit 1
        fi
    fi
fi

stores_json=$(auth "$API/stores" || true)
store_rows=$(json_rows_of "$stores_json")
store_id=$(printf '%s' "$store_rows" | jq -r '[.[] | select(.name=="lab")][0].id // empty' 2>/dev/null || true)

wallets=$(jq -nc --arg btc "$btc_id" --arg xmr "$xmr_id" '[$btc] + (if $xmr=="" then [] else [$xmr] end)')
checkout=$(jq -nc --argjson speed "$speed" '{
    expiration: 60,
    transaction_speed: $speed,
    underpaid_percentage: 0,
    email_required: false,
    allow_anonymous_invoice_creation: false
}')

if [ -z "$store_id" ]; then
    created=$(auth -d "$(jq -nc --argjson wallets "$wallets" --argjson checkout "$checkout" \
        '{name:"lab",default_currency:"USD",wallets:$wallets,checkout_settings:$checkout}')" \
        "$API/stores" || true)
    store_id=$(json_id_of "$created")
    if [ -z "$store_id" ]; then
        echo "store was not created" >&2
        echo "$created" >&2
        exit 1
    fi
else
    updated=$(auth -X PATCH -d "$(jq -nc --argjson wallets "$wallets" --argjson checkout "$checkout" \
        '{name:"lab",default_currency:"USD",wallets:$wallets,checkout_settings:$checkout}')" \
        "$API/stores/${store_id}" || true)
    if [ -z "$(json_id_of "$updated")" ]; then
        echo "store settings were not updated" >&2
        echo "$updated" >&2
        exit 1
    fi
fi

invoice=$(auth -d '{"permissions":["invoice_management"]}' "$API/token" || true)
invoice_token=$(token_of "$invoice")
if [ -z "$invoice_token" ]; then
    invoice=$(auth -d "$(jq -nc --arg email "$EMAIL" --arg password "$BITCART_ADMIN_PASSWORD" \
        '{email:$email,password:$password,permissions:["invoice_management"]}')" \
        "$API/token" || true)
    invoice_token=$(token_of "$invoice")
fi
if [ -z "$invoice_token" ]; then
    echo "invoice token was not created" >&2
    echo "$invoice" >&2
    exit 1
fi

count=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$CACERT" \
    -H "Authorization: Bearer ${invoice_token}" "$API/invoices/count" || true)
if [ "$count" != "200" ]; then
    echo "invoice token was rejected by /invoices/count (HTTP ${count})" >&2
    exit 1
fi

umask 077
tmp=$(mktemp /lab-config/bitcart.env.XXXXXX)
cat > "$tmp" <<EOF
ARKFILE_BITCART_STORE_ID=${store_id}
ARKFILE_BITCART_API_TOKEN=${invoice_token}
EOF
chmod 0600 "$tmp"
mv "$tmp" "$ENV_FILE"
echo "bitcart store ${store_id} is ready"
