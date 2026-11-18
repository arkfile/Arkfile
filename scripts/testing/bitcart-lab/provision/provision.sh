#!/bin/sh
# Configure Bitcart for the lab: one admin, watch-only wallets, one USD store,
# and an invoice-only token for Arkfile. Safe to run again.
set -eu

apk add --no-cache curl jq >/dev/null

API="${BITCART_API:-https://bitcart.lab:19080/api}"
CACERT="${BITCART_CACERT:-/ca/ca.crt}"
ENV_FILE=/lab-config/bitcart.env
EMAIL="${BITCART_ADMIN_EMAIL:-admin@bitcart.lab}"

if [ -z "${BITCART_ADMIN_PASSWORD:-}" ] || [ -z "${BTC_XPUB:-}" ]; then
    echo "BITCART_ADMIN_PASSWORD and BTC_XPUB are required" >&2
    exit 1
fi

case "$BTC_XPUB" in
    xprv*|yprv*|zprv*|tprv*|uprv*|vprv*)
        echo "BTC_XPUB looks like a private key. Provide an extended public key." >&2
        exit 1
        ;;
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
    printf '%s' "$1" | jq -r '.access_token // .token // empty'
}

settings_ok() {
    body=$1
    echo "$body" | jq -e '
        .checkout_settings.transaction_speed >= 1
        and .checkout_settings.underpaid_percentage == 0
        and .checkout_settings.email_required == false
        and .checkout_settings.allow_anonymous_invoice_creation == false
        and (.default_currency | ascii_upcase) == "USD"
    ' >/dev/null
}

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
            echo "existing invoice token and store are valid"
            exit 0
        fi
        echo "stored token or store settings need to be created again"
    fi
fi

wait_api

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
        "$API/token")
    admin_token=$(token_of "$login")
    if [ -z "$admin_token" ]; then
        echo "could not register or authenticate the Bitcart admin (user HTTP ${user_code})" >&2
        echo "$user_body" >&2
        echo "$login" >&2
        echo "Open https://bitcart.lab:19080/admin if the API shape differs, then re-run provision." >&2
        exit 1
    fi
fi

auth() {
    curl -sS --cacert "$CACERT" -H "Authorization: Bearer ${admin_token}" -H 'Content-Type: application/json' "$@"
}

wallets_json=$(auth "$API/wallets")
wallet_rows=$(printf '%s' "$wallets_json" | jq -c 'if type=="array" then . elif .result then .result else [] end')

find_wallet() {
    currency=$1
    printf '%s' "$wallet_rows" | jq -r --arg c "$currency" '[.[] | select((.currency|ascii_downcase)==$c)][0].id // empty'
}

btc_id=$(find_wallet btc)
if [ -z "$btc_id" ]; then
    created=$(auth -d "$(jq -nc --arg xpub "$BTC_XPUB" \
        '{name:"lab-btc",xpub:$xpub,currency:"btc",lightning_enabled:false}')" \
        "$API/wallets")
    btc_id=$(printf '%s' "$created" | jq -r '.id // empty')
    if [ -z "$btc_id" ]; then
        echo "bitcoin wallet was not created" >&2
        echo "$created" >&2
        echo "Check the extended public key, then open https://bitcart.lab:19080/admin and re-run provision." >&2
        exit 1
    fi
fi

speed=${BITCART_TX_SPEED:-1}
case "$speed" in
    ''|*[!0-9]*) echo "BITCART_TX_SPEED must be a positive integer" >&2; exit 1 ;;
esac
if [ "$speed" -lt 1 ]; then
    echo "BITCART_TX_SPEED must be at least 1" >&2
    exit 1
fi

xmr_id=""
cryptos=$(printf '%s' "${BITCART_CRYPTOS:-btc}" | tr '[:upper:]' '[:lower:]')
case ",$cryptos," in
    *,xmr,*)
        if [ -z "${XMR_ADDRESS:-}" ] || [ -z "${XMR_VIEW_KEY:-}" ]; then
            echo "XMR_ADDRESS and XMR_VIEW_KEY are required when BITCART_CRYPTOS includes xmr" >&2
            exit 1
        fi
        xmr_id=$(find_wallet xmr)
        if [ -z "$xmr_id" ]; then
            extra=$(jq -nc --arg address "$XMR_ADDRESS" '{address:$address}')
            if [ -n "${XMR_RESTORE_HEIGHT:-}" ]; then
                extra=$(printf '%s' "$extra" | jq --argjson h "$XMR_RESTORE_HEIGHT" '. + {restore_height:$h}')
            fi
            created=$(auth -d "$(jq -nc --arg key "$XMR_VIEW_KEY" --argjson extra "$extra" \
                '{name:"lab-xmr",xpub:$key,currency:"xmr",additional_xpub_data:$extra}')" \
                "$API/wallets")
            xmr_id=$(printf '%s' "$created" | jq -r '.id // empty')
            if [ -z "$xmr_id" ] && [ -n "${XMR_RESTORE_HEIGHT:-}" ]; then
                echo "retrying monero wallet without restore_height"
                created=$(auth -d "$(jq -nc --arg key "$XMR_VIEW_KEY" --arg address "$XMR_ADDRESS" \
                    '{name:"lab-xmr",xpub:$key,currency:"xmr",additional_xpub_data:{address:$address}}')" \
                    "$API/wallets")
                xmr_id=$(printf '%s' "$created" | jq -r '.id // empty')
            fi
            if [ -z "$xmr_id" ]; then
                echo "monero wallet was not created" >&2
                echo "$created" >&2
                exit 1
            fi
        fi
        ;;
esac

stores_json=$(auth "$API/stores")
store_rows=$(printf '%s' "$stores_json" | jq -c 'if type=="array" then . elif .result then .result else [] end')
store_id=$(printf '%s' "$store_rows" | jq -r '[.[] | select(.name=="lab")][0].id // empty')

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
        "$API/stores")
    store_id=$(printf '%s' "$created" | jq -r '.id // empty')
    if [ -z "$store_id" ]; then
        echo "store was not created" >&2
        echo "$created" >&2
        exit 1
    fi
else
    updated=$(auth -X PATCH -d "$(jq -nc --argjson wallets "$wallets" --argjson checkout "$checkout" \
        '{default_currency:"USD",wallets:$wallets,checkout_settings:$checkout}')" \
        "$API/stores/${store_id}")
    if ! printf '%s' "$updated" | jq -e '.id' >/dev/null; then
        echo "store settings were not updated" >&2
        echo "$updated" >&2
        exit 1
    fi
fi

invoice=$(auth -d '{"permissions":["invoice_management"]}' "$API/token")
invoice_token=$(token_of "$invoice")
if [ -z "$invoice_token" ]; then
    echo "invoice token was not created" >&2
    echo "$invoice" >&2
    exit 1
fi

count=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$CACERT" \
    -H "Authorization: Bearer ${invoice_token}" "$API/invoices/count")
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
chmod 0640 "$tmp"
mv "$tmp" "$ENV_FILE"
echo "bitcart store ${store_id} is ready"
