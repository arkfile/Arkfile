#!/bin/sh
# Configure Bitcart for the lab mirroring arkfile-bitcart production isolation:
#   - admin@bitcart.lab (superuser): locks down global instance policies and creates merchant
#   - merchant@bitcart.lab (non-superuser): owns watch-only wallets, USD store, and invoice_management token
# Provisioning talks to the internal admin API (:19081/api) and verifies the
# scoped token and blocked routes through the strict public gateway (:19080/api).
# Safe to run repeatedly.
set -eu

# Refuse rootful containers (initial user namespace maps all 4294967295 UIDs at 0 -> 0).
if [ -r /proc/self/uid_map ] && awk '$1 == 0 && $2 == 0 && $3 == 4294967295 { exit 0 } END { exit 1 }' /proc/self/uid_map; then
    echo "[X] Refusing to start in a rootful container (host root user namespace detected)." >&2
    echo "    Run this lab only with rootless Podman via: bash scripts/testing/bitcart-lab/paylab.sh up" >&2
    exit 1
fi

apk add --no-cache curl jq >/dev/null

ADMIN_API="${BITCART_ADMIN_API:-https://bitcart.lab:19081/api}"
PUBLIC_API="${BITCART_PUBLIC_API:-https://bitcart.lab:19080/api}"
CACERT="${BITCART_CACERT:-/ca/ca.crt}"
ENV_FILE=/lab-config/bitcart.env
MERCHANT_ENV=/lab-config/merchant.env
MERCHANT_MARKER=/lab-config/merchant-provisioned
XMR_SPEED_FILE=/lab-config/xmr-tx-speed
ADMIN_EMAIL="${BITCART_ADMIN_EMAIL:-admin@bitcart.lab}"
MERCHANT_EMAIL="${BITCART_MERCHANT_EMAIL:-merchant@bitcart.lab}"

if [ -z "${BITCART_ADMIN_PASSWORD:-}" ] || [ -z "${BTC_XPUB:-}" ]; then
    echo "[X] BITCART_ADMIN_PASSWORD and BTC_XPUB are required in lab.env" >&2
    exit 1
fi

case "$BTC_XPUB" in
    xprv*|yprv*|zprv*|tprv*|uprv*|vprv*)
        echo "[X] BTC_XPUB looks like a private key. Provide an extended public key." >&2
        exit 1
        ;;
esac

speed=${BITCART_TX_SPEED:-1}
case "$speed" in
    ''|*[!0-9]*) echo "[X] BITCART_TX_SPEED must be a positive integer" >&2; exit 1 ;;
esac
if [ "$speed" -lt 1 ]; then
    echo "[X] BITCART_TX_SPEED must be at least 1" >&2
    exit 1
fi

xmr_speed=${XMR_TX_SPEED:-5}
case "$xmr_speed" in
    ''|*[!0-9]*) echo "[X] XMR_TX_SPEED must be a positive integer" >&2; exit 1 ;;
esac
if [ "$xmr_speed" -lt 5 ]; then
    echo "[X] XMR_TX_SPEED must be at least 5" >&2
    exit 1
fi

log_retention_days=${BITCART_LOG_RETENTION_DAYS:-21}
case "$log_retention_days" in
    ''|*[!0-9]*) echo "[X] BITCART_LOG_RETENTION_DAYS must be a positive integer" >&2; exit 1 ;;
esac
if [ "$log_retention_days" -lt 1 ]; then
    echo "[X] BITCART_LOG_RETENTION_DAYS must be at least 1" >&2
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
        if curl_api -o /dev/null "$ADMIN_API/cryptos" 2>/dev/null || curl_api -o /dev/null "$ADMIN_API/manage/policies" 2>/dev/null; then
            echo "[OK] bitcart API is up"
            return 0
        fi
        i=$((i + 1))
        sleep 2
    done
    echo "[X] bitcart API did not become ready" >&2
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
        and .checkout_settings.expiration == 60
        and .checkout_settings.transaction_speed == $speed
        and .checkout_settings.underpaid_percentage == 0
        and .checkout_settings.email_required == false
        and .checkout_settings.allow_anonymous_invoice_creation == false
        and (.default_currency | ascii_upcase) == "USD"
        and (((.currency_data // {}) | to_entries | map(select((.key | ascii_downcase) == "btc" and (.value > 0))) | length) > 0)
        and ($want_xmr == 0 or (((.currency_data // {}) | to_entries | map(select((.key | ascii_downcase) == "xmr" and (.value > 0))) | length) > 0))
    ' >/dev/null 2>&1
}

wait_api

if [ -f "$ENV_FILE" ] && [ -f "$MERCHANT_MARKER" ]; then
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    xmr_speed_ok=1
    if [ "$want_xmr" -eq 1 ]; then
        prev_xmr_speed=$(cat "$XMR_SPEED_FILE" 2>/dev/null || true)
        if [ "$prev_xmr_speed" != "$xmr_speed" ]; then
            xmr_speed_ok=0
        fi
    fi
    if [ -n "${ARKFILE_BITCART_STORE_ID:-}" ] && [ -n "${ARKFILE_BITCART_API_TOKEN:-}" ] && [ "$xmr_speed_ok" -eq 1 ]; then
        code=$(curl -sS -o /tmp/store.json -w '%{http_code}' --cacert "$CACERT" \
            -H "Authorization: Bearer ${ARKFILE_BITCART_API_TOKEN}" \
            "$PUBLIC_API/stores/${ARKFILE_BITCART_STORE_ID}" || true)
        count=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$CACERT" \
            -H "Authorization: Bearer ${ARKFILE_BITCART_API_TOKEN}" \
            "$PUBLIC_API/invoices/count" || true)
        if [ "$code" = "200" ] && [ "$count" = "200" ] && settings_ok "$(cat /tmp/store.json)"; then
            chmod 0600 "$ENV_FILE"
            echo "[OK] existing non-superuser merchant invoice token and store are valid"
            exit 0
        fi
        echo "[!] stored token or store settings need to be updated"
    fi
fi

if [ ! -f "$MERCHANT_ENV" ]; then
    echo "[X] missing ${MERCHANT_ENV}; secrets-init must complete before provision" >&2
    exit 1
fi
# shellcheck disable=SC1090
. "$MERCHANT_ENV"
if [ -z "${MERCHANT_PASSWORD:-}" ]; then
    echo "[X] MERCHANT_PASSWORD is empty in ${MERCHANT_ENV}" >&2
    exit 1
fi

# Step 1: Register or authenticate initial superuser (admin@bitcart.lab).
admin_login=$(curl -sS --cacert "$CACERT" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg email "$ADMIN_EMAIL" --arg password "$BITCART_ADMIN_PASSWORD" \
        '{email:$email,password:$password,permissions:["full_control"]}')" \
    "$ADMIN_API/token" || true)
admin_token=$(token_of "$admin_login")

if [ -z "$admin_token" ]; then
    create_user=$(curl -sS -w '\n%{http_code}' --cacert "$CACERT" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg email "$ADMIN_EMAIL" --arg password "$BITCART_ADMIN_PASSWORD" \
            '{email:$email,password:$password,captcha_code:""}')" \
        "$ADMIN_API/users" || true)
    user_body=$(printf '%s' "$create_user" | sed '$d')
    user_code=$(printf '%s' "$create_user" | tail -n 1)
    admin_token=$(token_of "$user_body")

    if [ -z "$admin_token" ]; then
        admin_login=$(curl -sS --cacert "$CACERT" \
            -H 'Content-Type: application/json' \
            -d "$(jq -nc --arg email "$ADMIN_EMAIL" --arg password "$BITCART_ADMIN_PASSWORD" \
                '{email:$email,password:$password,permissions:["full_control"]}')" \
            "$ADMIN_API/token" || true)
        admin_token=$(token_of "$admin_login")
    fi
    if [ -z "$admin_token" ]; then
        echo "[X] could not register or authenticate Bitcart superuser ${ADMIN_EMAIL} (user HTTP ${user_code})" >&2
        echo "$user_body" >&2
        echo "$admin_login" >&2
        echo "Open https://bitcart.lab:19081/ to inspect, then re-run provision." >&2
        exit 1
    fi
fi

auth_as() {
    tok=$1
    shift
    curl -sS --cacert "$CACERT" -H "Authorization: Bearer ${tok}" -H 'Content-Type: application/json' "$@"
}

# Step 2: Lock down global Bitcart instance policies (mirrors arkfile-bitcart).
policy_resp=$(auth_as "$admin_token" -w '\n%{http_code}' -d "$(jq -nc --argjson days "$log_retention_days" '{
    disable_registration: true,
    discourage_index: true,
    check_updates: false,
    allow_anonymous_configurator: false,
    allow_file_uploads: false,
    log_retention_days: $days
}')" "$ADMIN_API/manage/policies" || true)
policy_code=$(printf '%s' "$policy_resp" | tail -n 1)
if [ "$policy_code" != "200" ]; then
    echo "[X] failed to apply global Bitcart policies (HTTP ${policy_code})" >&2
    printf '%s\n' "$policy_resp" | sed '$d' >&2
    exit 1
fi
echo "[OK] applied hardened global Bitcart policies (log_retention_days=${log_retention_days})"

# Step 3: Ensure isolated non-superuser merchant account (merchant@bitcart.lab).
users_json=$(auth_as "$admin_token" "$ADMIN_API/users?limit=-1" || true)
user_rows=$(json_rows_of "$users_json")
existing_merchant=$(printf '%s' "$user_rows" | jq -c --arg e "$MERCHANT_EMAIL" '[.[] | select(.email == $e)][0] // empty' 2>/dev/null || true)

if [ -n "$existing_merchant" ]; then
    is_su=$(printf '%s' "$existing_merchant" | jq -r '.is_superuser')
    if [ "$is_su" != "false" ]; then
        echo "[X] merchant account ${MERCHANT_EMAIL} has is_superuser=${is_su}; tenant accounts must never be superusers" >&2
        exit 1
    fi
    echo "[OK] verified existing non-superuser merchant account ${MERCHANT_EMAIL}"
else
    create_merchant=$(auth_as "$admin_token" -w '\n%{http_code}' -d "$(jq -nc \
        --arg email "$MERCHANT_EMAIL" \
        --arg password "$MERCHANT_PASSWORD" \
        '{email:$email,password:$password,is_superuser:false}')" \
        "$ADMIN_API/users" || true)
    merchant_code=$(printf '%s' "$create_merchant" | tail -n 1)
    if [ "$merchant_code" != "200" ] && [ "$merchant_code" != "201" ]; then
        echo "[X] failed to create non-superuser merchant ${MERCHANT_EMAIL} (HTTP ${merchant_code})" >&2
        printf '%s\n' "$create_merchant" | sed '$d' >&2
        exit 1
    fi
    echo "[OK] created non-superuser merchant account ${MERCHANT_EMAIL}"
fi

# Authenticate as the non-superuser merchant in memory to own wallets, store, and scoped token.
merchant_login=$(curl -sS --cacert "$CACERT" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg email "$MERCHANT_EMAIL" --arg password "$MERCHANT_PASSWORD" \
        '{email:$email,password:$password,permissions:["full_control"]}')" \
    "$ADMIN_API/token" || true)
merchant_token=$(token_of "$merchant_login")
if [ -z "$merchant_token" ]; then
    echo "[X] failed to authenticate non-superuser merchant ${MERCHANT_EMAIL}" >&2
    echo "$merchant_login" >&2
    exit 1
fi

# Step 4: Ensure watch-only wallets owned by merchant@bitcart.lab.
wallets_json=$(auth_as "$merchant_token" "$ADMIN_API/wallets?limit=-1" || true)
wallet_rows=$(json_rows_of "$wallets_json")

find_wallet() {
    currency=$1
    printf '%s' "$wallet_rows" | jq -r --arg c "$currency" '[.[] | select((.currency // "" | ascii_downcase)==$c)][0].id // empty' 2>/dev/null || true
}

btc_id=$(find_wallet btc)
if [ -z "$btc_id" ]; then
    created=$(auth_as "$merchant_token" -d "$(jq -nc --arg xpub "$BTC_XPUB" \
        '{name:"lab-btc",xpub:$xpub,currency:"btc",lightning_enabled:false}')" \
        "$ADMIN_API/wallets" || true)
    btc_id=$(json_id_of "$created")
    if [ -z "$btc_id" ]; then
        echo "[X] bitcoin wallet was not created" >&2
        echo "$created" >&2
        echo "Check the extended public key, then open https://bitcart.lab:19081/ and re-run provision." >&2
        exit 1
    fi
    echo "[OK] created watch-only BTC wallet (${btc_id})"
else
    echo "[OK] verified watch-only BTC wallet (${btc_id})"
fi

xmr_id=""
if [ "$want_xmr" -eq 1 ]; then
    if [ -z "${XMR_ADDRESS:-}" ] || [ -z "${XMR_PRIVATE_VIEW_KEY:-}" ]; then
        echo "[X] XMR_ADDRESS and XMR_PRIVATE_VIEW_KEY are required when BITCART_CRYPTOS includes xmr" >&2
        exit 1
    fi
    xmr_id=$(find_wallet xmr)
    if [ -z "$xmr_id" ]; then
        extra=$(jq -nc --arg address "$XMR_ADDRESS" '{address:$address}')
        if [ -n "${XMR_RESTORE_HEIGHT:-}" ]; then
            extra=$(printf '%s' "$extra" | jq --argjson h "$XMR_RESTORE_HEIGHT" '. + {restore_height:$h}')
        fi
        created=$(auth_as "$merchant_token" -d "$(jq -nc --arg key "$XMR_PRIVATE_VIEW_KEY" --argjson extra "$extra" --argjson xmr_speed "$xmr_speed" \
            '{name:"lab-xmr",xpub:$key,currency:"xmr",transaction_speed:$xmr_speed,additional_xpub_data:$extra}')" \
            "$ADMIN_API/wallets" || true)
        xmr_id=$(json_id_of "$created")
        if [ -z "$xmr_id" ] && [ -n "${XMR_RESTORE_HEIGHT:-}" ]; then
            echo "[!] retrying monero wallet without restore_height"
            created=$(auth_as "$merchant_token" -d "$(jq -nc --arg key "$XMR_PRIVATE_VIEW_KEY" --arg address "$XMR_ADDRESS" --argjson xmr_speed "$xmr_speed" \
                '{name:"lab-xmr",xpub:$key,currency:"xmr",transaction_speed:$xmr_speed,additional_xpub_data:{address:$address}}')" \
                "$ADMIN_API/wallets" || true)
            xmr_id=$(json_id_of "$created")
        fi
        if [ -z "$xmr_id" ]; then
            echo "[X] monero wallet was not created" >&2
            echo "$created" >&2
            exit 1
        fi
        echo "[OK] created watch-only XMR wallet (${xmr_id}, transaction_speed=${xmr_speed})"
    else
        updated_xmr=$(auth_as "$merchant_token" -X PATCH -d "$(jq -nc --argjson xmr_speed "$xmr_speed" '{transaction_speed:$xmr_speed}')" \
            "$ADMIN_API/wallets/${xmr_id}" || true)
        if [ -z "$(json_id_of "$updated_xmr")" ]; then
            echo "[X] monero wallet transaction_speed was not updated" >&2
            echo "$updated_xmr" >&2
            exit 1
        fi
        echo "[OK] verified watch-only XMR wallet (${xmr_id}, transaction_speed=${xmr_speed})"
    fi
fi

# Step 5: Ensure USD store and checkout settings owned by merchant@bitcart.lab.
stores_json=$(auth_as "$merchant_token" "$ADMIN_API/stores?limit=-1" || true)
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
    created=$(auth_as "$merchant_token" -d "$(jq -nc --argjson wallets "$wallets" --argjson checkout "$checkout" \
        '{name:"lab",default_currency:"USD",wallets:$wallets,checkout_settings:$checkout}')" \
        "$ADMIN_API/stores" || true)
    store_id=$(json_id_of "$created")
    if [ -z "$store_id" ]; then
        echo "[X] store was not created" >&2
        echo "$created" >&2
        exit 1
    fi
    echo "[OK] created merchant USD store lab (${store_id})"
else
    updated=$(auth_as "$merchant_token" -X PATCH -d "$(jq -nc --argjson wallets "$wallets" --argjson checkout "$checkout" \
        '{name:"lab",default_currency:"USD",wallets:$wallets,checkout_settings:$checkout}')" \
        "$ADMIN_API/stores/${store_id}" || true)
    if [ -z "$(json_id_of "$updated")" ]; then
        echo "[X] store settings were not updated" >&2
        echo "$updated" >&2
        exit 1
    fi
    echo "[OK] updated merchant USD store lab (${store_id})"
fi

# Step 6: Preserve existing valid merchant token if possible, otherwise mint a scoped invoice_management token.
invoice_token=""
if [ -f "$ENV_FILE" ] && [ -f "$MERCHANT_MARKER" ]; then
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    if [ -n "${ARKFILE_BITCART_API_TOKEN:-}" ] && [ "${ARKFILE_BITCART_STORE_ID:-}" = "$store_id" ]; then
        existing_count=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$CACERT" \
            -H "Authorization: Bearer ${ARKFILE_BITCART_API_TOKEN}" \
            "$PUBLIC_API/invoices/count" || true)
        existing_store=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$CACERT" \
            -H "Authorization: Bearer ${ARKFILE_BITCART_API_TOKEN}" \
            "$PUBLIC_API/stores/${store_id}" || true)
        if [ "$existing_count" = "200" ] && [ "$existing_store" = "200" ]; then
            invoice_token="$ARKFILE_BITCART_API_TOKEN"
            echo "[OK] preserved existing valid invoice_management token"
        fi
    fi
fi

if [ -z "$invoice_token" ]; then
    invoice=$(curl -sS --cacert "$CACERT" \
        -H 'Content-Type: application/json' \
        -d "$(jq -nc --arg email "$MERCHANT_EMAIL" --arg password "$MERCHANT_PASSWORD" \
            '{email:$email,password:$password,permissions:["invoice_management"],app_id:"arkfile-lab"}')" \
        "$ADMIN_API/token" || true)
    invoice_token=$(token_of "$invoice")
    if [ -z "$invoice_token" ]; then
        echo "[X] invoice_management token was not created for ${MERCHANT_EMAIL}" >&2
        echo "$invoice" >&2
        exit 1
    fi
    echo "[OK] minted scoped invoice_management token for ${MERCHANT_EMAIL}"
fi

# Step 7: Verify public gateway (:19080/api) permits required Arkfile routes and blocks batch mark_complete.
count=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$CACERT" \
    -H "Authorization: Bearer ${invoice_token}" "$PUBLIC_API/invoices/count" || true)
if [ "$count" != "200" ]; then
    echo "[X] public gateway rejected /invoices/count (HTTP ${count})" >&2
    exit 1
fi

store_code=$(curl -sS -o /tmp/store.json -w '%{http_code}' --cacert "$CACERT" \
    -H "Authorization: Bearer ${invoice_token}" "$PUBLIC_API/stores/${store_id}" || true)
if [ "$store_code" != "200" ] || ! settings_ok "$(cat /tmp/store.json)"; then
    echo "[X] public gateway store check failed (HTTP ${store_code}): $(cat /tmp/store.json)" >&2
    exit 1
fi

batch_code=$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$CACERT" \
    -X POST -H "Authorization: Bearer ${invoice_token}" -H 'Content-Type: application/json' \
    -d '{"ids":["00000000000000000000000000"],"command":"mark_complete"}' \
    "$PUBLIC_API/invoices/batch" || true)
if [ "$batch_code" != "404" ]; then
    echo "[X] public gateway did not block POST /api/invoices/batch (got HTTP ${batch_code}, expected 404)" >&2
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

printf '%s\n' "$MERCHANT_EMAIL" > "$MERCHANT_MARKER"
chmod 0600 "$MERCHANT_MARKER"

if [ "$want_xmr" -eq 1 ]; then
    printf '%s\n' "$xmr_speed" > "$XMR_SPEED_FILE"
    chmod 0600 "$XMR_SPEED_FILE"
fi
echo "[OK] bitcart merchant store ${store_id} is ready"
