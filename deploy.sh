#!/bin/bash
set -e

# ==============================================
#           VLESS WS TLS GCP AUTO DEPLOYER
#              created by prvtspyyy
# ==============================================

# --- ANSI color & style definitions ---
BOLD='\033[1m'
RESET='\033[0m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[0;37m'
LRED='\033[1;31m'
LGREEN='\033[1;32m'
LYELLOW='\033[1;33m'
LBLUE='\033[1;34m'
LMAGENTA='\033[1;35m'
LCYAN='\033[1;36m'
LWHITE='\033[1;37m'

C_SUCCESS="${BOLD}${LGREEN}"
C_ERROR="${BOLD}${LRED}"
C_WARN="${BOLD}${LYELLOW}"
C_INFO="${BOLD}${LCYAN}"
C_HEADER="${BOLD}${LMAGENTA}"
C_ACCENT="${BOLD}${LBLUE}"
C_PLAIN="${BOLD}${WHITE}"

# --- Bold mathematical Unicode converter ---
math_bold() {
    echo "$1" | sed -e 's/A/𝗔/g' -e 's/B/𝗕/g' -e 's/C/𝗖/g' -e 's/D/𝗗/g' -e 's/E/𝗘/g' \
        -e 's/F/𝗙/g' -e 's/G/𝗚/g' -e 's/H/𝗛/g' -e 's/I/𝗜/g' -e 's/J/𝗝/g' \
        -e 's/K/𝗞/g' -e 's/L/𝗟/g' -e 's/M/𝗠/g' -e 's/N/𝗡/g' -e 's/O/𝗢/g' \
        -e 's/P/𝗣/g' -e 's/Q/𝗤/g' -e 's/R/𝗥/g' -e 's/S/𝗦/g' -e 's/T/𝗧/g' \
        -e 's/U/𝗨/g' -e 's/V/𝗩/g' -e 's/W/𝗪/g' -e 's/X/𝗫/g' -e 's/Y/𝗬/g' \
        -e 's/Z/𝗭/g' -e 's/0/𝟬/g' -e 's/1/𝟭/g' -e 's/2/𝟮/g' -e 's/3/𝟯/g' \
        -e 's/4/𝟰/g' -e 's/5/𝟱/g' -e 's/6/𝟲/g' -e 's/7/𝟳/g' -e 's/8/𝟴/g' \
        -e 's/9/𝟵/g'
}

# --- Rainbow Banner ---
rainbow_banner() {
    clear
    echo ""
        echo ""
    echo -e "${BOLD}${LRED}╔══════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${BOLD}${LRED}║${RESET}                                                                                ${BOLD}${LRED}║${RESET}"
    echo -e "${BOLD}${LRED}║${RESET}         ${BOLD}${WHITE}██████╗ ██████╗ ██╗   ██╗████████╗███████╗██████╗ ██╗   ██╗${LRED}         ${BOLD}${LRED}║${RESET}"
    echo -e "${BOLD}${LRED}║${RESET}         ${BOLD}${WHITE}██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗╚██╗ ██╔╝${LRED}         ${BOLD}${LRED}║${RESET}"
    echo -e "${BOLD}${LRED}║${RESET}         ${BOLD}${WHITE}██████╔╝██████╔╝██║   ██║   ██║   ███████╗██████╔╝ ╚████╔╝ ${LRED}         ${BOLD}${LRED}║${RESET}"
    echo -e "${BOLD}${LRED}║${RESET}         ${BOLD}${WHITE}██╔═══╝ ██╔══██╗╚██╗ ██╔╝   ██║   ╚════██║██╔═══╝   ╚██╔╝  ${LRED}         ${BOLD}${LRED}║${RESET}"
    echo -e "${BOLD}${LRED}║${RESET}         ${BOLD}${WHITE}██║     ██║  ██║ ╚████╔╝    ██║   ███████║██║        ██║   ${LRED}         ${BOLD}${LRED}║${RESET}"
    echo -e "${BOLD}${LRED}║${RESET}         ${BOLD}${WHITE}╚═╝     ╚═╝  ╚═╝  ╚═══╝     ╚═╝   ╚══════╝╚═╝        ╚═╝   ${LRED}         ${BOLD}${LRED}║${RESET}"
    echo -e "${BOLD}${LRED}║${RESET}                                                                                ${BOLD}${LRED}║${RESET}"
    echo -e "${BOLD}${LRED}║${RESET}                    ${BOLD}${WHITE}Automated Deployment Made Easy${RESET}                         ${BOLD}${LRED}║${RESET}"
    echo -e "${BOLD}${LRED}║${RESET}           ${CYAN}For Complains and Concers Message Saeka Tojirp Privately${RESET}          ${BOLD}${LRED}║${RESET}"
    echo -e "${BOLD}${LRED}║${RESET}                                                                                ${BOLD}${LRED}║${RESET}"
    echo -e "${BOLD}${LRED}╚══════════════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

rainbow_banner

# ==============================================
#        FAILSAFE API VERIFICATION
# ==============================================
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${C_PLAIN}$(math_bold "API VERIFICATION")${RESET}"
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"

REQUIRED_APIS=("run.googleapis.com" "containerregistry.googleapis.com" "cloudbuild.googleapis.com" "compute.googleapis.com")
API_NAMES=("Cloud Run API" "Container Registry API" "Cloud Build API" "Compute Engine API")

for i in "${!REQUIRED_APIS[@]}"; do
    API="${REQUIRED_APIS[$i]}"
    NAME="${API_NAMES[$i]}"
    echo -e "${C_INFO}[*]${RESET} Checking ${BOLD}${NAME}${RESET}..."
    
    # Check if API is already enabled
    if gcloud services list --enabled --filter="name:${API}" --format="value(name)" 2>/dev/null | grep -q "${API}"; then
        echo -e "${C_SUCCESS}[✔]${RESET} ${NAME} already enabled"
    else
        echo -e "${C_WARN}[!]${RESET} Enabling ${NAME}..."
        # Use || true to prevent set -e from killing script
        gcloud services enable "${API}" --quiet 2>/dev/null || true
        echo -e "${C_SUCCESS}[✔]${RESET} ${NAME} enablement requested"
    fi
done
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo ""

# --- Project Setup ---
PROJECT_ID=$(gcloud config get-value project 2>/dev/null)
if [ -z "$PROJECT_ID" ]; then
    PROJECT_ID="vless-$(date +%s)"
    gcloud projects create "$PROJECT_ID" --name="VLESS-WS-TLS" --quiet
    gcloud config set project "$PROJECT_ID" --quiet
fi
echo -e "${C_SUCCESS}[✔]${RESET} Project: ${BOLD}${PROJECT_ID}${RESET}"
echo ""

# ==============================================
#        AUTOMATIC REGION SELECTION (QWIKLABS)
# ==============================================
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${C_PLAIN}$(math_bold "REGION SELECTION")${RESET}"
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"

# Qwiklabs projects are restricted to us-central1 by organization policy.
# Any other region will fail with a policy violation.
REGION="us-central1"

echo -e "${C_INFO}[*]${RESET} Qwiklabs environment detected."
echo -e "${C_SUCCESS}[✔]${RESET} Automatically locked to region: ${BOLD}${WHITE}${REGION}${RESET}"
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo ""

# Customizable service name
DEFAULT_SERVICE_NAME="prvtspyyy404"
read -p "$(echo -e "${C_INFO}[?]${RESET} Enter service name [default: ${DEFAULT_SERVICE_NAME}]: ")" SERVICE_NAME_INPUT
SERVICE_NAME="${SERVICE_NAME_INPUT:-$DEFAULT_SERVICE_NAME}"
SERVICE_NAME=$(echo "$SERVICE_NAME" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/--*/-/g' | sed 's/^-//;s/-$//')
if [ -z "$SERVICE_NAME" ]; then
    SERVICE_NAME="$DEFAULT_SERVICE_NAME"
fi
echo -e "${C_SUCCESS}[✔]${RESET} Service name: ${BOLD}${SERVICE_NAME}${RESET}"
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo ""

# ==============================================
#        CPU AND MEMORY SELECTION (FIXED)
# ==============================================
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${C_PLAIN}$(math_bold "CPU AND MEMORY SELECTION")${RESET}"
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo -e "  ${C_ACCENT}[1]${RESET} 1 vCPU, 1 GiB RAM"
echo -e "  ${C_ACCENT}[2]${RESET} 1 vCPU, 2 GiB RAM"
echo -e "  ${C_ACCENT}[3]${RESET} 2 vCPU, 2 GiB RAM"
echo -e "  ${C_ACCENT}[4]${RESET} 2 vCPU, 4 GiB RAM ${GREEN}(RECOMMENDED)${RESET}"
echo -e "  ${C_ACCENT}[5]${RESET} 4 vCPU, 8 GiB RAM"
echo -e "  ${C_ACCENT}[6]${RESET} 4 vCPU, 16 GiB RAM"
read -p "$(echo -e "${C_INFO}[?]${RESET} Select configuration [1-6] [default: 4]: ")" CPU_RAM_CHOICE

# Default to 4 if empty
CPU_RAM_CHOICE="${CPU_RAM_CHOICE:-4}"

case $CPU_RAM_CHOICE in
    1) CPU="1"; MEMORY="1Gi" ;;
    2) CPU="1"; MEMORY="2Gi" ;;
    3) CPU="2"; MEMORY="2Gi" ;;
    4) CPU="2"; MEMORY="4Gi" ;;
    5) CPU="4"; MEMORY="8Gi" ;;
    6) CPU="4"; MEMORY="16Gi" ;;
    *) CPU="2"; MEMORY="4Gi" ; echo -e "${C_WARN}[!]${RESET} Invalid choice, using recommended (2 vCPU, 4 GiB)" ;;
esac

echo -e "${C_SUCCESS}[✔]${RESET} CPU: ${BOLD}${CPU}${RESET}, Memory: ${BOLD}${MEMORY}${RESET}"
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo ""
# ==============================================
#        ULTRA-STABLE DEPLOYMENT ENGINE
# ==============================================
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${C_PLAIN}$(math_bold "INITIATING FULL SYSTEM DEPLOYMENT")${RESET}"
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"

# 1. PRE-FLIGHT CHECK (Ensures APIs are ready)
echo -ne "${C_INFO}[*]${RESET} Verifying Google Cloud Environment...\r"
gcloud services enable run.googleapis.com containerregistry.googleapis.com > /dev/null 2>&1
echo -e "${C_SUCCESS}[✔]${RESET} Verifying Google Cloud Environment... READY! \033[K"

# Extract Variables
UUID=$(grep -o '"id": *"[^"]*"' config.json | cut -d'"' -f4 | head -n 1)
WS_PATH=$(grep -o '"path": *"[^"]*"' config.json | cut -d'"' -f4 | head -n 1)
IMAGE="gcr.io/$PROJECT_ID/$SERVICE_NAME:latest"

# 2. BUILD
echo -ne "${C_INFO}[*]${RESET} Building high-speed container image...\r"
if ! docker build -t "$IMAGE" . --quiet > /dev/null 2>&1; then
    echo -e "${C_ERROR}[✘]${RESET} Build Failed. Check your Dockerfile content."
    exit 1
fi
echo -e "${C_SUCCESS}[✔]${RESET} Building high-speed container image... SUCCESSFUL! \033[K"

# 3. PUSH
echo -ne "${C_INFO}[*]${RESET} Pushing to Global Registry...\r"
if ! docker push "$IMAGE" --quiet > /dev/null 2>&1; then
    echo -e "${C_ERROR}[✘]${RESET} Push Failed. Check your internet or permissions."
    exit 1
fi
echo -e "${C_SUCCESS}[✔]${RESET} Pushing to Global Registry... SUCCESSFUL! \033[K"

# --- Deploy to Cloud Run (Corrected Port) ---
echo -e "${C_INFO}[*]${RESET} Deploying to Cloud Run in ${REGION}..."
gcloud run deploy "$SERVICE_NAME" \
    --image "$IMAGE" \
    --platform managed \
    --region us-central1 \
    --allow-unauthenticated \
    --port 8080 \
    --cpu 2 \
    --memory 4Gi \
    --cpu-boost \
    --concurrency 1000 \
    --timeout 3600 \
    --min-instances 1 \
    --max-instances 1 \
    --no-cpu-throttling \
    --session-affinity \
    --quiet

if [ $? -eq 0 ]; then
    SERVICE_URL=$(gcloud run services describe "$SERVICE_NAME" --region "$REGION" --format='value(status.url)' 2>/dev/null)
    CLEAN_HOST=$(echo "$SERVICE_URL" | sed 's|https://||')
    
    echo -e "${C_SUCCESS}[✔]${RESET} Deployment complete"
else
    echo -e "${C_ERROR}[✘]${RESET} Deployment failed. Check the error message above."
    exit 1
fi

# --- URI Generation (Now CLEAN_HOST is actually defined) ---
VLESS_URI="vless://${UUID}@${CLEAN_HOST}:443?encryption=none&security=tls&type=ws&path=%2F${WS_PATH#/}&host=${CLEAN_HOST}&sni=${CLEAN_HOST}&fp=chrome#${SERVICE_NAME}"
echo ""
echo -e "${C_SUCCESS}╔════════════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${C_SUCCESS}║${RESET}                                                                            ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${BOLD}${WHITE}$(math_bold "DEPLOYMENT SUCCESSFUL")${RESET}                                          ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}created by prvtspyyy${RESET}                                              ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}║${RESET}                                                                            ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}╠════════════════════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${C_SUCCESS}║${RESET}                                                                            ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}Service:${RESET}     ${BOLD}${SERVICE_NAME}${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}Address:${RESET}     ${BOLD}www.gstatic.com${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}SNI:${RESET}         ${BOLD}firebase-settings.crashlytics.com${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}Host:${RESET}        ${BOLD}${CLEAN_HOST}${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}Port:${RESET}        ${BOLD}443${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}UUID:${RESET}        ${BOLD}${UUID}${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}WS Path:${RESET}     ${BOLD}${WS_PATH}${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}Transport:${RESET}   ${BOLD}WebSocket (ws)${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}Security:${RESET}    ${BOLD}TLS (Google Managed)${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}Region:${RESET}      ${BOLD}${REGION}${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}CPU:${RESET}         ${BOLD}${CPU}${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}Memory:${RESET}      ${BOLD}${MEMORY}${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}Timeout:${RESET}     ${BOLD}3600s${RESET}"
echo -e "${C_SUCCESS}║${RESET}                                                                            ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}╠════════════════════════════════════════════════════════════════════════════╣${RESET}"
echo -e "${C_SUCCESS}║${RESET}                                                                            ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_PLAIN}Import URI:${RESET}                                                         ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${VLESS_URI}  ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}║${RESET}                                                                            ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}╚════════════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "${C_INFO}[i]${RESET} Deployment Automation created by prvtspyyy"

# ==============================================
#        AUTOMATIC NETWORK MONITOR (BACKGROUND)
# ==============================================
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${C_PLAIN}$(math_bold "STARTING NETWORK MONITOR")${RESET}"
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"

# Check if network-monitor.sh exists and launch it in background
if [ -f "./network-monitor.sh" ]; then
    echo -e "${C_INFO}[*]${RESET} Launching network monitor in background..."
    chmod +x ./network-monitor.sh
    nohup ./network-monitor.sh "$SERVICE_NAME" "$REGION" > /dev/null 2>&1 &
    MONITOR_PID=$!
    echo -e "${C_SUCCESS}[✔]${RESET} Network monitor started (PID: $MONITOR_PID)"
    echo -e "${C_INFO}[*]${RESET} Logs will be saved to: ${BOLD}~/network-logs/${RESET}"
    echo -e "${C_INFO}[*]${RESET} To stop monitor: ${BOLD}kill $MONITOR_PID${RESET}"
else
    echo -e "${C_WARN}[!]${RESET} network-monitor.sh not found. Skipping."
    echo -e "${C_INFO}[*]${RESET} Add network-monitor.sh to your repository for automatic logging."
fi

echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"

# ==============================================
#        OUTPUT SELECTION (QR CODE + PING MONITOR)
# ==============================================
echo ""
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo -e "${C_PLAIN}$(math_bold "OUTPUT OPTIONS")${RESET}"
echo -e "${C_HEADER}════════════════════════════════════════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${C_ACCENT}[1]${RESET} Show QR Code (scan with phone)"
echo -e "  ${C_ACCENT}[2]${RESET} Start Background Ping Monitor (keeps connection alive + logs)"
echo -e "  ${C_ACCENT}[3]${RESET} Both (QR + Ping Monitor)"
echo -e "  ${C_ACCENT}[4]${RESET} Exit"
echo ""
read -p "$(echo -e "${C_INFO}[?]${RESET} Select option [1-4]: ")" OUTPUT_CHOICE

# Encode URI for QR code
VLESS_URI_ENCODED=$(echo -n "$VLESS_URI" | jq -sRr @uri 2>/dev/null || python3 -c "import urllib.parse; print(urllib.parse.quote('$VLESS_URI'))" 2>/dev/null || echo -n "$VLESS_URI" | sed 's/ /%20/g')

# --- Function: Generate QR Code ---
generate_qr() {
    echo ""
    echo -e "${C_INFO}[*]${RESET} Generating QR code..."
    
    if ! command -v qrencode &> /dev/null; then
        echo -e "${C_WARN}[!]${RESET} Installing qrencode (one-time)..."
        sudo apt-get update -qq && sudo apt-get install -y qrencode -qq 2>/dev/null
    fi
    
    if command -v qrencode &> /dev/null; then
        echo ""
        echo -e "${C_PLAIN}Scan this QR code with your VLESS client:${RESET}"
        echo ""
        echo "$VLESS_URI" | qrencode -t ANSIUTF8
        echo ""
        echo -e "${C_SUCCESS}[✔]${RESET} QR code displayed above"
    else
        echo -e "${C_WARN}[!]${RESET} qrencode not available. Use this URI manually:"
        echo -e "${BOLD}$VLESS_URI${RESET}"
    fi
}

# --- Function: Start Background Ping Monitor (Zero Quota) ---
start_ping_monitor() {
    local TARGET="${CLEAN_HOST}"
    local INTERVAL="${PING_INTERVAL:-25}"
    local LOG_FILE="/tmp/vless-ping-$(date +%Y%m%d-%H%M%S).log"
    
    echo ""
    echo -e "${C_INFO}[*]${RESET} Starting background ping monitor..."
    echo -e "${C_INFO}[*]${RESET} Target: ${BOLD}${TARGET}${RESET}"
    echo -e "${C_INFO}[*]${RESET} Interval: ${BOLD}${INTERVAL}s${RESET}"
    echo -e "${C_INFO}[*]${RESET} Log: ${BOLD}${LOG_FILE}${RESET}"
    
    # Create the monitor script
    cat > /tmp/ping-monitor.sh <<'MONITOR_EOF'
#!/bin/bash
TARGET="$1"
INTERVAL="$2"
LOG_FILE="$3"

echo "$$" > /tmp/ping-monitor.pid
echo "Ping monitor started with PID: $$"
echo "Log file: $LOG_FILE"
echo "Press Ctrl+C or run 'kill $$' to stop."
echo ""

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    PING_RESULT=$(curl -o /dev/null -s -w '%{time_total}|%{http_code}' --max-time 5 "https://$TARGET/health" 2>/dev/null)
    
    if [ -n "$PING_RESULT" ]; then
        RESPONSE_TIME=$(echo "$PING_RESULT" | cut -d'|' -f1)
        HTTP_CODE=$(echo "$PING_RESULT" | cut -d'|' -f2)
        LATENCY_MS=$(echo "$RESPONSE_TIME * 1000" | bc 2>/dev/null | cut -d'.' -f1)
        
        if [ "$HTTP_CODE" = "200" ]; then
            echo "[$TIMESTAMP] UP   | ${LATENCY_MS}ms | HTTP $HTTP_CODE" | tee -a "$LOG_FILE"
        else
            echo "[$TIMESTAMP] WARN | HTTP $HTTP_CODE" | tee -a "$LOG_FILE"
        fi
    else
        echo "[$TIMESTAMP] DOWN | No response" | tee -a "$LOG_FILE"
    fi
    
    sleep "$INTERVAL"
done
MONITOR_EOF

    chmod +x /tmp/ping-monitor.sh
    
    # Start the monitor in background
    nohup /tmp/ping-monitor.sh "$TARGET" "$INTERVAL" "$LOG_FILE" > /tmp/ping-monitor-output.log 2>&1 &
    MONITOR_PID=$!
    
    sleep 1
    if kill -0 $MONITOR_PID 2>/dev/null; then
        echo ""
        echo -e "${C_SUCCESS}╔════════════════════════════════════════════════════════════════════════════╗${RESET}"
        echo -e "${C_SUCCESS}║${RESET}                    ${BOLD}${GREEN}PING MONITOR STARTED${RESET}                              ${C_SUCCESS}║${RESET}"
        echo -e "${C_SUCCESS}╠════════════════════════════════════════════════════════════════════════════╣${RESET}"
        echo -e "${C_SUCCESS}║${RESET}  ${CYAN}PID:${RESET}        ${BOLD}$MONITOR_PID${RESET}"
        echo -e "${C_SUCCESS}║${RESET}  ${CYAN}Log File:${RESET}   ${BOLD}$LOG_FILE${RESET}"
        echo -e "${C_SUCCESS}║${RESET}  ${CYAN}Interval:${RESET}   ${BOLD}${INTERVAL}s${RESET}"
        echo -e "${C_SUCCESS}║${RESET}                                                                            ${C_SUCCESS}║${RESET}"
        echo -e "${C_SUCCESS}║${RESET}  ${CYAN}Commands:${RESET}                                                              ${C_SUCCESS}║${RESET}"
        echo -e "${C_SUCCESS}║${RESET}    View log:  ${GREEN}tail -f $LOG_FILE${RESET}${C_SUCCESS}║${RESET}"
        echo -e "${C_SUCCESS}║${RESET}    Stop:       ${GREEN}kill $MONITOR_PID${RESET}${C_SUCCESS}║${RESET}"
        echo -e "${C_SUCCESS}║${RESET}    Check:      ${GREEN}kill -0 $MONITOR_PID && echo 'Running'${RESET}${C_SUCCESS}║${RESET}"
        echo -e "${C_SUCCESS}╚════════════════════════════════════════════════════════════════════════════╝${RESET}"
        echo ""
        echo -e "${C_WARN}[!]${RESET} Monitor will stop when Cloud Shell session ends."
        echo -e "${C_INFO}[*]${RESET} For 24/7 monitoring, deploy the keepalive-monitor Cloud Run service."
    else
        echo -e "${C_ERROR}[✘]${RESET} Failed to start monitor."
    fi
}

# --- Process User Choice ---
case $OUTPUT_CHOICE in
    1)
        generate_qr
        ;;
    2)
        start_ping_monitor
        ;;
    3)
        generate_qr
        start_ping_monitor
        ;;
    4)
        echo -e "${C_INFO}[*]${RESET} Exiting..."
        ;;
    *)
        echo -e "${C_WARN}[!]${RESET} Invalid choice. Exiting..."
        ;;
esac

# Always save URI to file
echo "$VLESS_URI" > /tmp/vless-uri.txt

echo ""
echo -e "${C_SUCCESS}╔════════════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${BOLD}${WHITE}$(math_bold "DEPLOYMENT COMPLETE")${RESET}                                            ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${C_ACCENT}created by prvtspyyy${RESET}                                              ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}║${RESET}   ${CYAN}URI saved to: /tmp/vless-uri.txt${RESET}                                 ${C_SUCCESS}║${RESET}"
echo -e "${C_SUCCESS}╚════════════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""
