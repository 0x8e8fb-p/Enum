#!/usr/bin/env bash
# =============================================================================
# x91.sh — CTF Enumeration Script (HTB / THM / OSCP)
# =============================================================================
# Usage: ./x91.sh -t <target_ip> [options]
# Requires: nmap, nc, curl, nuclei, feroxbuster/gobuster, enum4linux,
#           netexec/crackmapexec, ldapsearch, kerbrute (optional)
# =============================================================================

# Safer error handling — no 'set -e' to prevent silent exits in subshells/pipes
set -uo pipefail

# ─────────────────────────── COLORS & SYMBOLS ─────────────────────────────────
RED='\033[0;31m';    LRED='\033[1;31m'
GREEN='\033[0;32m';  LGREEN='\033[1;32m'
YELLOW='\033[1;33m'; CYAN='\033[0;36m'
BLUE='\033[0;34m';   MAGENTA='\033[0;35m'
WHITE='\033[1;37m';  GREY='\033[0;37m'
NC='\033[0m'         # No Colour

SYM_OK="${LGREEN}[+]${NC}"
SYM_INFO="${CYAN}[*]${NC}"
SYM_WARN="${YELLOW}[!]${NC}"
SYM_ERR="${LRED}[-]${NC}"
SYM_ARROW="${BLUE}[>]${NC}"

# ──────────────────────────── GLOBAL DEFAULTS ─────────────────────────────────
TARGET=""
OUTPUT_DIR="./x91_output"
WORDLIST_USERS="/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
WORDLIST_WEB="/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
NMAP_RATE="10000"
CMD_TIMEOUT=30          # seconds per individual helper command
NMAP_TIMEOUT=1800       # seconds for nmap full -p- scan (30 min; TCP-connect is slow over VPN)
SKIP_NUCLEI=false
SKIP_FEROX=false
VERBOSE=false
REPORT_FILE=""
OPEN_PORTS=""
OPEN_PORTS_CSV=""
START_TIME=$(date +%s)

# Trap: clean up on exit or interrupt
cleanup() {
    local code=$?
    echo -e "\n${SYM_WARN} Script interrupted or finished (exit code: ${code}). Partial results saved to ${OUTPUT_DIR}/"
    # Kill any background jobs spawned by this script
    jobs -p | xargs -r kill 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ──────────────────────────── HELPERS ─────────────────────────────────────────

banner() {
    echo -e "${MAGENTA}"
    cat << 'EOF'
 ___  ___ ___ _ ___| |   ___| |__
 \ \/ / _ \_  / / __| |  / __| '_ \
  >  <  __// /| \__ \ | _\__ \ | | |
 /_/\_\___/___|_|___/_(_)___/_| |_|
EOF
    echo -e "${GREY}  CTF Enumeration Engine — HTB / THM / OSCP${NC}"
    echo -e "${GREY}  $(date '+%Y-%m-%d %H:%M:%S')${NC}\n"
}

log()  { echo -e "${SYM_INFO} ${WHITE}$*${NC}";                         }
ok()   { echo -e "${SYM_OK}  $*";                                        }
warn() { echo -e "${SYM_WARN} ${YELLOW}$*${NC}";                         }
err()  { echo -e "${SYM_ERR}  ${LRED}$*${NC}" >&2;                       }
arrow(){ echo -e "${SYM_ARROW} ${CYAN}$*${NC}";                          }
sep()  { echo -e "${GREY}──────────────────────────────────────────────${NC}"; }

# Write to report file (strip ANSI for cleaner file output)
rpt() {
    if [[ -n "$REPORT_FILE" ]]; then
        echo "$*" | sed 's/\x1b\[[0-9;]*m//g' >> "$REPORT_FILE"
    fi
}

section() {
    local title="$1"
    echo ""
    echo -e "${MAGENTA}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${MAGENTA}║${WHITE}  ${title}${MAGENTA}${NC}"
    echo -e "${MAGENTA}╚══════════════════════════════════════════════╝${NC}"
    rpt ""
    rpt "=== ${title} ==="
}

# Run a command with a timeout; log output; never hard-exit on failure
run_cmd() {
    local desc="$1"; shift
    local tout="${CMD_TIMEOUT}"
    # Optional: first arg can be --timeout=N
    if [[ "$1" == --timeout=* ]]; then
        tout="${1#*=}"; shift
    fi
    local outfile="${OUTPUT_DIR}/cmd_$(echo "$desc" | tr ' /' '__').txt"
    arrow "Running: ${GREY}$*${NC}"
    rpt "CMD: $*"
    if timeout "${tout}" bash -c "$*" > "$outfile" 2>&1; then
        ok "${desc} — done"
    else
        local rc=$?
        if [[ $rc -eq 124 ]]; then
            warn "${desc} — TIMED OUT after ${tout}s (partial output kept)"
        else
            warn "${desc} — returned exit code ${rc}"
        fi
    fi
    if $VERBOSE; then cat "$outfile"; fi
    rpt "$(cat "$outfile")"
    echo "$outfile"   # Return path for callers
}

# Check if a tool is available
need() {
    command -v "$1" &>/dev/null
}

tool_check() {
    local tool="$1"; local pkg="${2:-$1}"
    if need "$tool"; then
        ok "Found: ${LGREEN}${tool}${NC}"
    else
        warn "Missing: ${YELLOW}${tool}${NC} — install with: ${GREY}apt install ${pkg}${NC}"
    fi
}

# Elapsed time since START_TIME
calc_duration() {
    local end=$(date +%s)
    local diff=$(( end - START_TIME ))
    printf "%dm %ds" $(( diff / 60 )) $(( diff % 60 ))
}

# ASCII progress bar — call with integer 0-100
draw_progress_bar() {
    local pct="${1:-0}" width=50
    local filled=$(( width * pct / 100 ))
    local empty=$(( width - filled ))
    local bar=$(printf "%${filled}s" | tr ' ' '█')
    local space=$(printf "%${empty}s" | tr ' ' '░')
    printf "\r${BLUE}[%s%s] %3d%%${NC}" "$bar" "$space" "$pct"
}

# Run a command; user can press 's' at any time to skip it
# Returns 0 on success, 1 on skip or failure
run_with_skip() {
    local cmd="$1"
    local desc="${2:-command}"
    log "${desc} ${GREY}(press 's' to skip)${NC}"
    bash -c "$cmd" &
    local pid=$!
    while kill -0 "$pid" 2>/dev/null; do
        if read -t 1 -N 1 -s key 2>/dev/null; then
            if [[ "$key" == "s" || "$key" == "S" ]]; then
                echo ""
                warn "Skipping: ${desc}"
                kill -9 "$pid" 2>/dev/null
                wait "$pid" 2>/dev/null
                return 1
            fi
        fi
    done
    wait "$pid"
    return $?
}

# Warn (not exit) if not root — some nmap features need it
check_root() {
    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root — some nmap features may be limited. Try: ${WHITE}sudo $0 $*${NC}"
    else
        ok "Running as root"
    fi
}

# Open a new terminal window running a command.
# Falls back to background process if no display or no emulator found.
spawn_terminal() {
    local title="$1"; shift
    local cmd="$*"
    local logfile="${OUTPUT_DIR}/${title// /_}.log"

    # Headless / no display — always background
    if [[ -z "${DISPLAY:-}" ]]; then
        warn "No \$DISPLAY — running '${title}' in background → ${CYAN}${logfile}${NC}"
        bash -c "$cmd" > "$logfile" 2>&1 &
        disown 2>/dev/null || true
        return
    fi

    # Try emulators in preference order
    local terms=(
        x-terminal-emulator
        mate-terminal gnome-terminal xfce4-terminal
        terminator tilix kitty alacritty konsole xterm
    )
    local spawned=0
    for t in "${terms[@]}"; do
        need "$t" || continue
        case "$t" in
            gnome-terminal|xfce4-terminal|terminator|mate-terminal|tilix)
                "$t" --title="$title" -- bash -c "$cmd; echo '[DONE] Press Enter to close'; read" \
                    >/dev/null 2>&1 & spawned=1 ;;
            konsole)
                "$t" --title "$title" -e bash -c "$cmd; echo '[DONE] Press Enter to close'; read" \
                    >/dev/null 2>&1 & spawned=1 ;;
            kitty|alacritty)
                "$t" --title "$title" bash -c "$cmd; echo '[DONE] Press Enter to close'; read" \
                    >/dev/null 2>&1 & spawned=1 ;;
            xterm|x-terminal-emulator)
                "$t" -title "$title" -e bash -c "$cmd; echo '[DONE] Press Enter to close'; read" \
                    >/dev/null 2>&1 & spawned=1 ;;
        esac
        [[ $spawned -eq 1 ]] && break
    done

    if [[ $spawned -eq 0 ]]; then
        warn "No graphical terminal found — running '${title}' in background → ${CYAN}${logfile}${NC}"
        bash -c "$cmd" > "$logfile" 2>&1 &
    fi
    disown 2>/dev/null || true
}

# ──────────────────────────── USAGE ───────────────────────────────────────────

usage() {
    cat << EOF
${WHITE}Usage:${NC}
  ./x91.sh -t <target_ip> [options]

${WHITE}Required:${NC}
  -t, --target <ip>       Target IP address

${WHITE}Options:${NC}
  -o, --output <dir>      Output directory (default: ./x91_output)
  -w, --wordlist <path>   Web content wordlist for feroxbuster/gobuster
  -u, --users <path>      Username wordlist for kerbrute
  -r, --rate <int>        nmap --min-rate (default: 3000)
      --skip-nuclei       Skip nuclei vulnerability scan
      --skip-ferox        Skip feroxbuster directory bruteforce
      --nmap-timeout <s>  Timeout for full nmap -p- scan in seconds (default: 1800)
  -v, --verbose           Print raw command output to console
  -h, --help              Show this help

${YELLOW}NOTE:${NC} Some nmap flags (-O) require sudo. Re-run with sudo if OS detection fails.

${WHITE}Examples:${NC}
  ./x91.sh -t 10.10.11.23
  sudo ./x91.sh -t 10.10.11.23 --rate 5000 -o ./loot
EOF
    exit 0
}

# ─────────────────────────── ARGUMENT PARSING ─────────────────────────────────

parse_args() {
    [[ $# -eq 0 ]] && usage

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -t|--target)    TARGET="$2";      shift 2 ;;
            -o|--output)    OUTPUT_DIR="$2";  shift 2 ;;
            -w|--wordlist)  WORDLIST_WEB="$2"; shift 2 ;;
            -u|--users)     WORDLIST_USERS="$2"; shift 2 ;;
            -r|--rate)      NMAP_RATE="$2";   shift 2 ;;
            --skip-nuclei)  SKIP_NUCLEI=true; shift   ;;
            --skip-ferox)   SKIP_FEROX=true;  shift   ;;
            --nmap-timeout) NMAP_TIMEOUT="$2"; shift 2 ;;
            -v|--verbose)   VERBOSE=true;     shift   ;;
            -h|--help)      usage ;;
            *) err "Unknown argument: $1"; usage ;;
        esac
    done

    [[ -z "$TARGET" ]] && { err "No target specified. Use -t <ip>"; exit 1; }

    # Validate basic IP/hostname format
    if ! echo "$TARGET" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$|^[a-zA-Z0-9._-]+$'; then
        err "Target '$TARGET' looks malformed. Please check."; exit 1
    fi
}

# ──────────────────────────── SETUP ───────────────────────────────────────────

setup_env() {
    mkdir -p "$OUTPUT_DIR"
    REPORT_FILE="${OUTPUT_DIR}/report_${TARGET//./_}.txt"
    : > "$REPORT_FILE"    # Truncate/create

    log "Target       : ${LGREEN}${TARGET}${NC}"
    log "Output dir   : ${CYAN}${OUTPUT_DIR}${NC}"
    log "Nmap rate    : ${CYAN}${NMAP_RATE}${NC}"
    log "Nmap timeout : ${CYAN}${NMAP_TIMEOUT}s${NC} (full -p- scan; adjust with --nmap-timeout)"
    log "Report file  : ${CYAN}${REPORT_FILE}${NC}"
    sep
    check_root

    echo "x91.sh Report — $(date)" >> "$REPORT_FILE"
    echo "Target: $TARGET"         >> "$REPORT_FILE"
    echo ""                        >> "$REPORT_FILE"

    # Tool availability check
    section "TOOL AVAILABILITY CHECK"
    for t in nmap nc curl; do tool_check "$t"; done
    tool_check nuclei   nuclei
    tool_check feroxbuster feroxbuster
    tool_check gobuster gobuster
    tool_check enum4linux enum4linux
    tool_check netexec  netexec
    tool_check crackmapexec crackmapexec
    tool_check ldapsearch ldap-utils
    tool_check kerbrute kerbrute
}

# ──────────────────────────── PHASE 1 — RECON ─────────────────────────────────

phase1_recon() {
    section "PHASE 1 — RECON"

    # ── Ping & TTL ──────────────────────────────────────────────────────────
    log "Ping check + TTL extraction…"
    local ping_out
    ping_out=$(timeout 5 ping -c 1 -W 2 "$TARGET" 2>/dev/null || true)

    if echo "$ping_out" | grep -q "bytes from"; then
        ok "Host is ${LGREEN}UP${NC} (ICMP)"
        local ttl
        ttl=$(echo "$ping_out" | grep -oP 'ttl=\K[0-9]+' || echo "unknown")
        arrow "TTL: ${WHITE}${ttl}${NC}"
        rpt "ICMP: UP | TTL: $ttl"

        # OS guess from TTL
        local os_guess="Unknown"
        if   [[ "$ttl" -le 64  && "$ttl" -gt 0   ]]; then os_guess="Linux/Unix (TTL≤64)"
        elif [[ "$ttl" -le 128 && "$ttl" -gt 64  ]]; then os_guess="Windows (TTL≤128)"
        elif [[ "$ttl" -le 255 && "$ttl" -gt 128 ]]; then os_guess="Cisco/Solaris (TTL≤255)"
        fi
        arrow "OS Guess (TTL heuristic): ${WHITE}${os_guess}${NC}"
        rpt "OS Guess: $os_guess"
    else
        warn "Host is DOWN or blocking ICMP — continuing anyway"
        rpt "ICMP: DOWN or filtered"
    fi
}

# ──────────────────────────── PHASE 2 — SCAN ──────────────────────────────────

phase2_scan() {
    section "PHASE 2 — SCAN & SERVICE ENUMERATION"

    # ── Quick pre-scan: top-1000 ports (fast feedback) ───────────────────────
    log "Quick scan: top-1000 ports for immediate feedback…"
    local nmap_quick="${OUTPUT_DIR}/nmap_quick"
    local nmap_quick_err="${OUTPUT_DIR}/nmap_quick.err"
    arrow "nmap -sV -F --min-rate ${NMAP_RATE} --open ${TARGET}"

    timeout 120 nmap -sV -F --min-rate "$NMAP_RATE" --open "$TARGET" \
        -oA "$nmap_quick" > /dev/null 2>"$nmap_quick_err"
    local quick_rc=$?

    if [[ $quick_rc -ne 0 ]]; then
        warn "Quick scan returned exit code ${quick_rc}"
        if [[ -s "$nmap_quick_err" ]]; then
            err "nmap stderr:"; cat "$nmap_quick_err" | while read -r l; do echo -e "  ${LRED}${l}${NC}"; done
        fi
        [[ $quick_rc -eq 1 ]] && warn "Exit code 1 → try re-running with ${WHITE}sudo${NC}"
    fi

    local quick_ports=""
    if [[ -f "${nmap_quick}.gnmap" ]]; then
        quick_ports=$(grep -oE "[0-9]+/open/tcp" "${nmap_quick}.gnmap" \
            | cut -d'/' -f1 | sort -un | paste -sd ',' || true)
    fi

    if [[ -n "$quick_ports" ]]; then
        ok "Quick scan found ports: ${LGREEN}${quick_ports}${NC}"
        grep -E "^PORT|^[0-9]+/tcp" "${nmap_quick}.nmap" 2>/dev/null \
            | while read -r line; do echo -e "  ${GREY}${line}${NC}"; done
    else
        warn "Quick scan found no open ports (continuing to full scan)"
    fi

    # ── Step A: Full -p- scan with live progress bar ──────────────────────────
    log "Step A: Full -p- scan (timeout: ${NMAP_TIMEOUT}s)…"
    local nmap_a="${OUTPUT_DIR}/nmap_full"
    local nmap_a_err="${OUTPUT_DIR}/nmap_full.err"
    arrow "nmap -sV -p- --min-rate ${NMAP_RATE} --open --stats-every 1s ${TARGET}"
    echo -e "${GREY}  Live progress below. Press 's' + Enter to skip to Script Scan.${NC}"
    echo ""

    # Pipe nmap stdout through progress-bar parser; -oA writes files independently
    nmap -sV -p- --min-rate "$NMAP_RATE" --open --stats-every 1s "$TARGET" \
        -oA "$nmap_a" 2>"$nmap_a_err" | while IFS= read -r line; do
        if [[ "$line" =~ About\ ([0-9]+)[.]?[0-9]*%\ done ]]; then
            draw_progress_bar "${BASH_REMATCH[1]}"
        elif [[ "$line" =~ Discovered\ open\ port\ ([0-9]+)/tcp ]]; then
            printf "\r\033[K"
            ok "Discovered port: ${LGREEN}${BASH_REMATCH[1]}/tcp${NC}"
        elif [[ "$line" =~ Nmap\ done ]]; then
            printf "\r\033[K"; draw_progress_bar 100; echo ""
        fi
    done &
    local nmap_pid=$!

    local elapsed=0
    while kill -0 "$nmap_pid" 2>/dev/null; do
        if read -t 1 -N 1 -s key 2>/dev/null; then
            if [[ "$key" == "s" || "$key" == "S" ]]; then
                echo ""
                warn "Skipping full scan — using quick-scan ports as fallback"
                kill -9 "$nmap_pid" 2>/dev/null
                wait "$nmap_pid" 2>/dev/null
                OPEN_PORTS_CSV="${quick_ports:-}"
                break
            fi
        fi
        elapsed=$(( elapsed + 1 ))
        if [[ $elapsed -ge $NMAP_TIMEOUT ]]; then
            echo ""
            warn "nmap -p- TIMED OUT after ${NMAP_TIMEOUT}s — try --nmap-timeout 3600"
            kill -9 "$nmap_pid" 2>/dev/null
            wait "$nmap_pid" 2>/dev/null
            OPEN_PORTS_CSV="${quick_ports:-}"
            break
        fi
    done
    wait "$nmap_pid" 2>/dev/null || true

    # Show nmap stderr if it contains anything actionable
    if [[ -s "$nmap_a_err" ]]; then
        local err_content; err_content=$(cat "$nmap_a_err")
        if echo "$err_content" | grep -qiE 'error|failed|warning|requires'; then
            err "nmap stderr output:"
            echo "$err_content" | while read -r l; do echo -e "  ${LRED}${l}${NC}"; done
            echo "$err_content" | grep -qi 'requires root\|requires privileges' \
                && warn "Privilege error → re-run with ${WHITE}sudo${NC}"
        fi
    fi

    # Extract ports from .gnmap (most reliable nmap output format)
    if [[ -z "${OPEN_PORTS_CSV:-}" ]] && [[ -f "${nmap_a}.gnmap" ]]; then
        OPEN_PORTS_CSV=$(grep -oE "[0-9]+/open/tcp" "${nmap_a}.gnmap" \
            | cut -d'/' -f1 | sort -un | paste -sd ',' || true)
    fi
    [[ -z "${OPEN_PORTS_CSV:-}" ]] && OPEN_PORTS_CSV="${quick_ports:-}"

    if [[ -z "${OPEN_PORTS_CSV:-}" ]]; then
        warn "No open ports found — check connectivity / VPN / try sudo"
        if [[ -s "$nmap_a_err" ]]; then
            warn "Exit code 1 — most common causes:"
            arrow "Missing raw socket permissions → ${WHITE}sudo ./x91.sh -t ${TARGET}${NC}"
            arrow "Target unreachable / VPN not connected"
            arrow "nmap not in PATH → which nmap"
        fi
        rpt "Open ports: NONE"
        return
    fi

    ok "Open ports: ${LGREEN}${OPEN_PORTS_CSV}${NC}"
    rpt "Open ports: $OPEN_PORTS_CSV"
    echo "$OPEN_PORTS_CSV" > "${OUTPUT_DIR}/open_ports.txt"

    arrow "Service overview:"
    if [[ -f "${nmap_a}.nmap" ]]; then
        grep -E "^PORT|^[0-9]+/tcp" "${nmap_a}.nmap" 2>/dev/null | while read -r line; do
            echo -e "  ${GREY}${line}${NC}"
            rpt "  $line"
        done
    fi

    # ── Step B: Full -p- + NSE scripts with live progress bar ────────────────
    log "Step B: Full -p- + NSE scripts (-sC)  ${GREY}(press 's' + Enter to skip)${NC}…"
    local nmap_b="${OUTPUT_DIR}/nmap_scripts"
    local nmap_b_err="${OUTPUT_DIR}/nmap_scripts.err"
    arrow "nmap -sV -p- --min-rate ${NMAP_RATE} -sC --open --stats-every 1s ${TARGET}"
    echo ""

    nmap -sV -p- --min-rate "$NMAP_RATE" -sC --open --stats-every 1s "$TARGET" \
        -oA "$nmap_b" 2>"$nmap_b_err" | while IFS= read -r line; do
        if [[ "$line" =~ About\ ([0-9]+)[.]?[0-9]*%\ done ]]; then
            draw_progress_bar "${BASH_REMATCH[1]}"
        elif [[ "$line" =~ Discovered\ open\ port\ ([0-9]+)/tcp ]]; then
            printf "\r\033[K"
            ok "Discovered port: ${LGREEN}${BASH_REMATCH[1]}/tcp${NC}"
        elif [[ "$line" =~ Nmap\ done ]]; then
            printf "\r\033[K"; draw_progress_bar 100; echo ""
        fi
    done &
    local nmap_b_pid=$!

    elapsed=0
    while kill -0 "$nmap_b_pid" 2>/dev/null; do
        if read -t 1 -N 1 -s key 2>/dev/null; then
            if [[ "$key" == "s" || "$key" == "S" ]]; then
                echo ""
                warn "Skipping script scan"
                kill -9 "$nmap_b_pid" 2>/dev/null
                wait "$nmap_b_pid" 2>/dev/null
                break
            fi
        fi
        elapsed=$(( elapsed + 1 ))
        if [[ $elapsed -ge 300 ]]; then
            echo ""
            warn "Script scan timed out (300s)"
            kill -9 "$nmap_b_pid" 2>/dev/null
            break
        fi
    done
    wait "$nmap_b_pid" 2>/dev/null || true

    if [[ -s "$nmap_b_err" ]]; then
        grep -iE 'error|failed' "$nmap_b_err" \
            | while read -r l; do echo -e "  ${LRED}${l}${NC}"; done || true
    fi

    if [[ -f "${nmap_b}.nmap" ]]; then
        ok "Script scan complete → ${CYAN}${nmap_b}.nmap${NC}"
        grep -v '^#\|^$\|^Starting\|^Nmap done' "${nmap_b}.nmap" | while read -r line; do
            echo -e "  ${GREY}${line}${NC}"
        done
        rpt "$(cat "${nmap_b}.nmap")"
    fi
}

# ──────────────────────────── PORT PRESENCE CHECK ─────────────────────────────

port_open() {
    local port="$1"
    echo "$OPEN_PORTS_CSV" | tr ',' '\n' | grep -qx "$port"
}

# ──────────────────────────── PHASE 3 — TARGETED ENUM ─────────────────────────

phase3_enum() {
    section "PHASE 3 — TARGETED ENUMERATION"

    # ── Unknown / tcpwrapped ─────────────────────────────────────────────────
    log "Checking for unknown/tcpwrapped services…"
    local mystery_ports
    mystery_ports=$(grep -E 'tcpwrapped|unknown' "${OUTPUT_DIR}/nmap_full.txt" 2>/dev/null \
        | awk '{print $1}' | cut -d'/' -f1 || true)

    if [[ -n "$mystery_ports" ]]; then
        warn "Suspicious ports (tcpwrapped/unknown): ${YELLOW}${mystery_ports}${NC}"
        rpt "Suspicious ports: $mystery_ports"
        while read -r p; do
            [[ -z "$p" ]] && continue
            log "Banner grabbing port ${p} with nc…"
            local nc_out
            nc_out=$(echo '' | timeout 5 nc -nv "$TARGET" "$p" 2>&1 || true)
            arrow "nc → port ${p}: ${GREY}${nc_out}${NC}"
            rpt "nc port $p: $nc_out"

            log "Banner grabbing port ${p} with telnet…"
            local tel_out
            tel_out=$(echo '' | timeout 5 telnet "$TARGET" "$p" 2>&1 || true)
            arrow "telnet → port ${p}: ${GREY}${tel_out}${NC}"
            rpt "telnet port $p: $tel_out"
        done <<< "$mystery_ports"
    else
        log "No tcpwrapped/unknown ports found"
    fi

    # ── HTTP (80) ────────────────────────────────────────────────────────────
    if port_open 80; then
        enum_http "http" 80
    fi

    # ── HTTPS (443) ──────────────────────────────────────────────────────────
    if port_open 443; then
        enum_http "https" 443
    fi

    # ── HTTP alt ports ───────────────────────────────────────────────────────
    for alt_port in 8080 8443 8000 8888 9090 3000 5000; do
        if port_open "$alt_port"; then
            local scheme="http"
            [[ $alt_port == 8443 || $alt_port == 443 ]] && scheme="https"
            enum_http "$scheme" "$alt_port"
        fi
    done

    # ── SMB (445 / 139) ──────────────────────────────────────────────────────
    if port_open 445 || port_open 139; then
        enum_smb
    fi

    # ── Active Directory ─────────────────────────────────────────────────────
    if port_open 88 || port_open 389 || port_open 5985; then
        enum_ad
    fi

    # ── SSH (22) ─────────────────────────────────────────────────────────────
    if port_open 22; then
        enum_ssh
    fi

    # ── Databases ────────────────────────────────────────────────────────────
    if port_open 3306; then enum_mysql;    fi
    if port_open 5432; then enum_postgres; fi
    if port_open 6379; then enum_redis;    fi
    if port_open 1433; then enum_mssql;    fi
    if port_open 27017; then enum_mongo;   fi

    # ── FTP (21) ─────────────────────────────────────────────────────────────
    if port_open 21; then enum_ftp; fi

    # ── SMTP (25 / 587 / 465) ────────────────────────────────────────────────
    if port_open 25 || port_open 587 || port_open 465; then enum_smtp; fi
}

# ──────────────────────────── HTTP ENUM ───────────────────────────────────────

enum_http() {
    local scheme="$1" port="$2"
    local base_url="${scheme}://${TARGET}:${port}"

    section "HTTP ENUM — ${base_url}"

    # curl headers
    log "Fetching HTTP headers…"
    local headers
    headers=$(timeout "$CMD_TIMEOUT" curl -skI --max-time 10 "$base_url" 2>/dev/null || true)
    if [[ -n "$headers" ]]; then
        ok "Headers received:"
        echo "$headers" | while read -r line; do
            echo -e "  ${GREY}${line}${NC}"
        done
        rpt "Headers:\n$headers"
    else
        warn "No headers returned from ${base_url}"
    fi

    # Page title
    local title
    title=$(timeout "$CMD_TIMEOUT" curl -skL --max-time 15 "$base_url" 2>/dev/null \
        | grep -oiP '(?<=<title>)[^<]+' | head -1 || true)
    [[ -n "$title" ]] && arrow "Page title: ${WHITE}${title}${NC}"
    rpt "Page title: $title"

    # robots.txt
    log "Checking robots.txt…"
    local robots
    robots=$(timeout 10 curl -sk --max-time 10 "${base_url}/robots.txt" 2>/dev/null || true)
    if echo "$robots" | grep -qi 'disallow\|allow\|sitemap'; then
        ok "robots.txt content:"
        echo "$robots" | head -30 | while read -r line; do echo -e "  ${GREY}${line}${NC}"; done
        rpt "robots.txt:\n$robots"
    fi

    # nuclei
    if ! $SKIP_NUCLEI && need nuclei; then
        log "Running nuclei on ${base_url}…"
        local nout="${OUTPUT_DIR}/nuclei_${port}.txt"
        local ncmd="nuclei -u '$base_url' -o '$nout' -silent -c 50 -bs 25 -timeout 5 2>/dev/null"
        run_with_skip "$ncmd" "nuclei on ${base_url}" \
            || warn "nuclei skipped or returned non-zero"
        local hits; hits=$(wc -l < "$nout" 2>/dev/null || echo 0)
        ok "nuclei: ${hits} finding(s) → ${CYAN}${nout}${NC}"
        rpt "nuclei findings: $(cat "$nout" 2>/dev/null)"
    elif $SKIP_NUCLEI; then
        warn "nuclei: SKIPPED (--skip-nuclei)"
    else
        warn "nuclei not installed — skipping"
    fi

    # Directory brute-force (new terminal window to avoid blocking)
    if ! $SKIP_FEROX; then
        local wl="$WORDLIST_WEB"
        local fout="${OUTPUT_DIR}/ferox_${port}.txt"
        if need feroxbuster; then
            log "Spawning feroxbuster on ${base_url} (new window)…"
            local cmd="feroxbuster -u '${base_url}' -w '${wl}' -o '${fout}' --no-state -k 2>&1"
            spawn_terminal "feroxbuster-${port}" "$cmd"
            ok "feroxbuster spawned — output: ${CYAN}${fout}${NC}"
        elif need gobuster; then
            log "Spawning gobuster on ${base_url} (new window)…"
            local cmd="gobuster dir -u '${base_url}' -w '${wl}' -o '${fout}' -k 2>&1"
            spawn_terminal "gobuster-${port}" "$cmd"
            ok "gobuster spawned — output: ${CYAN}${fout}${NC}"
        else
            warn "Neither feroxbuster nor gobuster found — skipping directory bruteforce"
        fi
    else
        warn "Directory brute-force: SKIPPED (--skip-ferox)"
    fi
}

# ──────────────────────────── SMB ENUM ────────────────────────────────────────

enum_smb() {
    section "SMB ENUM — Port 445/139"

    # enum4linux
    if need enum4linux; then
        log "Running enum4linux -a…"
        local el_out="${OUTPUT_DIR}/enum4linux.txt"
        run_with_skip "timeout 120 enum4linux -a '$TARGET' > '$el_out' 2>&1" \
            "enum4linux -a (120s max)" \
            || warn "enum4linux skipped or returned non-zero (common)"
        ok "enum4linux → ${CYAN}${el_out}${NC}"
        rpt "$(cat "$el_out" 2>/dev/null | head -100)"
    else
        warn "enum4linux not found"
    fi

    # netexec / crackmapexec
    local nxc_bin=""
    need netexec     && nxc_bin="netexec"
    need crackmapexec && nxc_bin="crackmapexec"
    if [[ -n "$nxc_bin" ]]; then
        log "Running ${nxc_bin} smb…"
        local nxc_out="${OUTPUT_DIR}/nxc_smb.txt"
        timeout 30 "$nxc_bin" smb "$TARGET" > "$nxc_out" 2>&1 \
            || warn "${nxc_bin} smb returned non-zero"
        ok "${nxc_bin} smb → ${CYAN}${nxc_out}${NC}"
        cat "$nxc_out" | while read -r line; do echo -e "  ${GREY}${line}${NC}"; done
        rpt "$(cat "$nxc_out" 2>/dev/null)"

        # Try null session share enumeration
        log "Trying null-session share list…"
        local share_out="${OUTPUT_DIR}/nxc_shares.txt"
        timeout 30 "$nxc_bin" smb "$TARGET" -u '' -p '' --shares > "$share_out" 2>&1 \
            || warn "Null session share enum failed (expected if not allowed)"
        cat "$share_out" | while read -r line; do echo -e "  ${GREY}${line}${NC}"; done
        rpt "$(cat "$share_out" 2>/dev/null)"
    else
        warn "netexec / crackmapexec not found — install: apt install netexec"
        # Fallback: nmap smb scripts
        log "Falling back to nmap SMB scripts…"
        run_cmd "nmap-smb-scripts" --timeout=60 \
            "nmap -p 445 --script 'smb-enum-shares,smb-enum-users,smb-os-discovery' ${TARGET}"
    fi
}

# ──────────────────────────── ACTIVE DIRECTORY ENUM ──────────────────────────

enum_ad() {
    section "ACTIVE DIRECTORY ENUM"

    # Domain info from netexec/cme
    local nxc_bin=""
    need netexec      && nxc_bin="netexec"
    need crackmapexec && nxc_bin="crackmapexec"
    if [[ -n "$nxc_bin" ]]; then
        log "Getting domain info via ${nxc_bin}…"
        local dc_out="${OUTPUT_DIR}/nxc_dc.txt"
        timeout 30 "$nxc_bin" smb "$TARGET" > "$dc_out" 2>&1 || true
        local domain
        domain=$(grep -oP 'domain:\K[^\s)]+' "$dc_out" 2>/dev/null \
            | head -1 || grep -oP '(?<=Domain:)[^\s]+' "$dc_out" | head -1 || echo "")
        [[ -n "$domain" ]] && ok "Domain: ${LGREEN}${domain}${NC}" || warn "Could not extract domain name"
        rpt "Domain info: $(cat "$dc_out" 2>/dev/null)"
    fi

    # LDAP anonymous bind check
    if port_open 389 && need ldapsearch; then
        log "Attempting LDAP anonymous bind for naming contexts…"
        local ldap_out="${OUTPUT_DIR}/ldap_namingctx.txt"
        timeout 20 ldapsearch -x -H "ldap://${TARGET}" \
            -s base namingContexts > "$ldap_out" 2>&1 \
            || warn "LDAP anonymous bind may have been refused"
        if grep -qi 'namingContexts' "$ldap_out" 2>/dev/null; then
            ok "LDAP naming contexts:"
            grep -i 'namingContexts' "$ldap_out" | while read -r l; do
                echo -e "  ${GREY}${l}${NC}"
            done
            rpt "$(cat "$ldap_out")"

            # Attempt full base DN dump
            local base_dn
            base_dn=$(grep -oP '(?<=: )DC=[^,].*' "$ldap_out" | head -1 || echo "")
            if [[ -n "$base_dn" ]]; then
                log "Attempting anonymous LDAP dump for ${base_dn}…"
                local ldap_dump="${OUTPUT_DIR}/ldap_dump.txt"
                timeout 60 ldapsearch -x -H "ldap://${TARGET}" \
                    -b "$base_dn" > "$ldap_dump" 2>&1 \
                    || warn "LDAP dump may be partial"
                ok "LDAP dump → ${CYAN}${ldap_dump}${NC}"
            fi
        else
            warn "LDAP anonymous bind denied or no naming contexts returned"
        fi
    fi

    # WinRM probe
    if port_open 5985; then
        arrow "Port 5985 (WinRM) is OPEN — try: evil-winrm -i ${TARGET} -u <user> -p <pass>"
        rpt "WinRM (5985): OPEN"
    fi

    # Kerberos — kerbrute user enum
    if port_open 88 && need kerbrute; then
        if [[ -f "$WORDLIST_USERS" ]]; then
            log "Running kerbrute userenum…"
            local kbu_out="${OUTPUT_DIR}/kerbrute_users.txt"
            timeout 120 kerbrute userenum --dc "$TARGET" \
                -d "${domain:-DOMAIN}" "$WORDLIST_USERS" \
                -o "$kbu_out" 2>/dev/null || warn "kerbrute returned non-zero"
            ok "kerbrute users → ${CYAN}${kbu_out}${NC}"
            rpt "$(cat "$kbu_out" 2>/dev/null | head -50)"
        else
            warn "kerbrute: user wordlist not found (${WORDLIST_USERS})"
        fi
    elif port_open 88 && ! need kerbrute; then
        warn "Port 88 (Kerberos) open — install kerbrute for user enumeration"
    fi

    # AS-REP Roasting hint
    if port_open 88; then
        arrow "Kerberos open → check AS-REP Roasting: GetNPUsers.py -dc-ip ${TARGET} <domain>/"
    fi
}

# ──────────────────────────── SSH ENUM ────────────────────────────────────────

enum_ssh() {
    section "SSH ENUM — Port 22"
    log "SSH banner grab via nc…"
    local ssh_banner
    ssh_banner=$(timeout 5 bash -c "echo '' | nc -nv ${TARGET} 22 2>&1" || true)
    arrow "Banner: ${GREY}${ssh_banner}${NC}"
    rpt "SSH banner: $ssh_banner"

    # nmap ssh version / hostkey
    run_cmd "nmap-ssh-hostkey" --timeout=30 \
        "nmap -p 22 --script ssh-hostkey,ssh2-enum-algos ${TARGET}"
}

# ──────────────────────────── DATABASE ENUM ───────────────────────────────────

enum_mysql() {
    section "MYSQL ENUM — Port 3306"
    log "Attempting MySQL anonymous banner probe…"
    local banner
    banner=$(echo '' | timeout 5 nc -nv "$TARGET" 3306 2>&1 | strings | head -5 || true)
    arrow "MySQL banner: ${GREY}${banner}${NC}"
    rpt "MySQL banner: $banner"
    run_cmd "nmap-mysql" --timeout=30 \
        "nmap -p 3306 --script mysql-info,mysql-empty-password ${TARGET}"
}

enum_postgres() {
    section "POSTGRES ENUM — Port 5432"
    run_cmd "nmap-postgres" --timeout=30 \
        "nmap -p 5432 --script pgsql-brute --script-args userdb=/dev/null ${TARGET}"
    if need psql; then
        log "Trying postgres anonymous connect…"
        timeout 5 psql -h "$TARGET" -U postgres -c '\l' 2>&1 \
            | tee "${OUTPUT_DIR}/postgres_probe.txt" || true
    fi
}

enum_redis() {
    section "REDIS ENUM — Port 6379"
    log "Probing Redis (unauthenticated)…"
    local redis_out
    redis_out=$(echo -e "PING\r\nINFO server\r\nCONFIG GET *\r\n" \
        | timeout 5 nc -nv "$TARGET" 6379 2>&1 || true)
    echo "$redis_out" | head -30 | while read -r l; do echo -e "  ${GREY}${l}${NC}"; done
    rpt "Redis probe: $redis_out"
}

enum_mssql() {
    section "MSSQL ENUM — Port 1433"
    run_cmd "nmap-mssql" --timeout=30 \
        "nmap -p 1433 --script ms-sql-info,ms-sql-empty-password ${TARGET}"
}

enum_mongo() {
    section "MONGODB ENUM — Port 27017"
    run_cmd "nmap-mongo" --timeout=30 \
        "nmap -p 27017 --script mongodb-info ${TARGET}"
}

# ──────────────────────────── FTP ENUM ────────────────────────────────────────

enum_ftp() {
    section "FTP ENUM — Port 21"
    log "FTP banner grab…"
    local ftp_banner
    ftp_banner=$(echo '' | timeout 5 nc -nv "$TARGET" 21 2>&1 | head -5 || true)
    arrow "Banner: ${GREY}${ftp_banner}${NC}"
    rpt "FTP banner: $ftp_banner"

    log "Checking FTP anonymous login…"
    local anon_out
    anon_out=$(timeout 10 bash -c "
        {
            sleep 1; echo 'USER anonymous'; sleep 1
            echo 'PASS x@x.com'; sleep 1
            echo 'LIST'; sleep 2; echo 'QUIT'
        } | nc -nv ${TARGET} 21 2>&1" || true)
    if echo "$anon_out" | grep -qi '230\|Login successful'; then
        ok "${LGREEN}Anonymous FTP login SUCCESSFUL!${NC}"
        rpt "FTP anonymous: SUCCESS\n$anon_out"
    else
        warn "Anonymous FTP login failed (likely expected)"
    fi
    arrow "Try: ftp ${TARGET}  →  anonymous / anonymous"
}

# ──────────────────────────── SMTP ENUM ───────────────────────────────────────

enum_smtp() {
    section "SMTP ENUM — Port 25/587/465"
    for sp in 25 587 465; do
        port_open "$sp" || continue
        log "SMTP banner on port ${sp}…"
        local smtp_banner
        smtp_banner=$(echo '' | timeout 5 nc -nv "$TARGET" "$sp" 2>&1 | head -3 || true)
        arrow "Port ${sp}: ${GREY}${smtp_banner}${NC}"
        rpt "SMTP ($sp): $smtp_banner"
    done
    run_cmd "nmap-smtp" --timeout=30 \
        "nmap -p 25,587,465 --script smtp-commands,smtp-open-relay,smtp-enum-users ${TARGET}"
}

# ──────────────────────────── PHASE 4 — REPORT ────────────────────────────────

phase4_report() {
    section "PHASE 4 — FINAL REPORT"

    echo ""
    echo -e "${WHITE}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${WHITE}║              x91.sh  SCAN COMPLETE                      ║${NC}"
    echo -e "${WHITE}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log "Target       : ${LGREEN}${TARGET}${NC}"
    log "Open ports   : ${LGREEN}${OPEN_PORTS_CSV:-none detected}${NC}"
    log "Output dir   : ${CYAN}${OUTPUT_DIR}${NC}"
    log "Report file  : ${CYAN}${REPORT_FILE}${NC}"
    log "Elapsed time : ${CYAN}$(calc_duration)${NC}"
    echo ""

    # Summary table of files generated
    echo -e "${YELLOW}Generated files:${NC}"
    find "$OUTPUT_DIR" -maxdepth 1 -type f | sort | while read -r f; do
        local sz; sz=$(wc -c < "$f" 2>/dev/null || echo 0)
        printf "  ${GREY}%-45s${NC} %s bytes\n" "$(basename "$f")" "$sz"
    done
    echo ""

    # Reminder hints
    echo -e "${YELLOW}Next steps & quick wins:${NC}"
    port_open 21   && arrow "FTP anon login: ftp ${TARGET}"
    port_open 22   && arrow "SSH: ssh -o StrictHostKeyChecking=no user@${TARGET}"
    port_open 80   && arrow "HTTP: firefox http://${TARGET} | curl -skL http://${TARGET}"
    port_open 443  && arrow "HTTPS: firefox https://${TARGET}"
    port_open 139  || port_open 445 && arrow "SMB: smbclient -L //${TARGET}/ -N"
    port_open 389  && arrow "LDAP: ldapsearch -x -H ldap://${TARGET} -s base"
    port_open 88   && arrow "Kerberos: GetNPUsers.py, Rubeus, or kerbrute"
    port_open 5985 && arrow "WinRM: evil-winrm -i ${TARGET} -u <user> -p <pass>"
    port_open 3306 && arrow "MySQL: mysql -h ${TARGET} -u root --password=''"
    port_open 5432 && arrow "Postgres: psql -h ${TARGET} -U postgres"
    port_open 6379 && arrow "Redis: redis-cli -h ${TARGET}"
    echo ""

    rpt "=== SCAN COMPLETE ==="
    rpt "Timestamp: $(date)"
    ok "Done. Happy hacking!"
}

# ──────────────────────────── MAIN ────────────────────────────────────────────

main() {
    banner
    parse_args "$@"
    setup_env
    phase1_recon
    phase2_scan
    phase3_enum
    phase4_report
}

main "$@"