#!/usr/bin/env bash
# Developer Machine Security Check
# Reads only — does not modify, delete, or quarantine anything.
# Run from Terminal. Share the full output with Security Engineering.

set -euo pipefail

# Load nvm if present, so npm is available without requiring the developer
# to source it manually before running the script
[ -s "$HOME/.nvm/nvm.sh" ] && source "$HOME/.nvm/nvm.sh"

# Write output to both terminal and a file on the Desktop
output_file="$HOME/Desktop/dev-security-check-$(hostname -s)-$(date +%Y%m%d-%H%M%S).txt"
exec > >(tee "$output_file") 2>&1

PASS="\033[32m[PASS]\033[0m"
WARN="\033[33m[WARN]\033[0m"
FLAG="\033[31m[FLAG]\033[0m"
INFO="\033[36m[INFO]\033[0m"
SECTION="\033[1m"
RESET="\033[0m"

flags_found=0

flag() { echo -e "$FLAG $1"; flags_found=$((flags_found + 1)); }
pass() { echo -e "$PASS $1"; }
warn() { echo -e "$WARN $1"; }
info() { echo -e "$INFO $1"; }
section() { echo ""; echo -e "${SECTION}--- $1 ---${RESET}"; }

echo ""
echo "========================================"
echo " Developer Machine Security Check"
echo " $(date)"
echo "========================================"

# ---------------------------------------------------------------------------
section "Developer app integrity (Antigravity, Cursor, Discord, GitHub Desktop)"
# ---------------------------------------------------------------------------
VOID_MARKERS="C250617A|C250618A|C250619A|C250620A"

check_app_integrity() {
  local app_path="$1"
  local app_name="$2"
  local expected_team="${3:-}"
  [ -d "$app_path" ] || return 0

  local infected=false
  info "$app_name found — running integrity checks"

  # Hidden .node_modules injection folder
  hidden_mods=$(find "$app_path" -name ".node_modules" -type d 2>/dev/null)
  if [ -n "$hidden_mods" ]; then
    flag "$app_name: hidden .node_modules injection folder found:"
    echo "$hidden_mods" | while read -r p; do echo " $p"; done
    infected=true
  fi

  # Known attacker version markers
  markers=$(grep -rl -E "$VOID_MARKERS" "$app_path" 2>/dev/null | head -5 || true)
  if [ -n "$markers" ]; then
    flag "$app_name: attacker injection markers found:"
    echo "$markers" | while read -r f; do echo " $f"; done
    infected=true
  fi

  # JS/asar files modified after install — outside node_modules only
  if [ -f "$app_path/Contents/Info.plist" ]; then
    modified=$(find "$app_path" \
      \( -name "*.js" -o -name "*.asar" \) \
      -newer "$app_path/Contents/Info.plist" \
      ! -path "*/node_modules/*" \
      ! -path "*/CachedData/*" ! -path "*/Cache/*" ! -path "*/logs/*" \
      2>/dev/null | head -10 || true)
    if [ -n "$modified" ]; then
      flag "$app_name: non-bundled files modified after install — possible tampering:"
      echo "$modified" | while read -r f; do echo " $f"; done
      infected=true
    fi
  fi

  # Code signing
  if command -v codesign &>/dev/null; then
    local sig_info team_id identifier
    sig_info=$(codesign -dv "$app_path" 2>&1)
    team_id=$(echo "$sig_info" | grep "TeamIdentifier" | awk -F= '{print $2}' | tr -d ' ')
    identifier=$(echo "$sig_info" | grep "^Identifier=" | head -1 | awk -F= '{print $2}')
    if [ -z "$team_id" ] || [ "$team_id" = "not set" ]; then
      flag "$app_name: app is unsigned — unexpected for a legitimate release"
      infected=true
    elif [ -n "$expected_team" ] && [ "$team_id" != "$expected_team" ]; then
      flag "$app_name: signing TeamID mismatch — expected $expected_team, got $team_id"
      infected=true
    else
      info "$app_name: signed — Identifier=$identifier TeamID=$team_id"
    fi
  fi

  [ "$infected" = false ] && pass "$app_name: all integrity checks passed"
}

# Known-good Team IDs: EQHXZ8M8AV = Google LLC, VEKTX9H2N7 = GitHub Inc
check_app_integrity "/Applications/Antigravity.app" "Antigravity" "EQHXZ8M8AV"
check_app_integrity "$HOME/Applications/Antigravity.app" "Antigravity (user)" "EQHXZ8M8AV"
check_app_integrity "/Applications/Cursor.app" "Cursor" ""
check_app_integrity "$HOME/Applications/Cursor.app" "Cursor (user)" ""
check_app_integrity "/Applications/Discord.app" "Discord" ""
check_app_integrity "/Applications/GitHub Desktop.app" "GitHub Desktop" "VEKTX9H2N7"

_any_app=false
for _p in "/Applications/Antigravity.app" "$HOME/Applications/Antigravity.app" \
          "/Applications/Cursor.app" "$HOME/Applications/Cursor.app" \
          "/Applications/Discord.app" "/Applications/GitHub Desktop.app"; do
  [ -d "$_p" ] && _any_app=true && break
done
[ "$_any_app" = false ] && pass "None of the targeted developer apps installed"

# ---------------------------------------------------------------------------
section "VS Code and Cursor — suspicious config files"
# ---------------------------------------------------------------------------

_vscode_clean=true
if [ -d "$HOME/.vscode" ]; then
  suspicious=$(find "$HOME/.vscode" -name "*.js" ! -path "*/extensions/*" 2>/dev/null || true)
  if [ -n "$suspicious" ]; then
    flag "Unexpected JS files in ~/.vscode (known backdoor location):"
    echo "$suspicious" | while read -r f; do echo " $f"; done
    _vscode_clean=false
  fi
fi
[ "$_vscode_clean" = true ] && pass "No unexpected JS files in ~/.vscode"

if [ -d "$HOME/.cursor" ]; then
  suspicious=$(find "$HOME/.cursor" -name "*.js" ! -path "*/extensions/*" 2>/dev/null || true)
  if [ -n "$suspicious" ]; then
    flag "Unexpected JS files in ~/.cursor (Cursor IDE — same vector as VS Code):"
    echo "$suspicious" | while read -r f; do echo " $f"; done
  else
    pass "No unexpected JS files in ~/.cursor"
  fi
fi

# ---------------------------------------------------------------------------
section "Known dropper and payload files"
# ---------------------------------------------------------------------------

known_paths=(
  "$HOME/.npl"
  "/tmp/.x"
  "/tmp/.x/m"
  "$HOME/.local/bin/node"
)

dropper_found=false
for p in "${known_paths[@]}"; do
  if [ -e "$p" ]; then
    flag "Known malicious file/directory found: $p"
    dropper_found=true
  fi
done
[ "$dropper_found" = false ] && pass "No known dropper/payload files found at fixed locations"

known_hashes=(
  "6beef02785bc2271b5fdba55f19df5756c9f6ea408ee481739741699a05580cf:Python dropper"
  "a45751fbfe88440bebff63cd44814e4ed6deb642bc3e3c4a14c4f8ae0ed9e019:PostCSS malware binary"
  "73943a7f31ce0f98bd0530b324f8c6e1dc6bd004dc31887ea2c0175bba994107:Malicious node npm binary"
  "298a9e830ed52f36c299427565485d717d1ce0179c0597cc16560513eb780b06:Emrah Python payload"
)

hash_check_paths=("$HOME/.npl" "/tmp/.x/m" "$HOME/.local/bin/node" "$HOME/Downloads")

hash_found=false
for hash_entry in "${known_hashes[@]}"; do
  hash="${hash_entry%%:*}"
  label="${hash_entry#*:}"
  for search_path in "${hash_check_paths[@]}"; do
    [ -e "$search_path" ] || continue
    match=$(find "$search_path" -type f 2>/dev/null | xargs shasum -a 256 2>/dev/null | grep "^$hash" || true)
    if [ -n "$match" ]; then
      flag "Malicious file detected ($label): $match"
      hash_found=true
    fi
  done
done
[ "$hash_found" = false ] && pass "No known malicious file hashes found in checked locations"

# ---------------------------------------------------------------------------
section "macOS Launch Agents (persistence)"
# ---------------------------------------------------------------------------

la_dir="$HOME/Library/LaunchAgents"
if [ -d "$la_dir" ]; then
  plists=$(find "$la_dir" -name "*.plist" 2>/dev/null)
  if [ -n "$plists" ]; then
    while IFS= read -r plist; do
      if grep -qE "(\.npl|/tmp/\.|Antigravity|python3? -c|curl.*sh\b|wget.*sh\b)" "$plist" 2>/dev/null; then
        flag "Suspicious Launch Agent content: $plist"
        grep -E "(\.npl|/tmp/\.|Antigravity|python3? -c|curl.*sh\b|wget.*sh\b)" "$plist" | \
        while read -r line; do echo " $line"; done
      else
        info "Launch Agent (review if unfamiliar): $plist"
      fi
    done <<< "$plists"
  else
    pass "No Launch Agents found"
  fi
else
  pass "No Launch Agents directory"
fi

if [ -d "/Library/LaunchDaemons" ]; then
  info "System Launch Daemons present — run with sudo to inspect if needed"
fi

# ---------------------------------------------------------------------------
section "Crontab"
# ---------------------------------------------------------------------------

cron=$(crontab -l 2>/dev/null || true)
if [ -n "$cron" ]; then
  warn "Crontab entries found — review for anything unexpected:"
  echo "$cron" | while read -r line; do echo " $line"; done
else
  pass "No crontab entries"
fi

# ---------------------------------------------------------------------------
section "npm — global packages"
# ---------------------------------------------------------------------------

NPM_CMD=""
if command -v npm &>/dev/null; then
  NPM_CMD="npm"
else
  for candidate in \
    "$HOME/.nvm/versions/node/$(ls "$HOME/.nvm/versions/node/" 2>/dev/null | sort -V | tail -1)/bin/npm" \
    /usr/local/bin/npm /opt/homebrew/bin/npm /usr/bin/npm; do
    [ -x "$candidate" ] && NPM_CMD="$candidate" && break
  done
fi

if [ -n "$NPM_CMD" ]; then
  info "Installed global npm packages (review for anything unexpected):"
  "$NPM_CMD" list -g --depth=0 2>/dev/null | tail -n +2 | while read -r line; do echo " $line"; done
else
  warn "npm not found in PATH — skipping npm checks (run manually: npm list -g --depth=0)"
fi

# ---------------------------------------------------------------------------
section "npm — cache check for malicious packages"
# ---------------------------------------------------------------------------

if [ -n "$NPM_CMD" ]; then
  npm_cache=$("$NPM_CMD" config get cache 2>/dev/null || echo "")
  if [ -n "$npm_cache" ] && [ -d "$npm_cache" ]; then
    malicious_cached=false
    for pkg in "node-18.20.3" "node-bin-setup"; do
      if find "$npm_cache" -name "${pkg}*" 2>/dev/null | grep -q .; then
        flag "Malicious package '$pkg' found in npm cache — run: npm cache clean --force"
        malicious_cached=true
      fi
    done
    [ "$malicious_cached" = false ] && pass "No known malicious packages in npm cache"
  else
    info "npm cache directory not found"
  fi
else
  info "npm not available — skipping cache check"
fi

# ---------------------------------------------------------------------------
section "Local project repos — infected config file scan"
# ---------------------------------------------------------------------------

ioc_pattern="global[._V.]=|global\.i='5-3-134'|createRequire.*import\.meta\.url.*oWN|5-3-134|api\.trongrid\.io|fullnode\.mainnet\.aptoslabs|oWN\(5586\)"
dev_dirs=("$HOME/dev" "$HOME/projects" "$HOME/work" "$HOME/code")
scanned=false

for dev_dir in "${dev_dirs[@]}"; do
  [ -d "$dev_dir" ] || continue
  scanned=true
  info "Scanning $dev_dir for infected config files..."
  infected=$(grep -rl \
    --include="postcss.config.mjs" \
    --include="postcss.config.js" \
    --include="tailwind.config.js" \
    --include="tailwind.config.ts" \
    --include="server.js" \
    -E "$ioc_pattern" \
    "$dev_dir" 2>/dev/null || true)
  if [ -n "$infected" ]; then
    flag "Infected config files found — delete these repos and re-clone from GitHub:"
    echo "$infected" | while read -r f; do echo " $f"; done
  else
    pass "No infected config files found in $dev_dir"
  fi
done

[ "$scanned" = false ] && info "No standard dev directories found (~/dev, ~/projects, ~/work, ~/code)"

# ---------------------------------------------------------------------------
section "Network — active connections to known C2 addresses"
# ---------------------------------------------------------------------------

c2_ips=("166.88.4.2" "23.27.20.143" "67.203.7.205" "52.221.58.173" "18.139.165.181")
c2_domains=("api.trongrid.io" "fullnode.mainnet.aptoslabs.com" "bsc-dataseed.binance.org")

conn_found=false
for ip in "${c2_ips[@]}"; do
  if netstat -an 2>/dev/null | grep -q "$ip"; then
    flag "Active connection to known C2 IP: $ip — isolate this machine immediately"
    conn_found=true
  fi
done

for domain in "${c2_domains[@]}"; do
  if dscacheutil -q host -a name "$domain" 2>/dev/null | grep -q "ip_address"; then
    warn "Recent DNS resolution of C2 domain: $domain (may be cached from earlier activity)"
  fi
done

[ "$conn_found" = false ] && pass "No active connections to known C2 IPs"

# ---------------------------------------------------------------------------
echo ""
echo "========================================"
if [ $flags_found -gt 0 ]; then
  echo -e "${FLAG} $flags_found issue(s) flagged. Do NOT commit to any repo."
  echo ""
  echo " Send this full output to Security Engineering before continuing."
else
  echo -e "${PASS} No issues flagged."
  echo ""
  echo " Still complete the remaining checklist steps:"
  echo " 1. Run: npm cache clean --force"
  echo " 2. Rotate your GitHub tokens and SSH keys (instructions to follow)"
  echo " Note: re-cloning repos is only required if this script flagged infected config files — it did not."
fi
echo ""
echo " Results saved to: $output_file"
echo " Please share this file with Security Engineering."
echo "========================================"
echo ""
