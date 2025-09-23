#!/bin/bash
# filepath: mcp-config-deployment.sh

set -e

# Configuration variables
MCP_PROXY_URL="${MCP_PROXY_URL:-https://your-mcp-url/mcp}"
HTTP_PROXY_URL="${HTTP_PROXY_URL:-http://your-proxy-server:80}"
HTTPS_PROXY_URL="${HTTPS_PROXY_URL:-http://your-proxy-server:80}"
NO_PROXY_DOMAINS="${NO_PROXY_DOMAINS:-localhost,127.0.0.1,10.*,192.168.*,172.16.*,172.17.*,172.18.*,172.19.*,172.20.*,172.21.*,172.22.*,172.23.*,172.24.*,172.25.*,172.26.*,172.27.*,172.28.*,172.29.*,172.30.*,172.31.*}"

# Debug flag - set to true to enable debug logging
DEBUG_MODE=false

current_user=$(/usr/bin/stat -f %Su /dev/console)
HOME_DIR="/Users/$current_user"
SERVICE_DIR="$HOME_DIR/mcp-config"
LOGS_DIR="$SERVICE_DIR/logs"

mkdir -p $SERVICE_DIR && mkdir -p $LOGS_DIR

timestamp_date=$(date +%Y_%m_%d)
LOG_FILE="$LOGS_DIR/logfile_$timestamp_date.log"

# Output info log with timestamp
print_info_log(){
  if ! test -f "$LOG_FILE"; then
    touch $LOG_FILE
  fi
  local timestamp
  timestamp=$(date +%F\ %T)
  echo "$timestamp [INFO] $1" >> $LOG_FILE
}

# Output error log with timestamp
print_error_log(){
  local timestamp
  timestamp=$(date +%F\ %T)
  echo "$timestamp [ERROR] $1" >> $LOG_FILE
}

# Output debug log with timestamp (only if DEBUG_MODE is true)
print_debug_log(){
  if [[ "$DEBUG_MODE" == "true" ]]; then
    local timestamp
    timestamp=$(date +%F\ %T)
    echo "$timestamp [DEBUG] $1" >> $LOG_FILE
  fi
}

# Set Homebrew path
HOMEBREW_PATH="/opt/homebrew/bin"
# Check if Homebrew path exists
if [ -d "$HOMEBREW_PATH" ]; then
    PATH="$HOMEBREW_PATH:$PATH"
fi

update_file_ownership() {
  filePath=$1

  print_debug_log "Checking file ownership for file $filePath"

  # Only change ownership of files/directories in our service directory or Claude config files
  if [[ "$filePath" != "$SERVICE_DIR"* ]] && [[ "$filePath" != "$CLAUDE_MCP_PATH" ]] && [[ "$filePath" != "$CLAUDE_SETTINGS_PATH" ]] && [[ "$filePath" != "$(dirname "$CLAUDE_SETTINGS_PATH")" ]]; then
    print_debug_log "Skipping ownership change for $filePath (not in service directory or Claude configs)"
    return 0
  fi

  # Change ownership without -R to avoid recursive traversal that slows things down
  if [[ -e "$filePath" ]]; then
    sudo chown "$current_user" "$filePath"
    print_info_log "Changed ownership of $filePath to $current_user"
  fi
}

JQ_DEFAULT_PATH=$(sudo -u $current_user PATH="$PATH" command -v jq || echo "/usr/bin/jq")
JQ_VERSION=$(sudo -u $current_user PATH="$PATH" $JQ_DEFAULT_PATH --version | awk '{print $1}')
print_info_log "JQ version $JQ_VERSION is installed."

# https://github.com/microsoft/playwright-mcp#configuration-file

# Template with comments for user reference
PLAYWRIGHT_CONFIG_TEMPLATE=$( cat <<'EOF'
{
  // Browser configuration
  browser?: {
    // Browser type to use (chromium, firefox, or webkit)
    browserName?: 'chromium' | 'firefox' | 'webkit';

    // Keep the browser profile in memory, do not save it to disk.
    isolated?: boolean;

    // Path to user data directory for browser profile persistence
    userDataDir?: string;

    // Browser launch options (see Playwright docs)
    // @see https://playwright.dev/docs/api/class-browsertype#browser-type-launch
    launchOptions?: {
      channel?: string;        // Browser channel (e.g. 'chrome')
      headless?: boolean;      // Run in headless mode
      executablePath?: string; // Path to browser executable
      // ... other Playwright launch options
    };

    // Browser context options
    // @see https://playwright.dev/docs/api/class-browser#browser-new-context
    contextOptions?: {
      viewport?: { width: number, height: number };
      // ... other Playwright context options
    };

    // CDP endpoint for connecting to existing browser
    cdpEndpoint?: string;

    // Remote Playwright server endpoint
    remoteEndpoint?: string;
  },

  // Server configuration
  server?: {
    port?: number;  // Port to listen on
    host?: string;  // Host to bind to (default: localhost)
  },

  // List of additional capabilities
  capabilities?: Array<
    'tabs' |    // Tab management
    'install' | // Browser installation
    'pdf' |     // PDF generation
    'vision' |  // Coordinate-based interactions
  >;

  // Directory for output files
  outputDir?: string;

  // Network configuration
  network?: {
    // List of origins to allow the browser to request. Default is to allow all. Origins matching both `allowedOrigins` and `blockedOrigins` will be blocked.
    allowedOrigins?: string[];

    // List of origins to block the browser to request. Origins matching both `allowedOrigins` and `blockedOrigins` will be blocked.
    blockedOrigins?: string[];
  };

  /**
   * Whether to send image responses to the client. Can be "allow" or "omit".
   * Defaults to "allow".
   */
  imageResponses?: 'allow' | 'omit';
}
EOF
)

# Valid JSON version for processing - minimal working config
PLAYWRIGHT_MINIMAL_CONFIG_JSON=$( cat <<'EOF'
{
  "browser": {
    "browserName": "chromium",
    "headless": true
  },
  "capabilities": ["tabs"]
}
EOF
)

PLAYWRIGHT_CONFIG_DIR="$SERVICE_DIR/playwright"
PLAYWRIGHT_CUSTOM_CONFIG_DIR="$PLAYWRIGHT_CONFIG_DIR/custom_config"

mkdir -p $PLAYWRIGHT_CONFIG_DIR && mkdir -p $PLAYWRIGHT_CUSTOM_CONFIG_DIR
update_file_ownership "$PLAYWRIGHT_CUSTOM_CONFIG_DIR"

# Create template file with comments for users
playwright_template_config_path="$PLAYWRIGHT_CONFIG_DIR/template_with_comments.jsonc"
if ! test -f "$playwright_template_config_path"; then
  echo "$PLAYWRIGHT_CONFIG_TEMPLATE" > "$playwright_template_config_path"
  update_file_ownership "$playwright_template_config_path"
  print_info_log "Created Playwright template with comments at $playwright_template_config_path"
fi

# Create/update the actual JSON config file
playwright_default_config_path="$PLAYWRIGHT_CONFIG_DIR/config.json"
if ! test -f "$playwright_default_config_path"; then
  echo '{}' > "$playwright_default_config_path"
fi

current_playwright_default_config=$(jq '.' "$playwright_default_config_path")
desired_playwright_default_config=$(echo "$PLAYWRIGHT_MINIMAL_CONFIG_JSON" | jq '.')

comparison_result=$(jq --argjson a "$current_playwright_default_config" --argjson b "$desired_playwright_default_config" -n '$a == $b')
print_debug_log "Comparison result: $comparison_result"

if [[ "$comparison_result" == "true" ]]; then
  print_info_log "No change needed for $playwright_default_config_path"
else
  print_info_log "Adding playwright default config"
  echo "$PLAYWRIGHT_MINIMAL_CONFIG_JSON" | jq '.' > "$playwright_default_config_path"
  print_info_log "Updated Playwright config at $playwright_default_config_path"
  if ! test -f "$PLAYWRIGHT_CUSTOM_CONFIG_DIR/config.json"; then
    cp "$playwright_default_config_path" "$PLAYWRIGHT_CUSTOM_CONFIG_DIR/config.json"
    print_info_log "Updated Playwright config at $PLAYWRIGHT_CUSTOM_CONFIG_DIR/config.json"
  fi
fi

# Global setting paths
TOP_LEVEL_MCP_KEY_PATHS=()
VSCODE_MCP_PATH="$HOME_DIR/Library/Application Support/Code/User/mcp.json"
INTELLIJ_MCP_PATH="$HOME_DIR/.config/github-copilot/intellij/mcp.json"
CLAUDE_MCP_PATH="$HOME_DIR/.claude.json"
CLAUDE_SETTINGS_PATH="$HOME_DIR/.claude/settings.json"

# Define the mcp_config as a JSON string (direct format for mcp.json)
MCP_JSON=$( cat <<EOF
{
  "servers": {
    "mcp-proxy": {
      "type": "http",
      "url": "${MCP_PROXY_URL}"
    },
    "github": {
      "type": "http",
      "url": "https://api.githubcopilot.com/mcp"
    },
    "atlassian": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "https://mcp.atlassian.com/v1/sse"
      ],
      "type": "stdio"
    },
    "sentry": {
      "type": "http",
      "url": "https://mcp.sentry.dev/mcp"
    },
    "playwright": {
      "command": "npx",
      "args": [
        "@playwright/mcp",
        "--config",
        "${PLAYWRIGHT_CUSTOM_CONFIG_DIR}/config.json"
      ],
      "type": "stdio"
    }
  }
}
EOF
)

# Define the mcp_config as a JSON string (direct format for mcp.json)
MCP_INTELLIJ_JSON=$( cat <<EOF
{
  "servers": {
    "mcp-proxy": {
      "type": "http",
      "url": "${MCP_PROXY_URL}"
    },
    "github": {
      "type": "http",
      "url": "https://api.githubcopilot.com/mcp"
    }
  }
}
EOF
)

# Define the Claude MCP config (only user-scoped servers)
MCP_CLAUDE_JSON=$( cat <<EOF
{
  "mcpServers": {
    "mcp-proxy": {
      "type": "http",
      "url": "${MCP_PROXY_URL}"
    },
    "playwright": {
      "command": "npx",
      "args": [
        "-y",
        "@playwright/mcp",
        "--config",
        "${PLAYWRIGHT_CUSTOM_CONFIG_DIR}/config.json"
      ]
    },
    "atlassian": {
      "type": "sse",
      "url": "https://mcp.atlassian.com/v1/sse"
    },
    "sentry": {
      "type": "http",
      "url": "https://mcp.sentry.dev/mcp"
    },
    "figma": {
      "type": "http",
      "url": "http://127.0.0.1:3845/mcp"
    },
    "maestro": {
      "type": "stdio",
      "command": "maestro",
      "args": [
        "mcp"
      ]
    }
  }
}
EOF
)

# Define the Claude settings config for proxy and MCP server management
CLAUDE_SETTINGS_JSON=$( cat <<EOF
{
  "enabledMcpServers": [
    "mcp-proxy",
    "playwright",
    "atlassian",
    "sentry"
  ],
  "env": {
    "HTTP_PROXY": "${HTTP_PROXY_URL}",
    "HTTPS_PROXY": "${HTTPS_PROXY_URL}",
    "NO_PROXY": "${NO_PROXY_DOMAINS}"
  }
}
EOF
)

# Define the MCP settings config for top-level .mcp key (used for global settings files)
MCP_SETTINGS_JSON=$( cat <<EOF
{
  "mcp": ${MCP_JSON}
}
EOF
)

# Helper function to check if a path is in the global settings array
is_top_level_mcp_key_path() {
  local test_path="$1"
  for mcp_path in "${TOP_LEVEL_MCP_KEY_PATHS[@]}"; do
    if [[ "$test_path" == "$mcp_path" ]]; then
      return 0
    fi
  done
  return 1
}

# Helper function to determine if this is an mcp.json file or Claude config file (vs settings.json)
is_mcp_json_file() {
  local test_path="$1"
  if [[ "$test_path" == *"/mcp.json" ]] || [[ "$test_path" == "$CLAUDE_MCP_PATH" ]] || [[ "$test_path" == "$CLAUDE_SETTINGS_PATH" ]]; then
    return 0
  fi
  return 1
}

# Helper function to strip JSON comments (for JSONC files like IntelliJ generates)
strip_json_comments() {
  local file_path="$1"
  # Remove single-line comments (//) and multi-line comments (/* */)
  # This handles the basic cases that IntelliJ/Copilot generates
  sed -e 's|//.*$||g' -e '/\/\*/,/\*\//d' "$file_path" | \
  # Remove trailing commas before closing braces/brackets
  sed -e 's/,\([[:space:]]*[}\]].*\)/\1/g'
}

# Helper function to update Claude configuration
update_claude_config() {
  local file_path="$1"
  local desired_mcp_servers="$2"

  print_info_log "Updating Claude config at $file_path"

  # Read current config
  local current_config
  if current_config=$(jq '.' "$file_path" 2>/dev/null); then
    print_debug_log "Successfully parsed Claude config"
  else
    print_debug_log "Failed to parse Claude config, treating as empty"
    current_config='{}'
  fi

  # Extract desired mcpServers from the template
  local desired_servers=$(echo "$desired_mcp_servers" | jq '.mcpServers')

  # Update the configuration:
  # 1. Set global mcpServers at root level
  # 2. Remove any mcpServers from individual projects (purge project-specific servers)
  # 3. Keep all other project settings intact
  local updated_config=$(echo "$current_config" | jq --argjson servers "$desired_servers" '
    # Set the global mcpServers
    .mcpServers = $servers |
    # Remove mcpServers from all projects if they exist
    if .projects then
      .projects = (.projects | with_entries(.value |= del(.mcpServers)))
    else
      .
    end
  ')

  print_debug_log "Updated Claude config - set global mcpServers and purged project-specific mcpServers"
  echo "$updated_config" > "$file_path"
  return 0
}

update_claude_settings_config() {
  local file_path="$1"
  local desired_settings="$2"

  print_info_log "Updating Claude settings config at $file_path"

  # Read current config
  local current_config
  if current_config=$(jq '.' "$file_path" 2>/dev/null); then
    print_debug_log "Successfully parsed Claude settings config"
  else
    print_debug_log "Failed to parse Claude settings config, treating as empty"
    current_config='{}'
  fi

  # Extract desired settings components
  local desired_enabled_servers=$(echo "$desired_settings" | jq '.enabledMcpServers')
  local desired_env=$(echo "$desired_settings" | jq '.env')

  # Update the configuration:
  # 1. Set/update the enabledMcpServers
  # 2. Merge env settings (preserve existing keys, update/add our specific keys)
  # 3. Keep everything else intact
  local updated_config=$(echo "$current_config" | jq --argjson servers "$desired_enabled_servers" --argjson new_env "$desired_env" '
    # Set enabledMcpServers
    .enabledMcpServers = $servers |
    # Merge env settings - preserve existing keys, update/add our proxy keys
    .env = (.env // {}) + $new_env
  ')

  print_debug_log "Updated Claude settings config structure (merged env variables)"
  echo "$updated_config" > "$file_path"
  return 0
}

create_backup() {
  local file_path="$1"
  local app="$2"
  if [[ "$file_path" = "$HOME_DIR/Library/Application Support/Code/"* ]]; then
    app="vscode"
    file_name=$(echo "$file_path" | sed 's|.*Code/||' | sed 's|/|_|')
  elif [[ "$file_path" = "$HOME_DIR/.config/github-copilot/intellij/"* ]]; then
    app="intellij"
    file_name=$(echo "$file_path" | sed 's|.*intellij/||' | sed 's|/|_|')
  elif [[ "$file_path" = "$HOME_DIR/.claude.json" ]]; then
    app="claude"
    file_name="claude.json"
  elif [[ "$file_path" = "$HOME_DIR/.claude/settings.json" ]]; then
    app="claude"
    file_name="claude_settings.json"
  fi
  mkdir -p "$SERVICE_DIR/backups/$app"
  backup_path="${file_name}.$(date +%Y%m%d%H%M).bak"
  cp "$file_path" "$SERVICE_DIR/backups/$app/$backup_path"
  print_info_log "Backup of $file_path created at $SERVICE_DIR/backups/$app/$backup_path"
}

app_type() {
  local file_path="$1"
  if [[ "$file_path" = "$HOME_DIR/Library/Application Support/Code/"* ]]; then
    echo "vscode"
    return
  elif [[ "$file_path" = "$HOME_DIR/.config/github-copilot/intellij/"* ]]; then
    echo "intellij"
    return
  elif [[ "$file_path" = "$HOME_DIR/.claude.json" ]] || [[ "$file_path" = "$CLAUDE_SETTINGS_PATH" ]]; then
    echo "claude"
    return
  fi
  echo "other"
  return
}


# Find all .vscode/mcp.json files
find_vscode_mcp_paths() {
  VSCODE_MCP_PATHS+=$(find "$HOME_DIR/Library/Application Support/Code/" -type f -path "*/.vscode/mcp.json")
}

# Collect all paths (found + global)
MCP_PATHS=()
if [ -d "$HOME_DIR/Library/Application Support/Code/User" ]; then
  print_info_log "VS Code path found... Adding vscode paths"
  MCP_PATHS+=("$VSCODE_MCP_PATH")
  MCP_PATHS+=($(find_vscode_mcp_paths))
fi

# Add IntelliJ MCP path support
if [ -f "$INTELLIJ_MCP_PATH" ] || [ -d "$(dirname "$INTELLIJ_MCP_PATH")" ]; then
  print_info_log "IntelliJ GitHub Copilot path found or directory exists... Adding IntelliJ paths"
  MCP_PATHS+=("$INTELLIJ_MCP_PATH")
fi

# Add Claude MCP path support (user-scoped only)
if [ -f "$CLAUDE_MCP_PATH" ] || [ -d "$(dirname "$CLAUDE_MCP_PATH")" ]; then
  print_info_log "Claude path found or directory exists... Adding Claude paths"
  MCP_PATHS+=("$CLAUDE_MCP_PATH")
fi

# Add Claude settings path support
if [ -f "$CLAUDE_SETTINGS_PATH" ] || [ -d "$(dirname "$CLAUDE_SETTINGS_PATH")" ]; then
  print_info_log "Claude settings path found or directory exists... Adding Claude settings path"
  MCP_PATHS+=("$CLAUDE_SETTINGS_PATH")
fi

for mcp_path in "${MCP_PATHS[@]}"; do
  if [ ! -f "$mcp_path" ]; then
    # Create empty file if it's the global settings
    if is_top_level_mcp_key_path "$mcp_path"; then
      echo '{}' > "$mcp_path"
    elif [[ "$mcp_path" == "$VSCODE_MCP_PATH" ]]; then
      echo "$MCP_JSON" | jq '.' > "$mcp_path"
      print_info_log "Created VS Code MCP config file at $mcp_path"
    elif [[ "$mcp_path" == "$INTELLIJ_MCP_PATH" ]]; then
      # Create IntelliJ MCP config directory and file if needed
      mkdir -p "$(dirname "$mcp_path")"
      echo "$MCP_INTELLIJ_JSON" | jq '.' > "$mcp_path"
      print_info_log "Created IntelliJ MCP config file at $mcp_path"
    elif [[ "$mcp_path" == "$CLAUDE_MCP_PATH" ]]; then
      # Create Claude MCP config file if needed
      echo "$MCP_CLAUDE_JSON" | jq '.' > "$mcp_path"
      print_info_log "Created Claude MCP config file at $mcp_path"
    elif [[ "$mcp_path" == "$CLAUDE_SETTINGS_PATH" ]]; then
      # Create Claude settings config directory and file if needed
      mkdir -p "$(dirname "$mcp_path")"
      echo "$CLAUDE_SETTINGS_JSON" | jq '.' > "$mcp_path"
      print_info_log "Created Claude settings config file at $mcp_path"
    else
      continue
    fi
    # Update ownership for files we should manage (service directory and Claude configs)
    if [[ "$mcp_path" == "$SERVICE_DIR"* ]] || [[ "$mcp_path" == "$CLAUDE_MCP_PATH" ]] || [[ "$mcp_path" == "$CLAUDE_SETTINGS_PATH" ]]; then
      update_file_ownership "$(dirname "$mcp_path")"
      update_file_ownership "$mcp_path"
    fi
  fi

  # Backup
  app_type=$(app_type "$mcp_path")

  if is_mcp_json_file "$mcp_path"; then
    # This is an mcp.json file - compare directly with root keys
    # Try to parse with jq first, if it fails, strip comments and try again
    if current_config=$(jq '.' "$mcp_path" 2>/dev/null); then
      # Valid JSON, use as-is
      print_debug_log "File $mcp_path is valid JSON"
    else
      # Not valid JSON, likely has comments - strip them
      print_debug_log "File $mcp_path has comments, stripping them"
      current_config=$(strip_json_comments "$mcp_path" | jq '.')
    fi

    if [[ "$mcp_path" == "$INTELLIJ_MCP_PATH" ]]; then
      desired_mcp_content=$MCP_INTELLIJ_JSON
    elif [[ "$mcp_path" == "$CLAUDE_MCP_PATH" ]]; then
      desired_mcp_content=$MCP_CLAUDE_JSON
    elif [[ "$mcp_path" == "$CLAUDE_SETTINGS_PATH" ]]; then
      desired_mcp_content=$CLAUDE_SETTINGS_JSON
    else
  	  desired_mcp_content=$MCP_JSON
    fi

    desired_config=$(echo "$desired_mcp_content" | jq '.')

    print_info_log "Comparing configurations for $mcp_path"

    # Debug logging - handle different config structures
    if [[ "$mcp_path" == "$CLAUDE_SETTINGS_PATH" ]]; then
      print_debug_log "Current config enabledMcpServers: $(echo "$current_config" | jq '.enabledMcpServers // null')"
      print_debug_log "Desired config enabledMcpServers: $(echo "$desired_config" | jq '.enabledMcpServers // null')"
    elif [[ "$mcp_path" == "$CLAUDE_MCP_PATH" ]]; then
      print_debug_log "Current config servers: $(echo "$current_config" | jq '.mcpServers | keys // empty')"
      print_debug_log "Desired config servers: $(echo "$desired_config" | jq '.mcpServers | keys // empty')"
    else
      print_debug_log "Current config servers: $(echo "$current_config" | jq '.servers | keys // empty')"
      print_debug_log "Desired config servers: $(echo "$desired_config" | jq '.servers | keys // empty')"
    fi

    # Check playwright specifically (debug only)
    if [[ "$DEBUG_MODE" == "true" ]]; then
      if [[ "$mcp_path" == "$CLAUDE_MCP_PATH" ]]; then
        current_playwright=$(echo "$current_config" | jq '.mcpServers.playwright // null')
        desired_playwright=$(echo "$desired_config" | jq '.mcpServers.playwright // null')
      else
        current_playwright=$(echo "$current_config" | jq '.servers.playwright // null')
        desired_playwright=$(echo "$desired_config" | jq '.servers.playwright // null')
      fi
      print_debug_log "Current playwright config: $current_playwright"
      print_debug_log "Desired playwright config: $desired_playwright"
    fi

    # Debug the comparison
    if [[ "$mcp_path" == "$CLAUDE_MCP_PATH" ]]; then
      # For Claude MCP config, compare only the mcpServers section
      current_mcp_servers=$(echo "$current_config" | jq '.mcpServers // {}')
      desired_mcp_servers=$(echo "$desired_config" | jq '.mcpServers')
      comparison_result=$(jq --argjson a "$current_mcp_servers" --argjson b "$desired_mcp_servers" -n '$a == $b')
      print_debug_log "Claude MCP servers comparison result: $comparison_result"
    elif [[ "$mcp_path" == "$CLAUDE_SETTINGS_PATH" ]]; then
      # For Claude settings, compare the entire config
      comparison_result=$(jq --argjson a "$current_config" --argjson b "$desired_config" -n '$a == $b')
      print_debug_log "Claude settings comparison result: $comparison_result"
    else
      # For other configs, compare the entire config
      comparison_result=$(jq --argjson a "$current_config" --argjson b "$desired_config" -n '$a == $b')
      print_debug_log "Comparison result: $comparison_result"
    fi

    if [[ "$comparison_result" == "true" ]]; then
      print_info_log "No change needed for $mcp_path"
      continue
    fi
    create_backup "$mcp_path" "$app_type"

    # Handle Claude MCP config specially - preserve user settings, only update mcpServers
    if [[ "$mcp_path" == "$CLAUDE_MCP_PATH" ]]; then
      print_info_log "Updating Claude MCP config at $mcp_path"
      update_claude_config "$mcp_path" "$desired_mcp_content"
    elif [[ "$mcp_path" == "$CLAUDE_SETTINGS_PATH" ]]; then
      print_info_log "Updating Claude settings config at $mcp_path"
      update_claude_settings_config "$mcp_path" "$desired_mcp_content"
    else
      print_info_log "Adding mcp config directly to file at path $mcp_path"
      echo "$desired_mcp_content" | jq '.' > "$mcp_path"
    fi
  elif is_top_level_mcp_key_path "$mcp_path"; then
    # This is a settings.json file - compare .mcp key
    current_mcp=$(jq '.mcp' "$mcp_path")
    desired_mcp=$(echo "$MCP_SETTINGS_JSON" | jq '.mcp')
    if jq --argjson a "$current_mcp" --argjson b "$desired_mcp" -n '$a == $b'; then
      print_info_log "No change needed for $mcp_path"
      continue
    fi
    create_backup "$mcp_path" "$app_type"
    print_info_log "Adding mcp config with mcp key as top level at path $mcp_path"
    updated=$(jq --argjson mcp "$desired_mcp" '.mcp = $mcp' "$mcp_path")
    echo "$updated" > "$mcp_path"
  else
    # This is a project-specific .vscode/mcp.json file - compare root keys
    # Try to parse with jq first, if it fails, strip comments and try again
    if current_root=$(jq '.' "$mcp_path" 2>/dev/null); then
      # Valid JSON, use as-is
      print_debug_log "File $mcp_path is valid JSON"
    else
      # Not valid JSON, likely has comments - strip them
      print_debug_log "File $mcp_path has comments, stripping them"
      current_root=$(strip_json_comments "$mcp_path" | jq '.')
    fi

    desired_root=$(echo "$MCP_JSON" | jq '.')
    comparison_result=$(jq --argjson a "$current_root" --argjson b "$desired_root" -n '$a == $b')
    print_debug_log "Comparison result: $comparison_result"

    if [[ "$comparison_result" == "true" ]]; then
      print_info_log "No change needed for $mcp_path"
      continue
    fi

    create_backup "$mcp_path" "$app_type"
    print_info_log "Adding mcp config to project-specific mcp.json at path $mcp_path"
    echo "$MCP_JSON" | jq '.' > "$mcp_path"
  fi

  print_info_log "Updated $mcp_path with mcp settings"
done
