# Oblivion Server - Linux Build Guide

## Requirements

### Debian/Ubuntu
```bash
sudo apt-get update
sudo apt-get install -y build-essential libssl-dev
```

### Dependencies
- g++ (C++17 compiler)
- OpenSSL development libraries (libssl-dev)
- pthread (usually included with g++)

## Build Instructions

### 1. Navigate to server directory
```bash
cd server
```

### 2. Build the server
```bash
make
```

### 3. Make management script executable and fix line endings
```bash
# Install dos2unix (if not already installed)
sudo apt-get install -y dos2unix

# Fix Windows line endings (if transferred from Windows)
dos2unix oblivion-start

# Make executable
chmod +x oblivion-start

# Test the script
./oblivion-start
```

**Note:** If you get "bad interpreter" error, it means the file has Windows line endings (CRLF). Run `dos2unix oblivion-start` to fix it.

### 4. Run the server

**Option A: Using management script (recommended)**
```bash
# Interactive mode (shows usage and prompts for input)
./oblivion-start

# Or with command directly
./oblivion-start start
```

**Option B: Run directly**
```bash
./oblivion-server
```

## Required runtime configuration

The server has no listener, file-path, concurrency, request-timeout, or heartbeat defaults. Provision every required variable through the service manager or a protected environment file before starting the process.

| Environment variable | Required value |
|---|---|
| `OBLIVION_LISTEN_ADDRESS` | Explicit local IPv4/IPv6 address or resolvable local interface name |
| `OBLIVION_LISTEN_PORT` | TCP port, canonical decimal, 1–65535 |
| `OBLIVION_LISTEN_BACKLOG` | Integer, 1–65535 |
| `OBLIVION_BAN_LIST_PATH` | Absolute path to an existing readable ban-list file |
| `OBLIVION_VIOLATION_LOG_PATH` | Absolute path to a writable log file, different from the ban-list path |
| `OBLIVION_MAX_CONCURRENT_CLIENTS` | Integer, 1–1024 |
| `OBLIVION_REQUEST_TIMEOUT_MS` | Integer, 100–120000 |
| `OBLIVION_HB_INTERVAL_MS` | Integer, 100–60000 |
| `OBLIVION_HB_JITTER_MS` | Integer, 0–10000 |
| `OBLIVION_HB_TIMEOUT_MS` | Integer, 250–120000 |
| `OBLIVION_HB_MAX_MISS` | Integer, 1–10 |
| `OBLIVION_HB_RTT_WARN_MS` | Integer, 0–60000 |

All values are mandatory. A missing or malformed value causes startup to fail; the server never silently substitutes a compiled-in value.

Configure exactly one secret source:

- `OBLIVION_SECRET` — secret text supplied by the service environment.
- `OBLIVION_SECRET_FILE` — absolute path to a plaintext secret file.

The two secret sources are mutually exclusive. The secret must contain at least 32 printable ASCII bytes. The secret file may end with one line ending. Restrict its permissions to the service account and authorized administrators. The client must be configured with the exact same secret text.

## Service integration

Use the service manager's protected environment/credential mechanism to provide the required configuration. Do not place secret values in this repository, command-line arguments, unit files committed to source control, or logs. Configure the actual service account and absolute storage paths for the host; do not use sample or placeholder paths.

Before starting, create the ban-list file at the configured path. It may be empty. Ensure the configured violation-log path is writable by the service account.

## Management script

The `oblivion-start` script can start, stop, restart, report status, and display the service log. It inherits the runtime environment from its caller. Start it from the service environment that supplies the required configuration.

## Operational notes

- Bind only to the intended local interface and restrict inbound TCP with host/perimeter firewalls.
- The transport is plain TCP; TLS is intentionally out of scope.
- Keep server secret/configuration, ban list, and logs accessible only to authorized operators.
- CI does not validate the game, actual client/server traffic, or the production host.
