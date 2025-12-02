# Serial-to-SSH Gateway

This is a Go application that acts as a gateway between a physical serial port and an SSH server. It is designed to run on a "server" computer (Windows, Linux, macOS) and allow a user connecting via a serial cable to log in to remote SSH servers.

## Features

- **Cross-Platform**: Runs on Windows (7/10/11), Linux, and macOS.
- **Binary Transparency**: Supports Zmodem (`rz`/`sz`) and other binary protocols by ensuring a raw data path.
- **TUI Interface**: Server-side dashboard using Bubble Tea to show status and logs.
- **No External Dependencies**: Uses native Go SSH implementation; does not require local `ssh` binary or `cmd.exe`.

## Usage

### Build

```bash
go build -o serial2ssh-gateway main.go
```

### Run

**List available ports:**
```bash
./serial2ssh-gateway -list
```

**Start the gateway:**
```bash
# Linux/macOS
./serial2ssh-gateway -port /dev/ttyUSB0

# Windows
serial2ssh-gateway.exe -port COM3
```

### Connection Workflow (Client Side)

1. Connect your client device (laptop, terminal) to the server's serial port.
2. Open a serial terminal (e.g., PuTTY, minicom) with settings: **115200, 8, N, 1**.
3. You will see a welcome screen.
4. Enter the target SSH host (e.g., `192.168.1.50`), username, and password.
5. Once connected, you are in a full SSH session. You can run commands or transfer files using Zmodem.
6. Type `exit` to close the SSH session and return to the gateway login screen.

## Development

**Dependencies:**
- `github.com/charmbracelet/bubbletea` (UI)
- `go.bug.st/serial` (Serial Comm)
- `golang.org/x/crypto/ssh` (SSH Client)

**Cross-Compiling for Windows (from macOS/Linux):**
```bash
GOOS=windows GOARCH=amd64 go build -o serial2ssh-gateway.exe main.go
```
