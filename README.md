# Port_Spy

Local port scanner. See what's listening where, mapped to PIDs and process names. Zero dependencies — Python stdlib only.

🔍 **[Port_Spy on Hermtica Marketplace](https://hermtica.com/marketplace)**

## Installation

```bash
git clone git@github.com:realMNohgee/Port_Spy.git
cd Port_Spy
chmod +x port_spy.py
# Or symlink to your PATH:
ln -s "$(pwd)/port_spy.py" /usr/local/bin/port_spy
```

## Usage

### Scan all listening ports

```bash
./port_spy.py scan
```

Output:
```
PORT  PROTO  PID    PROCESS       STATE
22    TCP    123    sshd          LISTEN
80    TCP    456    nginx         LISTEN
443   TCP    456    nginx         LISTEN
```

### Filter by port

```bash
./port_spy.py scan --port 3000
```

### Protocol filter

```bash
./port_spy.py scan --tcp        # TCP only
./port_spy.py scan --udp        # UDP only
./port_spy.py scan --all        # All protocols
```

### JSON output

```bash
./port_spy.py scan --format json
```

### Lookup detailed port info

```bash
./port_spy.py lookup 5432
```

Shows process name, PID, full command, user, and known service name (SSH, HTTP, HTTPS, PostgreSQL, Redis, etc.).

### Live watch for port changes

```bash
./port_spy.py watch
./port_spy.py watch --interval 5
```

Monitors every N seconds, showing NEW and CLOSED port changes in real time.

## Subcommands

| Command    | Description                                        |
|------------|----------------------------------------------------|
| `scan`     | Scan listening ports (filter by port, protocol)    |
| `lookup`   | Detailed info for a specific port                  |
| `watch`    | Live monitor port changes every N seconds          |

All subcommands support `--format text|json`.

## Requirements

- Python 3.8+
- macOS or Linux with `lsof` available
- No external dependencies

## License

MIT — see [LICENSE](LICENSE)
