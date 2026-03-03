# OpenClaw Fingerprint Scanner

[English](README.md) | [简体中文](README_CN.md)

A powerful network scanner for detecting OpenClaw AI Agent framework instances with multi-dimensional fingerprinting.

## Features

- **69+ Detection Features** - Comprehensive fingerprint database
- **CIDR Support** - Scan entire network segments (e.g., 192.168.1.0/24)
- **Real-time Output** - See discovered targets as they're found
- **Confidence Scoring** - Intelligent scoring system (HIGH/MEDIUM/LOW)
- **Configurable Rules** - Customize detection via JSON configuration
- **High Performance** - Multi-threaded scanning with connection pooling

## Quick Start

### Installation

```bash
pip install -r requirements.txt
```

### Basic Usage

```bash
# Scan single IP
python scanner.py -t 192.168.1.100

# Scan C-class network
python scanner.py -t 192.168.1.0/24 --realtime

# Batch scan with results
python scanner.py -f targets.txt -o results.json
```

## Configuration

All detection features are configured in `fingerprints.json`:

- **endpoints** - API endpoints to probe
- **headers** - Response header signatures
- **keywords** - Content keywords
- **json_keys** - JSON structure patterns
- **weights** - Feature scoring weights

### Custom Configuration

```bash
python scanner.py -t 192.168.1.100 --config my_config.json
```

## Command Line Options

### Target Options

| Option | Description | Example |
|--------|-------------|---------|
| `-t, --target` | Single target | `-t 192.168.1.0/24` |
| `-f, --file` | Target file | `-f targets.txt` |

### Performance Options

| Option | Default | Description |
|--------|---------|-------------|
| `-w, --workers` | 20 | Concurrent threads |
| `--timeout` | 5 | Request timeout (seconds) |
| `--retry` | 2 | Retry attempts |
| `--rate-limit` | 0 | Request interval (seconds) |

### Output Options

| Option | Description |
|--------|-------------|
| `-o, --output` | Save JSON results |
| `-v, --verbose` | Detailed output |
| `--realtime` | Real-time discovery output |
| `--stats` | Show statistics |

### Filter Options

| Option | Description |
|--------|-------------|
| `--min-confidence` | Minimum confidence (LOW/MEDIUM/HIGH) |
| `--config` | Custom config file |

## Target Formats

Supports multiple target formats:

```
# IP address
192.168.1.100

# IP with port
192.168.1.100:8080

# CIDR notation
192.168.1.0/24

# Domain
example.com

# Full URL
http://example.com:8080
```

## Usage Examples

### Fast Scan

```bash
python scanner.py -t 192.168.1.0/24 -w 50 --realtime
```

### Stealth Scan

```bash
python scanner.py -t 192.168.1.0/24 -w 5 --rate-limit 2 --timeout 10
```

### High Confidence Only

```bash
python scanner.py -f targets.txt --min-confidence HIGH -o results.json
```

## Output

### Confidence Levels

- **HIGH** (Red): Score >= 80, strong match
- **MEDIUM** (Yellow): Score >= 40, possible match
- **LOW** (Green): Score < 40, weak match

### Example Output

```
Scanning progress |████████| 500/2032 [00:30<01:45, 14.5url/s] Found:3
[Found] http://192.168.1.100:8080 [Confidence: HIGH | Score: 125]
[Found] http://192.168.1.105:3000 [Confidence: MEDIUM | Score: 65]
```

## Documentation

- [README.md](README.md) - This file
- [USAGE.md](USAGE.md) - Detailed usage guide
- [fingerprints.json](fingerprints.json) - Detection configuration
- [targets.txt.example](targets.txt.example) - Target file example

## Security Notice

⚠️ **Important**:
- Use only on authorized systems
- Comply with applicable laws and regulations
- Control scan rate to avoid service impact
- Respect target system policies

## License

MIT License

## Contributing

Contributions welcome! Please feel free to submit a Pull Request.
