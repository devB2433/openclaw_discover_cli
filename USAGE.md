# OpenClaw Fingerprint Scanner - Quick Start Guide

[English](USAGE.md) | [简体中文](USAGE_CN.md)

## Quick Start

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Basic Scanning

```bash
# Scan single IP
python scanner.py -t 192.168.1.100

# Scan C-class network
python scanner.py -t 192.168.1.0/24

# Scan specific port
python scanner.py -t 192.168.1.100:8080
```

## Common Scenarios

### Scenario 1: Fast C-Class Scan

```bash
python scanner.py -t 192.168.1.0/24 --realtime -w 50
```

- `--realtime`: Display targets as discovered
- `-w 50`: Use 50 concurrent threads

### Scenario 2: Batch Scan Multiple Networks

Create target file `targets.txt`:
```
192.168.1.0/24
10.0.0.0/24
172.16.0.0/28
```

Execute scan:
```bash
python scanner.py -f targets.txt --realtime -o results.json --stats
```

### Scenario 3: Stealth Scan

**What is Stealth Scanning?**

Stealth scanning reduces scan visibility to avoid detection by security devices (IDS/IPS, WAF, firewalls).

**Why Use Stealth Scanning?**
- Avoid triggering security alerts
- Prevent IP blocking
- Minimize service impact
- Meet compliance requirements

**Stealth Scan Command:**
```bash
python scanner.py -t 192.168.1.0/24 -w 5 --rate-limit 2 --timeout 10
```

**Parameters:**
- `-w 5`: Low concurrency (5 threads instead of 50)
- `--rate-limit 2`: 2-second interval between requests (mimics normal access)
- `--timeout 10`: Long timeout (more patient)

**Comparison:**
```bash
# Fast scan (easily detected)
python scanner.py -t 192.168.1.0/24 -w 100 --timeout 3
# Characteristics: High volume in short time, obvious scanning behavior

# Stealth scan (hard to detect)
python scanner.py -t 192.168.1.0/24 -w 5 --rate-limit 2 --timeout 10
# Characteristics: Distributed traffic, resembles normal user access
```

### Scenario 4: High Confidence Filter

```bash
python scanner.py -f targets.txt --min-confidence HIGH -o high_confidence.json
```

Output only high-confidence results.

## Configuration File

Scanner uses `fingerprints.json` for all detection features and parameters.

### Using Custom Configuration

```bash
# Specify config file
python scanner.py -t 192.168.1.100 --config my_config.json
```

### Configuration Structure

```json
{
  "endpoints": {},           // API endpoints
  "headers": [],            // Response headers
  "keywords": [],           // Keywords
  "json_keys": [],          // JSON structure
  "error_patterns": [],     // Error patterns
  "websocket_endpoints": [], // WebSocket endpoints
  "weights": ,            // Feature weights
  "confidence_thresholds": {}, // Confidence thresholds
  "scanner_config": {},     // Scanner parameters
  "output_colors": {}       // Output colors
}
```

### Custom Features

Edit `fingerprints.json` to add new features:

```json
{
  "endpoints": {
    "/my/custom/api": ["GET"]
  },
  "keywords": [
    "my-framework"
  ],
  "weights": {
    "Keyword 'my-framework'": 50
  }
}
```

## Command Line Parameters

### Target Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `-t, --target` | Single target | `-t 192.168.1.0/24` |
| `-f, --file` | Target file | `-f targets.txt` |

### Performance Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `-w, --workers` | 20 | Concurrent threads |
| `--timeout` | 5 | Request timeout (seconds) |
| `--retry` | 2 | Retry attempts |
| `--rate-limit` | 0 | Request interval (seconds) |
| `--ports` | - | Custom port list |

### Output Parameters

| Parameter | Description |
|-----------|-------------|
| `-o, --output` | Save JSON results |
| `-v, --verbose` | Detailed output |
| `--realtime` | Real-time discovery output |
| `--no-progress` | Disable progress bar |
| `--stats` | Show statistics |

### Filter Parameters

| Parameter | Description |
|-----------|-------------|
| `--min-confidence` | Minimum confidence (LOW/MEDIUM/HIGH) |
| `--config` | Specify config file |

## Target Formats

Supports the following formats:

```
# IP address
192.168.1.100

# IP:PORT
192.168.1.100:8080

# CIDR notation
192.168.1.0/24
10.0.0.0/16

# Domain
example.com
api.example.com

# Full URL
http://example.com:8080
https://api.example.com
```

## Output Description

### Confidence Levels

- **HIGH** (Red): Score >= 80, strong match
- **MEDIUM** (Yellow): Score >= 40, possible match
- **LOW** (Green): Score < 40, weak match

### Real-time Output Example

```
Scanning progress |████████| 500/2032 [00:30<01:45, 14.5url/s] Found:3
[Found] http://192.168.1.100:8080 [Confidence: HIGH | Score: 125]
[Found] http://192.168.1.105:3000 [Confidence: MEDIUM | Score: 65]
```

### Detailed Output (-v)

```bash
python scanner.py -t 192.168.1.100 -v
```

Output:
```
[+] http://192.168.1.100:8080 [Confidence: HIGH | Score: 125]
    - Header: X-OpenClaw-Version=1.2.3
    - Keyword 'openclaw' at /
    - JSON key 'agents' at /api/v1/agents
    - Agent API accessible (GET)
```

## Performance Optimization

### Fast Scan
```bash
python scanner.py -t 192.168.1.0/24 -w 100 --timeout 3 --retry 1
```

### Balanced Mode
```bash
python scanner.py -t 192.168.1.0/24 -w 20 --timeout 5 --retry 2
```

### Stealth Mode
```bash
python scanner.py -t 192.168.1.0/24 -w 5 --timeout 10 --rate-limit 2
```

## Custom Configuration

### Modify Default Ports

Edit `fingerprints.json`:
```json
{
  "scanner_config": {
    "default_ports": [80, 443, 8080, 8443, 3000, 5000]
  }
}
```

### Add Custom Features

```json
{
  "endpoints": {
    "/my/custom/api": ["GET"]
  },
  "keywords": [
    "my-framework"
  ],
  "weights": {
    "Keyword 'my-framework'": 50
  }
}
```

### Use Custom Config

```bash
python scanner.py -t 192.168.1.100 --config my_config.json
```

## FAQ

### Q: How to scan multiple C-class networks?

A: Create target file with one CIDR per line:
```bash
echo "192.168.1.0/24" > targets.txt
echo "192.168.2.0/24" >> targets.txt
python scanner.py -f targets.txt --realtime
```

### Q: How to scan specific ports only?

A: Use `--ports` parameter:
```bash
python scanner.py -t 192.168.1.0/24 --ports 80,443,8080
```

### Q: Scan is too slow?

A: Increase concurrency, reduce timeout:
```bash
python scanner.py -t 192.168.1.0/24 -w 100 --timeout 3
```

### Q: How to avoid detection?

A: Lower concurrency, add intervals:
```bash
python scanner.py -t 192.168.1.0/24 -w 5 --rate-limit 2
```

### Q: How to save scan results?

A: Use `-o` parameter:
```bash
python scanner.py -f targets.txt -o results.json
```

## Complete Examples

### Example 1: Enterprise Internal Network Scan

```bash
# Scan multiple internal networks, real-time output, save results
python scanner.py -f internal_networks.txt \
  --realtime \
  -w 50 \
  --min-confidence MEDIUM \
  -o scan_results.json \
  --stats
```

### Example 2: External Target Scan

```bash
# Cautious scan of external targets
python scanner.py -f external_targets.txt \
  -w 10 \
  --rate-limit 1 \
  --timeout 10 \
  --retry 3 \
  -o external_results.json
```

### Example 3: Quick Verification

```bash
# Quick verification of single target
python scanner.py -t 192.168.1.100:8080 -v
```

## Important Notes

⚠️ **Important**:
1. Use only on authorized systems
2. Comply with target system access policies
3. Control scan rate to avoid service impact
4. Follow applicable laws and regulations
5. Test on small scale before large-scale scanning

## Getting Help

```bash
# View all parameters
python scanner.py --help
```

## Related Documentation

- `README.md` - Complete usage guide
- `fingerprints.json` - Fingerprint configuration
- `targets.txt.example` - Target file example
