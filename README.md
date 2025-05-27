# DNSniper v2.0 - Automated DNS Firewall

DNSniper is an advanced automated DNS firewall system designed for Linux servers. It automatically downloads domain lists from threat intelligence feeds, resolves them to IP addresses, and blocks malicious traffic using iptables and ipset for maximum performance.

## 🚀 Features

### Core Features
- **Automated Domain Processing**: Downloads and processes domain lists from multiple threat intelligence sources
- **High-Performance Blocking**: Uses Linux ipset for O(1) IP lookup performance
- **Whitelist Priority**: Whitelist rules always take precedence over blocklist rules
- **IPv4/IPv6 Support**: Full support for both IPv4 and IPv6 addresses and ranges
- **FIFO IP Management**: Intelligent rotation of IPs per domain to prevent memory exhaustion
- **CDN Detection**: Automatically detects and flags CDN domains

### Advanced Features
- **GORM Database Integration**: Modern ORM with automatic firewall synchronization
- **Real-time Firewall Sync**: Database changes automatically update firewall rules
- **Rate Limiting**: Built-in rate limiting for DNS resolution requests
- **Worker Pool**: Concurrent domain processing for improved performance
- **Comprehensive Logging**: Detailed logging with file rotation
- **Configuration Management**: YAML-based configuration with environment variable overrides

### Security Features
- **Whitelist Priority Protection**: Prevents accidental blocking of critical services
- **Input Validation**: Comprehensive validation of domains, IPs, and CIDR ranges
- **Error Recovery**: Automatic backup and restore of firewall rules
- **Safe Uninstallation**: Complete cleanup of all firewall rules and configurations

## 📋 Requirements

### System Requirements
- **Operating System**: Linux (Ubuntu 18.04+, Debian 9+, CentOS 7+, RHEL 7+)
- **Architecture**: x86_64 (amd64)
- **Memory**: Minimum 512MB RAM (1GB+ recommended)
- **Storage**: 100MB for installation + space for logs and database

### Dependencies
- **iptables**: For firewall rule management
- **ipset**: For high-performance IP set management
- **systemd**: For service management
- **Go 1.19+**: For building from source (optional)

### Network Requirements
- Internet access for downloading threat intelligence feeds
- DNS resolution capability
- Root/sudo access for firewall management

## 🔧 Installation

### Quick Installation (Recommended)
```bash
# Download and run the installer
curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/scripts/installer.sh | sudo bash
```

### Manual Installation
```bash
# Clone the repository
git clone https://github.com/MahdiGraph/DNSniper.git
cd DNSniper

# Make installer executable
chmod +x scripts/installer.sh

# Run installer with root privileges
sudo ./scripts/installer.sh
```

### Building from Source
```bash
# Install Go 1.19+ first, then:
git clone https://github.com/MahdiGraph/DNSniper.git
cd DNSniper

# Build binaries
go build -ldflags="-s -w" -o /usr/local/bin/dnsniper ./cmd/dnsniper
go build -ldflags="-s -w" -o /usr/local/bin/dnsniper-agent ./cmd/dnsniper-agent

# Run installer to set up services and configuration
sudo ./scripts/installer.sh
```

## ⚙️ Configuration

### Default Configuration
DNSniper automatically creates a default configuration at `/etc/dnsniper/config.yaml`:

```yaml
version: "2.0"
dns_resolvers:
  - "8.8.8.8"
  - "1.1.1.1"
affected_chains:
  - "INPUT"
  - "OUTPUT"
  - "FORWARD"
enable_ipv6: true
rate_limit_enabled: true
rate_limit_count: 1000
rate_limit_window: 1m
update_urls:
  - "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"
update_interval: 3h
rule_expiration: 12h
max_ips_per_domain: 5
logging_enabled: false
log_level: "info"
database_path: "/etc/dnsniper/dnsniper.db"
log_path: "/var/log/dnsniper"
```

### Configuration Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `dns_resolvers` | DNS servers for domain resolution | `["8.8.8.8", "1.1.1.1"]` | `["9.9.9.9", "1.1.1.1"]` |
| `affected_chains` | iptables chains to apply rules | `["INPUT", "OUTPUT", "FORWARD"]` | `["INPUT"]` |
| `enable_ipv6` | Enable IPv6 support | `true` | `false` |
| `rate_limit_enabled` | Enable rate limiting | `true` | `false` |
| `rate_limit_count` | Max requests per window | `1000` | `500` |
| `rate_limit_window` | Rate limit time window | `1m` | `30s` |
| `update_urls` | Threat intelligence feed URLs | See config | Custom URLs |
| `update_interval` | How often to update | `3h` | `1h` |
| `rule_expiration` | When auto-rules expire | `12h` | `24h` |
| `max_ips_per_domain` | Max IPs per domain | `5` | `10` |
| `logging_enabled` | Enable file logging | `false` | `true` |
| `log_level` | Logging verbosity | `"info"` | `"debug"` |

### Environment Variables
All configuration options can be overridden with environment variables:

```bash
export DNSNIPER_DNS_RESOLVERS="9.9.9.9,1.1.1.1"
export DNSNIPER_AFFECTED_CHAINS="INPUT,OUTPUT"
export DNSNIPER_ENABLE_IPV6="true"
export DNSNIPER_UPDATE_INTERVAL="1h"
export DNSNIPER_LOGGING_ENABLED="true"
export DNSNIPER_LOG_LEVEL="debug"
```

## 🎯 Usage

### Interactive Management
```bash
# Launch interactive menu
sudo dnsniper
```

The interactive menu provides:
- Real-time status monitoring
- Whitelist/blacklist management
- Configuration management
- Firewall rule management
- System health checks

### Command Line Usage
```bash
# Show help
dnsniper --help

# Show version
dnsniper --version

# Use custom config
dnsniper --config /path/to/config.yaml

# Run agent manually
dnsniper-agent

# Run agent with custom config
dnsniper-agent --config /path/to/config.yaml
```

### Service Management
```bash
# Check service status
systemctl status dnsniper-agent.service
systemctl status dnsniper-agent.timer

# Start/stop services
systemctl start dnsniper-agent.timer
systemctl stop dnsniper-agent.timer

# View logs
journalctl -u dnsniper-agent.service -f
journalctl -u dnsniper-agent.timer -f

# Check next scheduled run
systemctl list-timers dnsniper-agent.timer
```

## 🛡️ Firewall Integration

### IPSet Collections
DNSniper creates the following ipset collections:

| Set Name | Purpose | Type |
|----------|---------|------|
| `whitelistIP-v4` | IPv4 whitelist IPs | hash:ip |
| `whitelistIP-v6` | IPv6 whitelist IPs | hash:ip |
| `whitelistRange-v4` | IPv4 whitelist ranges | hash:net |
| `whitelistRange-v6` | IPv6 whitelist ranges | hash:net |
| `blocklistIP-v4` | IPv4 blocked IPs | hash:ip |
| `blocklistIP-v6` | IPv6 blocked IPs | hash:ip |
| `blocklistRange-v4` | IPv4 blocked ranges | hash:net |
| `blocklistRange-v6` | IPv6 blocked ranges | hash:net |

### Iptables Rules
Example generated rules for INPUT chain:
```bash
# Whitelist rules (processed first - higher priority)
iptables -A INPUT -m set --match-set whitelistIP-v4 src -j ACCEPT
iptables -A INPUT -m set --match-set whitelistRange-v4 src -j ACCEPT

# Blocklist rules (processed after whitelist)
iptables -A INPUT -m set --match-set blocklistIP-v4 src -j DROP
iptables -A INPUT -m set --match-set blocklistRange-v4 src -j DROP
```

### Whitelist Priority
**Important**: Whitelist rules ALWAYS take priority over blocklist rules. This means:
- If an IP is in both whitelist and blocklist, it will be ALLOWED
- Whitelist rules are processed first in iptables
- This prevents accidental blocking of critical services

## 📊 Monitoring and Logs

### Status Monitoring
```bash
# View comprehensive status
sudo dnsniper
# Select option 2 (Show status)

# Check firewall rules
sudo iptables -L -n | grep dnsniper
sudo ipset list | grep -E "(whitelist|blocklist)"

# View statistics
sudo dnsniper
# Select option 2 for detailed statistics
```

### Log Files
- **Service logs**: `journalctl -u dnsniper-agent.service`
- **Application logs**: `/var/log/dnsniper/dnsniper.log` (if logging enabled)
- **Run-specific logs**: `/var/log/dnsniper/runs/run_*.log`

### Database
- **Location**: `/etc/dnsniper/dnsniper.db`
- **Type**: SQLite with GORM
- **Tables**: domains, ips, ip_ranges, agent_runs, agent_logs, update_urls

## 🔧 Troubleshooting

### Common Issues

#### 1. Service Not Starting
```bash
# Check service status
systemctl status dnsniper-agent.service

# Check logs
journalctl -u dnsniper-agent.service -n 50

# Common fixes
sudo systemctl daemon-reload
sudo systemctl restart dnsniper-agent.timer
```

#### 2. Firewall Rules Not Applied
```bash
# Check if ipset is installed
which ipset

# Check if iptables is working
sudo iptables -L -n

# Rebuild firewall rules
sudo dnsniper
# Select option 7 (Rebuild firewall rules)
```

#### 3. DNS Resolution Issues
```bash
# Test DNS resolution
nslookup google.com 8.8.8.8

# Check DNS resolvers in config
cat /etc/dnsniper/config.yaml | grep dns_resolvers

# Update DNS resolvers
sudo dnsniper
# Select option 5 (Settings) -> 1 (DNS Resolvers)
```

#### 4. Permission Issues
```bash
# Ensure proper ownership
sudo chown -R root:root /etc/dnsniper
sudo chmod 755 /etc/dnsniper
sudo chmod 644 /etc/dnsniper/config.yaml

# Check if running as root
sudo dnsniper-agent
```

### Debug Mode
Enable debug logging for detailed troubleshooting:
```bash
# Edit config
sudo nano /etc/dnsniper/config.yaml

# Set:
logging_enabled: true
log_level: "debug"

# Restart service
sudo systemctl restart dnsniper-agent.timer
```

## 🔄 Updating

### Automatic Updates
DNSniper automatically updates domain lists based on the configured `update_interval`. No manual intervention required.

### Manual Updates
```bash
# Run agent manually
sudo dnsniper-agent

# Or trigger via systemd
sudo systemctl start dnsniper-agent.service
```

### Software Updates
```bash
# Re-run installer to update
curl -sSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/scripts/installer.sh | sudo bash

# Or build from source
git pull origin main
go build -ldflags="-s -w" -o /usr/local/bin/dnsniper ./cmd/dnsniper
go build -ldflags="-s -w" -o /usr/local/bin/dnsniper-agent ./cmd/dnsniper-agent
sudo systemctl restart dnsniper-agent.timer
```

## 🗑️ Uninstallation

### Complete Removal
```bash
# Using the built-in uninstaller (recommended)
sudo dnsniper --uninstall

# Or using the interactive menu
sudo dnsniper
# Select option U (Uninstall DNSniper)
```

### Manual Removal
```bash
# Stop services
sudo systemctl stop dnsniper-agent.timer
sudo systemctl stop dnsniper-agent.service
sudo systemctl disable dnsniper-agent.timer
sudo systemctl disable dnsniper-agent.service

# Remove service files
sudo rm -f /etc/systemd/system/dnsniper-agent.service
sudo rm -f /etc/systemd/system/dnsniper-agent.timer
sudo systemctl daemon-reload

# Remove binaries
sudo rm -f /usr/local/bin/dnsniper
sudo rm -f /usr/local/bin/dnsniper-agent

# Remove configuration and data
sudo rm -rf /etc/dnsniper
sudo rm -rf /var/log/dnsniper

# Clean up firewall rules
sudo dnsniper --uninstall  # If binary still exists
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
```bash
git clone https://github.com/MahdiGraph/DNSniper.git
cd DNSniper
go mod download
go build ./cmd/dnsniper
go build ./cmd/dnsniper-agent
```

### Running Tests
```bash
go test ./...
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/MahdiGraph/DNSniper/issues)
- **Discussions**: [GitHub Discussions](https://github.com/MahdiGraph/DNSniper/discussions)
- **Documentation**: [Wiki](https://github.com/MahdiGraph/DNSniper/wiki)

## 🙏 Acknowledgments

- Thanks to all threat intelligence providers
- Linux netfilter/iptables developers
- Go community for excellent libraries
- All contributors and users

---

**⚠️ Important Security Note**: DNSniper is a powerful firewall tool. Always test in a non-production environment first and ensure you have alternative access methods before deploying in production.