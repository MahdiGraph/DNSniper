# DNSniper v2.0 - Automated DNS Firewall

DNSniper is an advanced DNS-based firewall solution that automatically blocks malicious domains and their associated IP addresses using iptables and ipset for high-performance traffic filtering.

## 🚀 Quick Install

### One-Line Installation (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/scripts/installer.sh | sudo bash
```

Or with wget:
```bash
wget -qO- https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/scripts/installer.sh | sudo bash
```

### Manual Installation

1. Download the installer:
```bash
wget https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/scripts/installer.sh
chmod +x installer.sh
```

2. Run the installer:
```bash
sudo ./installer.sh
```

### Build from Source

If you want to build from the latest source code:
```bash
git clone https://github.com/MahdiGraph/DNSniper.git
cd DNSniper
sudo ./scripts/installer.sh --build
```

## 📋 System Requirements

- **Operating System**: Linux with systemd (Ubuntu 18.04+, Debian 10+, CentOS 7+, Fedora 30+)
- **Architecture**: x86_64, ARM64, ARMv7, or i386
- **Kernel**: Linux 3.10+ (for optimal iptables/netfilter support)
- **Memory**: Minimum 512MB RAM
- **Storage**: 100MB free space
- **Network**: Internet connection for downloading domain lists

## 🔧 What the Installer Does

The enhanced installer automatically:

1. **System Compatibility Check**
   - Detects Linux distribution and version
   - Verifies systemd availability
   - Checks kernel version for netfilter support

2. **Dependency Installation**
   - Installs iptables, ipset, and persistence tools
   - Configures package manager (apt/yum/dnf)
   - Verifies all critical commands are available

3. **Existing Installation Detection**
   - Scans for previous DNSniper installations
   - Offers upgrade, clean install, or uninstall options
   - Preserves user data during upgrades

4. **Binary Management**
   - Downloads latest release from GitHub (default)
   - Verifies SHA256 checksums for security
   - Supports building from source with `--build` flag
   - Installs binaries to `/usr/local/bin`

5. **Configuration Setup**
   - Creates default configuration in `/etc/dnsniper/`
   - Preserves existing settings during upgrades
   - Sets up logging and database paths

6. **Service Configuration**
   - Creates systemd services and timers
   - Reads update interval from configuration
   - Enables firewall rule persistence
   - Starts services automatically

7. **System Integration**
   - Creates system-wide `dnsniper` command
   - Enables iptables/ipset persistence
   - Configures automatic startup

## 🎯 Quick Start

After installation:

1. **Open the management interface**:
   ```bash
   dnsniper
   ```

2. **Check service status**:
   ```bash
   systemctl status dnsniper-agent.timer
   ```

3. **View logs**:
   ```bash
   journalctl -u dnsniper-agent.service -f
   ```

4. **Manual agent run**:
   ```bash
   dnsniper-agent
   ```

## 🛡️ Features

- **Automatic Domain Blocking**: Downloads and processes malicious domain lists
- **IP Resolution & Blocking**: Resolves domains to IPs and blocks them via iptables
- **Whitelist Priority**: Whitelist rules always take precedence over blocklist
- **High Performance**: Uses ipset for O(1) IP lookup performance
- **IPv4/IPv6 Support**: Full dual-stack support
- **Database Integration**: GORM-based with automatic firewall synchronization
- **Web Interface**: User-friendly management interface
- **Systemd Integration**: Automatic startup and scheduling
- **Rule Persistence**: Firewall rules survive reboots
- **Comprehensive Logging**: Detailed operation logs
- **Rate Limiting**: Prevents DNS resolver overload

## 📁 File Locations

After installation, DNSniper files are located at:

- **Binaries**: `/usr/local/bin/dnsniper`, `/usr/local/bin/dnsniper-agent`
- **Configuration**: `/etc/dnsniper/config.yaml`
- **Database**: `/etc/dnsniper/dnsniper.db`
- **Logs**: `/var/log/dnsniper/`
- **Services**: `/etc/systemd/system/dnsniper-agent.*`

## 🔧 Configuration

The main configuration file is located at `/etc/dnsniper/config.yaml`:

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
update_interval: "3h"
rule_expiration: "12h"
max_ips_per_domain: 5
update_urls:
  - "https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/domains-default.txt"
```

## 🚨 Uninstallation

To completely remove DNSniper:

```bash
sudo dnsniper --uninstall
```

Or use the installer:
```bash
sudo ./installer.sh
# Choose option 3 (Uninstall)
```

## 🐛 Troubleshooting

### Common Issues

1. **Permission Denied**
   ```bash
   # Make sure to run with sudo
   sudo ./installer.sh
   ```

2. **Service Not Starting**
   ```bash
   # Check service status
   systemctl status dnsniper-agent.service
   
   # Check logs
   journalctl -u dnsniper-agent.service
   ```

3. **Firewall Rules Not Working**
   ```bash
   # Verify iptables rules
   iptables -L | grep DNSniper
   
   # Check ipset lists
   ipset list
   ```

4. **Build Failures**
   ```bash
   # Install Go 1.21+
   # Then use build flag
   sudo ./installer.sh --build
   ```

## 📚 Documentation

- [Configuration Guide](docs/configuration.md)
- [API Reference](docs/api.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Contributing](CONTRIBUTING.md)

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- [GitHub Repository](https://github.com/MahdiGraph/DNSniper)
- [Issue Tracker](https://github.com/MahdiGraph/DNSniper/issues)
- [Releases](https://github.com/MahdiGraph/DNSniper/releases)

---

**⚠️ Important**: DNSniper modifies your system's firewall rules. Always test in a non-production environment first and ensure you have alternative access methods to your system.