# DNSniper: Advanced Firewall Management Application

🎯 **DNSniper** is a comprehensive firewall management application that manages blacklists and whitelists using iptables and ipsets to block malware domains and IPs at the firewall layer on Ubuntu servers.

![DNSniper Dashboard](https://img.shields.io/badge/Status-Production%20Ready-green)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Latest-00a393)
![React](https://img.shields.io/badge/React-18+-61dafb)

## 🚀 Features

### Core Functionality
- **Advanced Firewall Management**: Complete iptables and ipsets integration with IPv4/IPv6 support
- **Domain & IP Management**: Add, edit, and delete domains, IPs, and IP ranges
- **Auto-Update System**: Automated fetching and processing of blacklists from external sources
- **Intelligent DNS Resolution**: Safe domain resolution with private IP filtering
- **CDN Detection**: Automatic detection of CDNs based on IP count
- **Expiration Management**: FIFO mechanism for IP limits and automatic cleanup

### User Interface
- **Modern Dashboard**: Real-time statistics and system status
- **Domain Management**: Search, filter, and manage domains with CDN indicators
- **IP Management**: IPv4/IPv6 address management with validation
- **Settings Panel**: Firewall configuration and auto-update settings
- **Activity Logs**: Real-time monitoring of firewall activity

### Security Features
- **Safe IP Filtering**: Automatic filtering of private, localhost, and server IPs
- **Manual vs Auto-Update**: Clear distinction between user entries and auto-updates
- **Expiration Controls**: Manual entries are permanent, auto-updates expire
- **Firewall Safety**: Whitelist processing before blacklist rules

## 📋 Requirements

### System Requirements
- **OS**: Ubuntu 18.04+ (or any Linux with iptables/ipset support)
- **Python**: 3.8 or higher
- **Node.js**: 16+ (for frontend development)
- **Sudo Access**: Required for firewall management

### Dependencies
- `iptables` and `ip6tables`
- `ipset`
- `netfilter-persistent` (recommended for rule persistence)
- `ipset-persistent` (recommended for ipset persistence)

## 🛠️ Installation

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/dnsniper.git
   cd dnsniper
   ```

2. **Run the automated setup:**
   ```bash
   # For full installation with systemd service (requires sudo)
   sudo python3 setup.py
   
   # Or for development setup
   python3 setup.py
   ```

3. **Configure server settings (optional):**
   ```bash
   # Copy example configuration
   cp config.json.example backend/config.json
   
   # Edit backend/config.json as needed
   # Default: host=0.0.0.0, port=8000
   ```

4. **Start the application:**
   ```bash
   # Option 1: Use the start script (recommended)
   ./start.sh
   
   # Option 2: Run directly (from backend directory)
   cd backend
   python3 main.py
   ```

5. **Access the application:**
   - Web Interface: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

### Manual Installation

#### Backend Setup
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Frontend Setup
```bash
cd frontend
npm install
npm run build
```

#### Configuration
```bash
# Create configuration file
cp config.json.example backend/config.json

# Edit backend/config.json to customize host and port
```

#### Run the Application
```bash
# Option 1: From project root using start script
./start.sh

# Option 2: From backend directory
cd backend
source venv/bin/activate
python3 main.py
```

## ⚙️ Configuration

### Web Server Configuration
DNSniper uses a simple JSON configuration file. Create a `config.json` file in the `backend/` directory:

```json
{
  "web_server": {
    "host": "0.0.0.0",
    "port": 8000
  },
  "frontend": {
    "static_path": "../frontend/build"
  }
}
```

**Configuration Options:**
- **`web_server.host`**: Server bind address (default: `0.0.0.0`)
- **`web_server.port`**: Server port (default: `8000`)
- **`frontend.static_path`**: Path to frontend build directory (default: `../frontend/build`)

**Configuration Examples:**
- **Localhost only** (more secure):
  ```json
  {
    "web_server": {
      "host": "127.0.0.1",
      "port": 8000
    },
    "frontend": {
      "static_path": "../frontend/build"
    }
  }
  ```
- **Custom port and frontend path**:
  ```json
  {
    "web_server": {
      "host": "0.0.0.0",
      "port": 3000
    },
    "frontend": {
      "static_path": "/var/www/dnsniper-ui"
    }
  }
  ```
- **Production HTTP port** (requires sudo):
  ```json
  {
    "web_server": {
      "host": "0.0.0.0",
      "port": 80
    },
    "frontend": {
      "static_path": "../frontend/build"
    }
  }
  ```

**Note:** If `config.json` doesn't exist, DNSniper will use defaults: `host=0.0.0.0`, `port=8000`, `static_path=../frontend/build`

### SSL/HTTPS Configuration
SSL settings are managed through the web interface in **Settings > System Configuration**. Once configured in the database, they will be automatically applied when starting the server.

### Database Configuration

All other settings are managed through the web interface and stored in the database:

- **Auto-update Settings**: Intervals, expiration, rate limiting
- **DNS Settings**: Primary/secondary resolvers  
- **Security Settings**: Critical IP protection, automatic domain resolution
- **Logging Settings**: Log retention, monitoring
- **SSL/HTTPS Settings**: Certificate paths, domain configuration

### Firewall Configuration

DNSniper creates the following IPSets and iptables chains:

#### IPSets (8 total)
- IPv4: `dnsniper-whitelistIP-v4`, `dnsniper-whitelistRange-v4`, `dnsniper-blocklistIP-v4`, `dnsniper-blocklistRange-v4`
- IPv6: `dnsniper-whitelistIP-v6`, `dnsniper-whitelistRange-v6`, `dnsniper-blocklistIP-v6`, `dnsniper-blocklistRange-v6`

#### Chains
- IPv4: `DNSniper` chain integrated with INPUT, FORWARD, OUTPUT
- IPv6: `DNSniper6` chain integrated with INPUT, FORWARD, OUTPUT

## 📖 Usage

### Dashboard
- View system statistics and firewall status
- Monitor auto-update agent activity
- Check recent firewall activity

### Domain Management
- **Add Domains**: Manually add domains to blacklist/whitelist
- **Auto-Resolution**: Domains are automatically resolved to IPs
- **CDN Detection**: Domains with >3 IPs are flagged as CDNs
- **Search & Filter**: Find domains by name, list type, or source

### IP Management
- **Direct IP Control**: Add IPv4/IPv6 addresses directly
- **Validation**: Automatic IP address validation
- **Source Tracking**: Track manual vs auto-update entries

### Settings
- **Firewall Management**: Clear and rebuild firewall rules
- **Auto-Update Sources**: Configure external blacklist URLs
- **System Configuration**: Adjust intervals, limits, and behavior

### Auto-Update System

The auto-update system:
1. **Cleans expired entries** (restores access first)
2. **Resolves manual domains** (keeps IP mappings current)
3. **Processes auto-update sources** (adds new blocks with expiration)
4. **Maintains FIFO limits** (prevents database bloat)

## 🔧 API Reference

### Core Endpoints
- `GET /api/health` - System health check
- `GET /api/dashboard` - Dashboard statistics

### Domain Management
- `GET /api/domains` - List domains with filtering
- `POST /api/domains` - Add new domain
- `PUT /api/domains/{id}` - Update domain (manual only)
- `DELETE /api/domains/{id}` - Delete domain (manual only)
- `POST /api/domains/{id}/resolve` - Manually resolve domain

### IP Management
- `GET /api/ips` - List IPs with filtering
- `POST /api/ips` - Add new IP
- `DELETE /api/ips/{id}` - Delete IP (manual only)

### Settings
- `GET /api/settings` - Get all settings
- `PUT /api/settings/{key}` - Update setting
- `POST /api/settings/firewall/clear` - Clear firewall rules
- `POST /api/settings/firewall/rebuild` - Rebuild rules from database

## 🔒 Security Considerations

### IP Safety Checks
DNSniper automatically filters out:
- Private network IPs (RFC 1918)
- Localhost addresses (127.0.0.1, ::1)
- Null routes (0.0.0.0, ::)
- Server's own public IP
- Gateway and route IPs
- Multicast and reserved ranges

### Entry Management
- **Manual Entries**: Permanent until manually removed (`expired_at = NULL`)
- **Auto-Update Entries**: Expire based on configuration
- **Whitelist Priority**: Whitelist rules processed before blacklist
- **FIFO Limits**: Prevents database bloat from domains with many IPs

## 🚀 Production Deployment

### Systemd Service
The setup script creates a systemd service:

```bash
sudo systemctl start dnsniper
sudo systemctl enable dnsniper
sudo systemctl status dnsniper
```

### Rule Persistence
Ensure firewall rules persist across reboots:

```bash
sudo apt install netfilter-persistent ipset-persistent
sudo netfilter-persistent save
```

### Monitoring
- Check application logs: `sudo journalctl -u dnsniper -f`
- Monitor firewall activity: `sudo tail -f /var/log/kern.log | grep DNSniper`
- View IPSet contents: `sudo ipset list`

## 🔧 Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure the application runs with sudo for firewall access
2. **IPSet Not Found**: Run firewall initialization from Settings
3. **Frontend Not Loading**: Build the frontend with `npm run build`
4. **Database Errors**: Check write permissions in the backend directory

### Debug Mode
Enable debug logging in settings or environment:
```env
LOG_LEVEL=DEBUG
```

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💝 Support the Project

If you find DNSniper helpful, consider supporting its development:

- ⭐ **Star this repository** to show your support
- 🐛 **Report bugs** and suggest improvements
- 📖 **Contribute** to the documentation
- 💰 **Donate** to help maintain and improve DNSniper

**Donation Options:**
- Email: immahdigraph@gmail.com (for donation methods)
- Your support helps keep this project free and open source!

## 🆘 Support

- **Documentation**: Check the `/docs` endpoint when running
- **Issues**: Report bugs on GitHub Issues
- **Community**: Join our discussions

## 🗺️ Roadmap

- [ ] IPv6 auto-update source support
- [ ] Geographic IP blocking
- [ ] Integration with threat intelligence feeds
- [ ] Webhook notifications
- [ ] REST API rate limiting
- [ ] Multi-user support with roles
- [ ] Backup and restore functionality

---

**⚠️ Important**: DNSniper modifies your system's firewall rules. Always test in a development environment first and ensure you have alternative access methods to your server.