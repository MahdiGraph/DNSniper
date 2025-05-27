# DNSniper v2.1 - Major System Improvements

## 🚀 Major Changes

### 1. Enhanced IPSet Management
- **Standardized Naming**: All ipsets now use `dnsniper-` prefix for better organization
- **Improved Isolation**: Clear separation between DNSniper and system ipsets
- **Better Cleanup**: Complete removal of DNSniper ipsets during uninstall

### 2. Database-IPSet Synchronization System
- **Real-time Sync**: New sync manager ensures database and ipsets are always in sync
- **Automatic Validation**: Built-in validation to detect and fix inconsistencies
- **Priority Protection**: Whitelist entries always take precedence over blocklist

### 3. Improved Firewall Rule Management
- **Direct File Writing**: Rules are written directly to `/etc/iptables/rules.v4` and `/etc/iptables/rules.v6`
- **Rule Preservation**: Existing non-DNSniper rules are preserved during updates
- **Proper Ordering**: Whitelist rules are always processed before blocklist rules
- **Automatic Persistence**: Rules are automatically saved for reboot persistence

### 4. Enhanced Installer
- **Better Cleanup**: Improved uninstall process removes all DNSniper components
- **Robust Detection**: Better detection and removal of existing installations
- **Error Recovery**: Enhanced error handling and recovery mechanisms

## 🔧 Technical Improvements

### IPSet Names
Old format: `whitelistIP-v4`, `blocklistIP-v4`
New format: `dnsniper-whitelist-ip-v4`, `dnsniper-blocklist-ip-v4`

### Sync System
- Replaces the old expiration-based system
- Ensures real-time consistency between database and firewall
- Automatic cleanup of orphaned entries

### Rule Generation
- Direct integration with iptables persistence files
- Proper IPv4/IPv6 separation
- Comment-based rule identification for easier management

## 🛡️ Security Enhancements

### Whitelist Priority
- Whitelist rules are always processed first
- Prevents accidental blocking of whitelisted IPs
- Clear separation between whitelist and blocklist logic

### Rule Validation
- Automatic validation of ipset existence before rule creation
- Backup and restore functionality for rule application
- Error recovery mechanisms

## 📋 Migration Notes

### For Existing Installations
1. The installer will automatically detect and upgrade existing installations
2. Old ipsets will be migrated to new naming convention
3. Database structure remains compatible

### For Wireguard Servers
- Perfect for Wireguard server environments
- No DNS dependency for blocking (uses direct IP blocking)
- Efficient filtering for both server and client traffic
- Minimal performance impact

## 🔄 Upgrade Process

### Automatic Upgrade
```bash
curl -fsSL https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/scripts/installer.sh | sudo bash
```

### Manual Upgrade
```bash
wget https://raw.githubusercontent.com/MahdiGraph/DNSniper/main/scripts/installer.sh
chmod +x installer.sh
sudo ./installer.sh
```

The installer will:
1. Detect existing installation
2. Offer upgrade option
3. Migrate ipsets to new naming
4. Update firewall rules
5. Start new sync system

## 🐛 Bug Fixes

- Fixed ipset duplication issues
- Resolved rule ordering problems
- Improved error handling in agent
- Better resource cleanup
- Enhanced logging and monitoring

## ⚠️ Breaking Changes

### IPSet Names
If you have custom scripts that reference the old ipset names, you'll need to update them:
- `whitelistIP-v4` → `dnsniper-whitelist-ip-v4`
- `blocklistIP-v4` → `dnsniper-blocklist-ip-v4`
- Similar changes for v6 and range sets

### Configuration
- Removed `rule_expiration` dependency (now uses sync system)
- Enhanced database-firewall integration
- Improved agent scheduling and execution

## 📊 Performance Improvements

- Faster sync operations
- Reduced memory usage
- Better CPU efficiency
- Optimized database queries
- Improved rule application speed

## 🔮 Future Roadmap

- Web-based management interface
- API endpoints for remote management
- Advanced analytics and reporting
- Integration with threat intelligence feeds
- Support for additional firewall backends

---

**Note**: This update significantly improves the reliability and performance of DNSniper, especially in Wireguard server environments where DNS-based filtering is not suitable. 