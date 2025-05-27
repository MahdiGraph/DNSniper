# DNSniper v2.1 - Debugging Guide

## Common Issues and Solutions

### 1. IPTables Rules Application Failed

**Error**: `failed to apply iptables rules, backup restored: exit status 1`

**Possible Causes**:
1. **Missing iptables modules**: Some iptables modules might not be loaded
2. **Permission issues**: DNSniper needs root privileges
3. **Conflicting rules**: Existing firewall rules might conflict
4. **Missing ipset support**: Kernel doesn't support ipset module

**Solutions**:

#### Check Required Modules
```bash
# Check if ipset module is loaded
lsmod | grep ip_set

# Load ipset module if missing
modprobe ip_set
modprobe ip_set_hash_ip
modprobe ip_set_hash_net

# Check iptables modules
lsmod | grep iptable
```

#### Verify IPSet Support
```bash
# Test ipset functionality
ipset create test-set hash:ip
ipset add test-set 192.168.1.1
ipset list test-set
ipset destroy test-set
```

#### Check Current IPTables Rules
```bash
# View current rules
iptables -L -n -v
ip6tables -L -n -v

# Check for conflicts
iptables-save
ip6tables-save
```

#### Manual Rule Testing
```bash
# Test a simple ipset rule manually
ipset create dnsniper-test hash:ip
iptables -A INPUT -m set --match-set dnsniper-test src -j ACCEPT
iptables -D INPUT -m set --match-set dnsniper-test src -j ACCEPT
ipset destroy dnsniper-test
```

### 2. System Initialization Issues

**Error**: `System initialization failed`

**Debug Steps**:

1. **Run with verbose logging**:
   ```bash
   sudo dnsniper-agent --verbose
   ```

2. **Check system requirements**:
   ```bash
   # Check if running as root
   whoami
   
   # Check required commands
   which ipset iptables ip6tables
   
   # Check kernel version
   uname -r
   ```

3. **Check directory permissions**:
   ```bash
   ls -la /etc/dnsniper/
   ls -la /var/log/dnsniper/
   ls -la /etc/iptables/
   ```

### 3. IPSet Creation Issues

**Error**: `failed to create ipset`

**Solutions**:

1. **Check ipset version**:
   ```bash
   ipset --version
   ```

2. **Test ipset manually**:
   ```bash
   # Test IPv4 hash:ip
   ipset create test-ip-v4 hash:ip family inet
   ipset destroy test-ip-v4
   
   # Test IPv6 hash:ip
   ipset create test-ip-v6 hash:ip family inet6
   ipset destroy test-ip-v6
   
   # Test IPv4 hash:net
   ipset create test-net-v4 hash:net family inet
   ipset destroy test-net-v4
   ```

3. **Check existing ipsets**:
   ```bash
   ipset list -n | grep dnsniper
   ```

### 4. Configuration Issues

**Error**: `Failed to load configuration`

**Solutions**:

1. **Check config file**:
   ```bash
   cat /etc/dnsniper/config.yaml
   ```

2. **Validate YAML syntax**:
   ```bash
   # Install yamllint if available
   yamllint /etc/dnsniper/config.yaml
   ```

3. **Reset to default config**:
   ```bash
   sudo rm /etc/dnsniper/config.yaml
   sudo dnsniper  # Will recreate default config
   ```

### 5. Database Issues

**Error**: `Failed to initialize database`

**Solutions**:

1. **Check database file**:
   ```bash
   ls -la /etc/dnsniper/dnsniper.db
   ```

2. **Check directory permissions**:
   ```bash
   sudo chown -R root:root /etc/dnsniper/
   sudo chmod 755 /etc/dnsniper/
   sudo chmod 644 /etc/dnsniper/dnsniper.db
   ```

3. **Reset database**:
   ```bash
   sudo rm /etc/dnsniper/dnsniper.db
   sudo dnsniper-agent --verbose  # Will recreate database
   ```

## Manual Testing Commands

### Test IPSet Functionality
```bash
# Create test ipsets
sudo ipset create dnsniper-whitelist-ip-v4 hash:ip family inet
sudo ipset create dnsniper-blocklist-ip-v4 hash:ip family inet

# Add test entries
sudo ipset add dnsniper-whitelist-ip-v4 8.8.8.8
sudo ipset add dnsniper-blocklist-ip-v4 1.2.3.4

# Test iptables rules
sudo iptables -A INPUT -m set --match-set dnsniper-whitelist-ip-v4 src -j ACCEPT
sudo iptables -A INPUT -m set --match-set dnsniper-blocklist-ip-v4 src -j DROP

# Check rules
sudo iptables -L -n | grep dnsniper

# Cleanup
sudo iptables -D INPUT -m set --match-set dnsniper-whitelist-ip-v4 src -j ACCEPT
sudo iptables -D INPUT -m set --match-set dnsniper-blocklist-ip-v4 src -j DROP
sudo ipset destroy dnsniper-whitelist-ip-v4
sudo ipset destroy dnsniper-blocklist-ip-v4
```

### Test Rules File Generation
```bash
# Check generated rules
cat /etc/iptables/rules.v4
cat /etc/iptables/rules.v6

# Test rules application
sudo iptables-restore --test < /etc/iptables/rules.v4
sudo ip6tables-restore --test < /etc/iptables/rules.v6
```

## System Requirements

### Minimum Requirements
- Linux kernel 3.10+
- iptables 1.4+
- ipset 6.0+
- Root privileges

### Required Kernel Modules
- ip_tables
- ip_set
- ip_set_hash_ip
- ip_set_hash_net
- xt_set

### Required Packages (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install iptables ipset iptables-persistent netfilter-persistent
```

### Required Packages (RHEL/CentOS)
```bash
sudo yum install iptables ipset iptables-services
# or
sudo dnf install iptables ipset iptables-services
```

## Logs and Debugging

### Check System Logs
```bash
# DNSniper logs
sudo journalctl -u dnsniper-agent.service -f

# System logs
sudo dmesg | grep -i iptables
sudo dmesg | grep -i ipset

# Check for kernel module issues
sudo dmesg | grep -i "module"
```

### Enable Debug Logging
```bash
# Run agent with verbose output
sudo dnsniper-agent --verbose

# Check specific log files
sudo tail -f /var/log/dnsniper/*.log
```

### Test System Components
```bash
# Test script
sudo ./scripts/test-system.sh
```

## Getting Help

If you're still experiencing issues:

1. **Run the test script**: `sudo ./scripts/test-system.sh`
2. **Collect debug info**: `sudo dnsniper-agent --verbose > debug.log 2>&1`
3. **Check system compatibility**: Ensure all requirements are met
4. **Review logs**: Check both DNSniper and system logs

## Workaround for Rule Application Issues

If iptables rule application continues to fail, you can still use DNSniper with manual rule management:

1. **Initialize system without rules**:
   ```bash
   sudo dnsniper-agent --verbose
   # This will create ipsets even if rule application fails
   ```

2. **Manually rebuild rules later**:
   ```bash
   sudo dnsniper
   # Choose option 7: "Rebuild firewall rules"
   ```

3. **Check ipsets are working**:
   ```bash
   sudo ipset list | grep dnsniper
   ```

The ipsets will be created and populated correctly, and you can manually manage iptables rules if needed. 