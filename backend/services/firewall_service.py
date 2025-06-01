import subprocess
from typing import List, Optional
import ipaddress
from database import SessionLocal
from models import Log
from models.logs import ActionType, RuleType


class FirewallService:
    """Service for managing iptables and ipsets"""
    
    # IPSet names for IPv4
    IPSETS_V4 = {
        "whitelist_ip": "dnsniper-whitelistIP-v4",
        "whitelist_range": "dnsniper-whitelistRange-v4", 
        "blacklist_ip": "dnsniper-blocklistIP-v4",
        "blacklist_range": "dnsniper-blocklistRange-v4"
    }
    
    # IPSet names for IPv6
    IPSETS_V6 = {
        "whitelist_ip": "dnsniper-whitelistIP-v6",
        "whitelist_range": "dnsniper-whitelistRange-v6",
        "blacklist_ip": "dnsniper-blocklistIP-v6", 
        "blacklist_range": "dnsniper-blocklistRange-v6"
    }
    
    # Chain names
    CHAIN_V4 = "DNSniper"
    CHAIN_V6 = "DNSniper6"

    def __init__(self):
        pass

    def run_command(self, command: List[str], check: bool = True) -> subprocess.CompletedProcess:
        """Run a command with error handling"""
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=check)
            if result.returncode != 0:
                db = SessionLocal()
                Log.create_error_log(db, f"Command failed: {' '.join(command)}\nError: {result.stderr}", context="FirewallService", mode="manual")
                Log.cleanup_old_logs(db)
                db.close()
            return result
        except subprocess.CalledProcessError as e:
            db = SessionLocal()
            Log.create_error_log(db, f"Command failed: {' '.join(command)}\nError: {e.stderr}", context="FirewallService", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()
            raise

    def ipset_exists(self, ipset_name: str) -> bool:
        """Check if an IPSet exists"""
        try:
            result = self.run_command(["sudo", "ipset", "list", ipset_name], check=False)
            return result.returncode == 0
        except Exception:
            return False

    def create_ipsets(self):
        """Create all required IPSets"""
        # No logging needed here
        
        # Create IPv4 IPSets
        for ipset_type, ipset_name in self.IPSETS_V4.items():
            if not self.ipset_exists(ipset_name):
                if "range" in ipset_type:
                    self.run_command(["sudo", "ipset", "create", ipset_name, "hash:net", "family", "inet"])
                else:
                    self.run_command(["sudo", "ipset", "create", ipset_name, "hash:ip", "family", "inet"])
        
        # Create IPv6 IPSets
        for ipset_type, ipset_name in self.IPSETS_V6.items():
            if not self.ipset_exists(ipset_name):
                if "range" in ipset_type:
                    self.run_command(["sudo", "ipset", "create", ipset_name, "hash:net", "family", "inet6"])
                else:
                    self.run_command(["sudo", "ipset", "create", ipset_name, "hash:ip", "family", "inet6"])

    def chain_exists(self, chain_name: str, ipv6: bool = False) -> bool:
        """Check if iptables chain exists"""
        try:
            cmd = ["sudo", "ip6tables" if ipv6 else "iptables", "-L", chain_name, "-n"]
            result = self.run_command(cmd, check=False)
            return result.returncode == 0
        except Exception:
            return False

    def create_iptables_chains(self):
        """Create and configure iptables chains"""
        # No logging needed here
        
        # IPv4 Chain
        if not self.chain_exists(self.CHAIN_V4):
            # Create chain
            self.run_command(["sudo", "iptables", "-N", self.CHAIN_V4])
            
            # Insert into main chains
            self.run_command(["sudo", "iptables", "-I", "INPUT", "1", "-j", self.CHAIN_V4])
            self.run_command(["sudo", "iptables", "-I", "FORWARD", "1", "-j", self.CHAIN_V4])
            self.run_command(["sudo", "iptables", "-I", "OUTPUT", "1", "-j", self.CHAIN_V4])
        
        # IPv6 Chain
        if not self.chain_exists(self.CHAIN_V6, ipv6=True):
            # Create chain
            self.run_command(["sudo", "ip6tables", "-N", self.CHAIN_V6])
            
            # Insert into main chains
            self.run_command(["sudo", "ip6tables", "-I", "INPUT", "1", "-j", self.CHAIN_V6])
            self.run_command(["sudo", "ip6tables", "-I", "FORWARD", "1", "-j", self.CHAIN_V6])
            self.run_command(["sudo", "ip6tables", "-I", "OUTPUT", "1", "-j", self.CHAIN_V6])

    def setup_iptables_rules(self):
        """Setup the complete iptables rule structure"""
        # No logging needed here
        
        # IPv4 Rules
        self._setup_ipv4_rules()
        
        # IPv6 Rules
        self._setup_ipv6_rules()

    def _setup_ipv4_rules(self):
        """Setup IPv4 iptables rules"""
        chain = self.CHAIN_V4
        
        # Clear existing rules in chain
        self.run_command(["sudo", "iptables", "-F", chain], check=False)
        
        # Loopback bypass
        self.run_command([
            "sudo", "iptables", "-A", chain, "-i", "lo", "-j", "RETURN"
        ])
        
        # Whitelist rules (process first)
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set", 
            self.IPSETS_V4["whitelist_ip"], "src", "-j", "RETURN"
        ])
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V4["whitelist_range"], "src", "-j", "RETURN"
        ])
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V4["whitelist_ip"], "dst", "-j", "RETURN"
        ])
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V4["whitelist_range"], "dst", "-j", "RETURN"
        ])
        
        # Blocklist rules with logging
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V4["blacklist_ip"], "src", "-j", "LOG", "--log-prefix", "DNSniper DROP_SRC: "
        ])
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V4["blacklist_ip"], "src", "-j", "DROP"
        ])
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V4["blacklist_range"], "src", "-j", "LOG", "--log-prefix", "DNSniper DROP_SRC: "
        ])
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V4["blacklist_range"], "src", "-j", "DROP"
        ])
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V4["blacklist_ip"], "dst", "-j", "LOG", "--log-prefix", "DNSniper DROP_DST: "
        ])
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V4["blacklist_ip"], "dst", "-j", "DROP"
        ])
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V4["blacklist_range"], "dst", "-j", "LOG", "--log-prefix", "DNSniper DROP_DST: "
        ])
        self.run_command([
            "sudo", "iptables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V4["blacklist_range"], "dst", "-j", "DROP"
        ])
        
        # Default return
        self.run_command(["sudo", "iptables", "-A", chain, "-j", "RETURN"])
        
        # Fast path drops (raw table for performance)
        self._setup_raw_table_rules(ipv6=False)

    def _setup_ipv6_rules(self):
        """Setup IPv6 iptables rules"""
        chain = self.CHAIN_V6
        
        # Clear existing rules in chain
        self.run_command(["sudo", "ip6tables", "-F", chain], check=False)
        
        # Loopback bypass
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-i", "lo", "-j", "RETURN"
        ])
        
        # Whitelist rules (process first)
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["whitelist_ip"], "src", "-j", "RETURN"
        ])
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["whitelist_range"], "src", "-j", "RETURN"
        ])
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["whitelist_ip"], "dst", "-j", "RETURN"
        ])
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["whitelist_range"], "dst", "-j", "RETURN"
        ])
        
        # Blocklist rules with logging
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["blacklist_ip"], "src", "-j", "LOG", "--log-prefix", "DNSniper6 DROP_SRC: "
        ])
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["blacklist_ip"], "src", "-j", "DROP"
        ])
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["blacklist_range"], "src", "-j", "LOG", "--log-prefix", "DNSniper6 DROP_SRC: "
        ])
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["blacklist_range"], "src", "-j", "DROP"
        ])
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["blacklist_ip"], "dst", "-j", "LOG", "--log-prefix", "DNSniper6 DROP_DST: "
        ])
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["blacklist_ip"], "dst", "-j", "DROP"
        ])
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["blacklist_range"], "dst", "-j", "LOG", "--log-prefix", "DNSniper6 DROP_DST: "
        ])
        self.run_command([
            "sudo", "ip6tables", "-A", chain, "-m", "set", "--match-set",
            self.IPSETS_V6["blacklist_range"], "dst", "-j", "DROP"
        ])
        
        # Default return
        self.run_command(["sudo", "ip6tables", "-A", chain, "-j", "RETURN"])
        
        # Fast path drops (raw table for performance)
        self._setup_raw_table_rules(ipv6=True)

    def _setup_raw_table_rules(self, ipv6: bool = False):
        """Setup raw table rules for fast packet drops"""
        cmd_prefix = ["sudo", "ip6tables" if ipv6 else "iptables", "-t", "raw"]
        ipsets = self.IPSETS_V6 if ipv6 else self.IPSETS_V4
        
        # Remove existing raw table rules (ignore errors)
        self.run_command(cmd_prefix + ["-D", "PREROUTING", "-m", "set", "--match-set", 
                                      ipsets["blacklist_ip"], "dst", "-j", "DROP"], check=False)
        self.run_command(cmd_prefix + ["-D", "PREROUTING", "-m", "set", "--match-set", 
                                      ipsets["blacklist_range"], "dst", "-j", "DROP"], check=False)
        self.run_command(cmd_prefix + ["-D", "OUTPUT", "-m", "set", "--match-set", 
                                      ipsets["blacklist_ip"], "dst", "-j", "DROP"], check=False)
        self.run_command(cmd_prefix + ["-D", "OUTPUT", "-m", "set", "--match-set", 
                                      ipsets["blacklist_range"], "dst", "-j", "DROP"], check=False)
        
        # Add fast path rules
        self.run_command(cmd_prefix + ["-I", "PREROUTING", "1", "-m", "set", "--match-set", 
                                      ipsets["blacklist_ip"], "dst", "-j", "DROP"])
        self.run_command(cmd_prefix + ["-I", "PREROUTING", "2", "-m", "set", "--match-set", 
                                      ipsets["blacklist_range"], "dst", "-j", "DROP"])
        self.run_command(cmd_prefix + ["-I", "OUTPUT", "1", "-m", "set", "--match-set", 
                                      ipsets["blacklist_ip"], "dst", "-j", "DROP"])
        self.run_command(cmd_prefix + ["-I", "OUTPUT", "2", "-m", "set", "--match-set", 
                                      ipsets["blacklist_range"], "dst", "-j", "DROP"])

    def initialize_firewall(self):
        """Initialize complete firewall setup"""
        try:
            # Create IPSets
            self.create_ipsets()
            
            # Create chains
            self.create_iptables_chains()
            
            # Setup rules
            self.setup_iptables_rules()
            
            # Save rules
            self.save_rules()
            
            db = SessionLocal()
            Log.create_rule_log(db, ActionType.update, None, "Firewall initialization completed successfully", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()
            
        except Exception as e:
            db = SessionLocal()
            Log.create_error_log(db, str(e), context="FirewallService.initialize_firewall", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()
            raise

    def add_ip_to_ipset(self, ip_address: str, list_type: str, ip_version: int):
        """Add IP address to appropriate IPSet"""
        ipsets = self.IPSETS_V6 if ip_version == 6 else self.IPSETS_V4
        ipset_name = ipsets[f"{list_type}_ip"]
        
        try:
            self.run_command(["sudo", "ipset", "add", ipset_name, ip_address], check=False)
        except Exception as e:
            db = SessionLocal()
            Log.create_error_log(db, f"Failed to add IP {ip_address} to {ipset_name}: {e}", context="FirewallService.add_ip_to_ipset", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()

    def remove_ip_from_ipset(self, ip_address: str, list_type: str, ip_version: int):
        """Remove IP address from IPSet"""
        ipsets = self.IPSETS_V6 if ip_version == 6 else self.IPSETS_V4
        ipset_name = ipsets[f"{list_type}_ip"]
        
        try:
            self.run_command(["sudo", "ipset", "del", ipset_name, ip_address], check=False)
        except Exception as e:
            db = SessionLocal()
            Log.create_error_log(db, f"Failed to remove IP {ip_address} from {ipset_name}: {e}", context="FirewallService.remove_ip_from_ipset", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()

    def add_ip_range_to_ipset(self, ip_range: str, list_type: str, ip_version: int):
        """Add IP range to appropriate IPSet"""
        ipsets = self.IPSETS_V6 if ip_version == 6 else self.IPSETS_V4
        ipset_name = ipsets[f"{list_type}_range"]
        
        try:
            self.run_command(["sudo", "ipset", "add", ipset_name, ip_range], check=False)
        except Exception as e:
            db = SessionLocal()
            Log.create_error_log(db, f"Failed to add IP range {ip_range} to {ipset_name}: {e}", context="FirewallService.add_ip_range_to_ipset", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()

    def remove_ip_range_from_ipset(self, ip_range: str, list_type: str, ip_version: int):
        """Remove IP range from IPSet"""
        ipsets = self.IPSETS_V6 if ip_version == 6 else self.IPSETS_V4
        ipset_name = ipsets[f"{list_type}_range"]
        
        try:
            self.run_command(["sudo", "ipset", "del", ipset_name, ip_range], check=False)
        except Exception as e:
            db = SessionLocal()
            Log.create_error_log(db, f"Failed to remove IP range {ip_range} from {ipset_name}: {e}", context="FirewallService.remove_ip_range_from_ipset", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()

    def clear_all_rules(self):
        """Clear all DNSniper firewall rules and ipsets completely"""
        try:
            # Step 1: Remove raw table rules first (to prevent blocking packets)
            for ipsets in [self.IPSETS_V4, self.IPSETS_V6]:
                cmd_prefix = ["sudo", "ip6tables" if ipsets == self.IPSETS_V6 else "iptables", "-t", "raw"]
                # Remove PREROUTING rules
                self.run_command(cmd_prefix + ["-D", "PREROUTING", "-m", "set", "--match-set", 
                                              ipsets["blacklist_ip"], "dst", "-j", "DROP"], check=False)
                self.run_command(cmd_prefix + ["-D", "PREROUTING", "-m", "set", "--match-set", 
                                              ipsets["blacklist_range"], "dst", "-j", "DROP"], check=False)
                # Remove OUTPUT rules
                self.run_command(cmd_prefix + ["-D", "OUTPUT", "-m", "set", "--match-set", 
                                              ipsets["blacklist_ip"], "dst", "-j", "DROP"], check=False)
                self.run_command(cmd_prefix + ["-D", "OUTPUT", "-m", "set", "--match-set", 
                                              ipsets["blacklist_range"], "dst", "-j", "DROP"], check=False)
            # Step 2: Remove chain references from main chains
            # IPv4 chain references
            self.run_command(["sudo", "iptables", "-D", "INPUT", "-j", self.CHAIN_V4], check=False)
            self.run_command(["sudo", "iptables", "-D", "FORWARD", "-j", self.CHAIN_V4], check=False)
            self.run_command(["sudo", "iptables", "-D", "OUTPUT", "-j", self.CHAIN_V4], check=False)
            # IPv6 chain references
            self.run_command(["sudo", "ip6tables", "-D", "INPUT", "-j", self.CHAIN_V6], check=False)
            self.run_command(["sudo", "ip6tables", "-D", "FORWARD", "-j", self.CHAIN_V6], check=False)
            self.run_command(["sudo", "ip6tables", "-D", "OUTPUT", "-j", self.CHAIN_V6], check=False)
            # Step 3: Flush and delete chains
            # IPv4 chain
            if self.chain_exists(self.CHAIN_V4):
                self.run_command(["sudo", "iptables", "-F", self.CHAIN_V4], check=False)
                self.run_command(["sudo", "iptables", "-X", self.CHAIN_V4], check=False)
            # IPv6 chain
            if self.chain_exists(self.CHAIN_V6, ipv6=True):
                self.run_command(["sudo", "ip6tables", "-F", self.CHAIN_V6], check=False)
                self.run_command(["sudo", "ip6tables", "-X", self.CHAIN_V6], check=False)
            # Step 4: Destroy all DNSniper IPSets
            all_ipsets = list(self.IPSETS_V4.values()) + list(self.IPSETS_V6.values())
            for ipset_name in all_ipsets:
                if self.ipset_exists(ipset_name):
                    # Flush the ipset first
                    self.run_command(["sudo", "ipset", "flush", ipset_name], check=False)
                    # Then destroy it
                    self.run_command(["sudo", "ipset", "destroy", ipset_name], check=False)
            # Step 5: Save the configuration to disk
            self.save_rules()
            db = SessionLocal()
            Log.create_rule_log(db, ActionType.update, None, "All DNSniper firewall rules and ipsets cleared successfully", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()
        except Exception as e:
            db = SessionLocal()
            Log.create_error_log(db, str(e), context="FirewallService.clear_all_rules", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()
            raise

    def rebuild_rules_from_database(self, db):
        """Rebuild all firewall rules from database"""
        from models import Domain, IP, IPRange
        
        # Clear existing rules
        self.clear_all_rules()
        
        # Reinitialize firewall
        self.initialize_firewall()
        
        # Add all IPs from database
        ips = db.query(IP).all()
        for ip in ips:
            if not ip.is_expired():
                self.add_ip_to_ipset(ip.ip_address, ip.list_type.value, ip.ip_version)
        
        # Add all IP ranges from database
        ip_ranges = db.query(IPRange).all()
        for ip_range in ip_ranges:
            if not ip_range.is_expired():
                self.add_ip_range_to_ipset(ip_range.ip_range, ip_range.list_type.value, ip_range.ip_version)
        
        # Save rules
        self.save_rules()

    def save_rules(self):
        """Save iptables and ipsets rules to disk for persistence"""
        try:
            self.run_command(["sudo", "netfilter-persistent", "save"], check=False)
        except Exception as e:
            db = SessionLocal()
            Log.create_error_log(db, f"Failed to save rules to disk: {e}", context="FirewallService.save_rules", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()

    def get_status(self) -> dict:
        """Get firewall status information"""
        status = {
            "chains_exist": {
                "ipv4": self.chain_exists(self.CHAIN_V4),
                "ipv6": self.chain_exists(self.CHAIN_V6, ipv6=True)
            },
            "ipsets_exist": {
                "ipv4": {},
                "ipv6": {}
            },
            "ipset_counts": {
                "ipv4": {},
                "ipv6": {}
            }
        }
        
        # Check IPv4 IPSets
        for name, ipset_name in self.IPSETS_V4.items():
            status["ipsets_exist"]["ipv4"][name] = self.ipset_exists(ipset_name)
            
            # Get entry count
            if status["ipsets_exist"]["ipv4"][name]:
                try:
                    result = self.run_command(["sudo", "ipset", "list", ipset_name, "-t"], check=False)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        # Look for "Number of entries: X"
                        for line in lines:
                            if "Number of entries:" in line:
                                count = int(line.split(":")[-1].strip())
                                status["ipset_counts"]["ipv4"][name] = count
                                break
                        else:
                            status["ipset_counts"]["ipv4"][name] = 0
                    else:
                        status["ipset_counts"]["ipv4"][name] = 0
                except Exception:
                    status["ipset_counts"]["ipv4"][name] = 0
            else:
                status["ipset_counts"]["ipv4"][name] = 0
        
        # Check IPv6 IPSets
        for name, ipset_name in self.IPSETS_V6.items():
            status["ipsets_exist"]["ipv6"][name] = self.ipset_exists(ipset_name)
            
            # Get entry count
            if status["ipsets_exist"]["ipv6"][name]:
                try:
                    result = self.run_command(["sudo", "ipset", "list", ipset_name, "-t"], check=False)
                    if result.returncode == 0:
                        lines = result.stdout.strip().split('\n')
                        # Look for "Number of entries: X"
                        for line in lines:
                            if "Number of entries:" in line:
                                count = int(line.split(":")[-1].strip())
                                status["ipset_counts"]["ipv6"][name] = count
                                break
                        else:
                            status["ipset_counts"]["ipv6"][name] = 0
                    else:
                        status["ipset_counts"]["ipv6"][name] = 0
                except Exception:
                    status["ipset_counts"]["ipv6"][name] = 0
            else:
                status["ipset_counts"]["ipv6"][name] = 0
        
        return status 