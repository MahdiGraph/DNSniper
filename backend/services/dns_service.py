import dns.resolver
import dns.exception
import ipaddress
from typing import List, Set, Optional
import socket
import urllib.request
import subprocess
from database import SessionLocal
from models import Log
from models.logs import ActionType


class DNSService:
    """Service for DNS resolution with safety checks"""
    
    def __init__(self, dns_resolver_primary: str = None, dns_resolver_secondary: str = None):
        self.dns_resolver_primary = dns_resolver_primary or "1.1.1.1"
        self.dns_resolver_secondary = dns_resolver_secondary or "8.8.8.8"
        self.resolvers = []
        for resolver_ip in [self.dns_resolver_primary, self.dns_resolver_secondary]:
            r = dns.resolver.Resolver()
            r.nameservers = [resolver_ip]
            r.timeout = 5.0
            r.lifetime = 10.0
            self.resolvers.append(r)
        # Cache for server's own IP
        self._server_ips = set()
        self._update_server_ips()

    def _update_server_ips(self):
        """Update cache of server's own IP addresses"""
        try:
            # Get local IP addresses
            hostname = socket.gethostname()
            local_ips = socket.gethostbyname_ex(hostname)[2]
            for ip in local_ips:
                self._server_ips.add(ip)
                
            # Get default route IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self._server_ips.add(s.getsockname()[0])
            s.close()
            
        except Exception as e:
            # Log warning through database if possible
            try:
                db = SessionLocal()
                Log.create_error_log(db, f"Could not determine server IPs: {e}", context="DNSService._update_server_ips", mode="manual")
                Log.cleanup_old_logs(db)
                db.close()
            except:
                pass  # Fail silently if logging is not available

    def _get_dynamic_critical_ips(self, db_session=None) -> dict:
        """Detect dynamic critical IPs at runtime (not stored in database)"""
        dynamic_ips = {
            'ipv4': set(),
            'ipv6': set()
        }
        
        try:
            # Get DNS resolver IPs from settings
            if db_session:
                from models import Setting
                dns_primary = Setting.get_setting(db_session, "dns_resolver_primary", "1.1.1.1")
                dns_secondary = Setting.get_setting(db_session, "dns_resolver_secondary", "8.8.8.8")
                
                # Add configured DNS servers to dynamic protection
                dynamic_ips['ipv4'].add(dns_primary)
                dynamic_ips['ipv4'].add(dns_secondary)
            
            # Get current local IP and derive network
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                s.close()
                dynamic_ips['ipv4'].add(local_ip)
                
                # Try to detect current network range
                result = subprocess.run(['ip', 'route', 'show'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if local_ip in line and '/' in line:
                        parts = line.split()
                        for part in parts:
                            if '/' in part and '.' in part:
                                try:
                                    network = ipaddress.IPv4Network(part, strict=False)
                                    dynamic_ips['ipv4'].add(str(network))
                                except:
                                    pass
            except:
                pass
            
            # Get gateway IP
            try:
                result = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'via ' in line:
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == 'via' and i + 1 < len(parts):
                                gateway_ip = parts[i + 1]
                                try:
                                    ipaddress.IPv4Address(gateway_ip)
                                    dynamic_ips['ipv4'].add(gateway_ip)
                                except:
                                    pass
            except:
                pass
            
            # Get public IP (quietly, no logging)
            try:
                services = ['https://ipv4.icanhazip.com', 'https://api.ipify.org']
                for service in services:
                    try:
                        with urllib.request.urlopen(service, timeout=3) as response:
                            ip = response.read().decode().strip()
                            try:
                                ipaddress.IPv4Address(ip)
                                dynamic_ips['ipv4'].add(ip)
                                break
                            except:
                                pass
                    except:
                        continue
            except:
                pass
                
        except Exception as e:
            # Fail silently - dynamic detection is optional
            pass
        
        # Convert to lists and return
        return {
            'ipv4': list(dynamic_ips['ipv4']),
            'ipv6': list(dynamic_ips['ipv6'])
        }

    def is_critical_ip(self, ip_str: str, critical_ipv4_list: List[str] = None, critical_ipv6_list: List[str] = None, db_session=None) -> bool:
        """Check if IP is in critical IPs list or ranges (for auto-update protection)"""
        
        # Get dynamic critical IPs at runtime
        dynamic_critical = self._get_dynamic_critical_ips(db_session)
        
        # Ensure critical IP lists are actually lists (they might be None or strings)
        if critical_ipv4_list is None:
            critical_ipv4_list = []
        elif isinstance(critical_ipv4_list, str):
            try:
                import json
                critical_ipv4_list = json.loads(critical_ipv4_list)
            except:
                critical_ipv4_list = []
        
        if critical_ipv6_list is None:
            critical_ipv6_list = []
        elif isinstance(critical_ipv6_list, str):
            try:
                import json
                critical_ipv6_list = json.loads(critical_ipv6_list)
            except:
                critical_ipv6_list = []
        
        # Combine static (from database) with dynamic (runtime detection)
        combined_ipv4_list = list(critical_ipv4_list) + list(dynamic_critical['ipv4'])
        combined_ipv6_list = list(critical_ipv6_list) + list(dynamic_critical['ipv6'])
        
        if not combined_ipv4_list and not combined_ipv6_list:
            return False
            
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            
            # Determine which list to check based on IP version
            if ip_obj.version == 4:
                critical_list = combined_ipv4_list
            elif ip_obj.version == 6:
                critical_list = combined_ipv6_list
            else:
                return False
            
            # Check against critical IPs and ranges
            for item in critical_list:
                try:
                    # Try as IP address first
                    if str(ip_obj) == item:
                        # Log critical IP protection through database
                        try:
                            db = SessionLocal()
                            Log.create_rule_log(db, ActionType.update, None, f"IP {ip_str} is in critical IPs list - skipping auto-block", mode="auto_update")
                            Log.cleanup_old_logs(db)
                            db.close()
                        except:
                            pass
                        return True
                except:
                    pass
                
                try:
                    # Try as network/CIDR range
                    network = ipaddress.ip_network(item, strict=False)
                    if ip_obj in network:
                        # Log critical IP protection through database
                        try:
                            db = SessionLocal()
                            Log.create_rule_log(db, ActionType.update, None, f"IP {ip_str} is in critical IP range {item} - skipping auto-block", mode="auto_update")
                            Log.cleanup_old_logs(db)
                            db.close()
                        except:
                            pass
                        return True
                except ValueError:
                    # Log invalid critical IP format through database
                    try:
                        db = SessionLocal()
                        Log.create_error_log(db, f"Invalid critical IP item format: {item}", context="DNSService.is_critical_ip", mode="auto_update")
                        Log.cleanup_old_logs(db)
                        db.close()
                    except:
                        pass
                    continue
            
            return False
        except ValueError:
            return False

    def is_safe_ip(self, ip_str: str) -> bool:
        """Check if IP is safe to block (not private, localhost, server IP, etc.)"""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            
            # Skip private networks
            if ip_obj.is_private:
                return False
            
            # Skip localhost
            if ip_obj.is_loopback:
                return False
            
            # Skip null route
            if str(ip_obj) == "0.0.0.0" or str(ip_obj) == "::":
                return False
            
            # Skip multicast and reserved
            if hasattr(ip_obj, 'is_multicast') and ip_obj.is_multicast:
                return False
            
            if hasattr(ip_obj, 'is_reserved') and ip_obj.is_reserved:
                return False
            
            # Skip server's own IPs
            if ip_str in self._server_ips:
                return False
            
            return True
        except ValueError:
            return False

    def is_safe_ip_for_auto_update(self, ip_str: str, critical_ipv4_list: List[str] = None, critical_ipv6_list: List[str] = None, db_session=None) -> bool:
        """Check if IP is safe to block during auto-update (includes critical IP protection)"""
        # First check basic safety
        if not self.is_safe_ip(ip_str):
            return False
        
        # Then check if it's a critical IP that should be protected from auto-blocking
        if self.is_critical_ip(ip_str, critical_ipv4_list, critical_ipv6_list, db_session):
            return False
        
        return True

    def resolve_domain(self, domain: str, record_types: List[str] = None) -> dict:
        """
        Resolve domain to IP addresses
        Returns dict with IPv4 and IPv6 addresses
        """
        if record_types is None:
            record_types = ['A', 'AAAA']
        
        result = {
            'ipv4': set(),
            'ipv6': set(),
            'errors': []
        }
        
        # Clean domain name
        domain = domain.strip().lower()
        if domain.startswith('*.'):
            domain = domain[2:]  # Remove wildcard
        
        try:
            for record_type in record_types:
                answered = False
                for resolver in self.resolvers:
                    try:
                        answers = resolver.resolve(domain, record_type)
                        for rdata in answers:
                            ip_str = str(rdata)
                            # Validate and categorize IP
                            if self.is_safe_ip(ip_str):
                                try:
                                    ip_obj = ipaddress.ip_address(ip_str)
                                    if ip_obj.version == 4:
                                        result['ipv4'].add(ip_str)
                                    elif ip_obj.version == 6:
                                        result['ipv6'].add(ip_str)
                                except ValueError:
                                    continue
                            else:
                                # Log debug info through database if needed
                                # self.logger.debug(f"Skipped unsafe IP {ip_str} for domain {domain}")
                                pass
                        answered = True
                        break  # Stop after first successful resolver
                    except dns.exception.DNSException as e:
                        last_error = f"{record_type}: {str(e)}"
                        continue
                if not answered:
                    result['errors'].append(last_error)
        except Exception as e:
            result['errors'].append(f"General error: {str(e)}")
            # Log error through database
            try:
                db = SessionLocal()
                Log.create_error_log(db, f"DNS resolution failed for {domain}: {e}", context="DNSService.resolve_domain", mode="auto_update")
                Log.cleanup_old_logs(db)
                db.close()
            except:
                pass
        
        # Convert sets to lists for JSON serialization
        result['ipv4'] = list(result['ipv4'])
        result['ipv6'] = list(result['ipv6'])
        
        return result

    def resolve_multiple_domains(self, domains: List[str]) -> dict:
        """Resolve multiple domains efficiently"""
        results = {}
        
        for domain in domains:
            results[domain] = self.resolve_domain(domain)
            
        return results

    def test_dns_servers(self) -> dict:
        """Test connectivity to configured DNS servers"""
        results = {}
        test_domain = "google.com"
        
        for dns_server in [self.dns_resolver_primary, self.dns_resolver_secondary]:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [dns_server]
                resolver.timeout = 3.0
                resolver.lifetime = 5.0
                
                start_time = dns.resolver.time.time()
                answers = resolver.resolve(test_domain, 'A')
                end_time = dns.resolver.time.time()
                
                results[dns_server] = {
                    'status': 'working',
                    'response_time': round((end_time - start_time) * 1000, 2),
                    'resolved_ips': [str(rdata) for rdata in answers]
                }
                
            except Exception as e:
                results[dns_server] = {
                    'status': 'failed',
                    'error': str(e)
                }
        
        return results

    def update_dns_servers(self, dns_servers: List[str]):
        """Update DNS servers configuration"""
        self.dns_resolver_primary = dns_servers[0]
        self.dns_resolver_secondary = dns_servers[1]
        self.resolvers = []
        for resolver_ip in [self.dns_resolver_primary, self.dns_resolver_secondary]:
            r = dns.resolver.Resolver()
            r.nameservers = [resolver_ip]
            r.timeout = 5.0
            r.lifetime = 10.0
            self.resolvers.append(r)
        
        # Log DNS server update through database
        try:
            db = SessionLocal()
            Log.create_rule_log(db, ActionType.update, None, f"Updated DNS servers to: {dns_servers}", mode="manual")
            Log.cleanup_old_logs(db)
            db.close()
        except:
            pass

    def get_domain_info(self, domain: str) -> dict:
        """Get comprehensive domain information"""
        info = {
            'domain': domain,
            'resolution': self.resolve_domain(domain),
            'mx_records': [],
            'txt_records': [],
            'ns_records': []
        }
        
        # Get additional records
        for record_type in ['MX', 'TXT', 'NS']:
            try:
                answers = self.resolvers[0].resolve(domain, record_type)
                records = []
                for rdata in answers:
                    if record_type == 'MX':
                        records.append(f"{rdata.preference} {rdata.exchange}")
                    else:
                        records.append(str(rdata))
                info[f"{record_type.lower()}_records"] = records
            except dns.exception.DNSException:
                info[f"{record_type.lower()}_records"] = []
        
        return info 