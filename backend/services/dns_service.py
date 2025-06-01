import dns.resolver
import dns.exception
import ipaddress
import logging
from typing import List, Set, Optional
import socket


class DNSService:
    """Service for DNS resolution with safety checks"""
    
    def __init__(self, dns_resolver_primary: str = None, dns_resolver_secondary: str = None):
        self.logger = logging.getLogger(__name__)
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
            self.logger.warning(f"Could not determine server IPs: {e}")

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
                                self.logger.debug(f"Skipped unsafe IP {ip_str} for domain {domain}")
                        answered = True
                        break  # Stop after first successful resolver
                    except dns.exception.DNSException as e:
                        last_error = f"{record_type}: {str(e)}"
                        continue
                if not answered:
                    result['errors'].append(last_error)
        except Exception as e:
            result['errors'].append(f"General error: {str(e)}")
            self.logger.error(f"DNS resolution failed for {domain}: {e}")
        
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
        self.logger.info(f"Updated DNS servers to: {dns_servers}")

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