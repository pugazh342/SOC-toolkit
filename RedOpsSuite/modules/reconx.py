# RedOpsSuite/modules/reconx.py
import socket
import whois
import dns.resolver
import ipaddress
# Use standard logging for standalone capability
import logging

# --- Setup basic logging for standalone execution ---
# Create a logger specific to this module
logger = logging.getLogger(__name__)
# Prevent propagation to root logger if run standalone
logger.propagate = False
# Set initial level (can be overridden by calling script or config)
logger.setLevel(logging.DEBUG)

# Prevent adding multiple handlers if module is re-imported
if not logger.handlers:
    # Create console handler
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG) # Set handler level
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    # Add handler to logger
    logger.addHandler(ch)
# --- End logging setup ---

class ReconX:
    """
    Basic reconnaissance module for RedOpsSuite.
    Performs domain/IP lookups, Whois queries, and basic DNS enumeration.
    """

    def __init__(self):
        """
        Initializes the ReconX module.
        Sets up internal logging.
        """
        # Use the module-specific logger
        self.logger = logger
        self.logger.info("ReconX module initialized.")

    def resolve_domain(self, domain):
        """
        Resolves a domain name to its IP address(es).

        Args:
            domain (str): The domain name to resolve.

        Returns:
            dict: A dictionary containing the domain, resolved IPs, and status.
        """
        result = {
            "type": "resolve_domain",
            "target": domain,
            "ips": [],
            "status": "unknown",
            "error": None
        }
        try:
            # socket.gethostbyname only returns one IP (usually A record)
            # For multiple IPs or IPv6, use socket.getaddrinfo
            # ips = socket.gethostbyname(domain) # Returns single IP string
            # Using getaddrinfo for potentially multiple addresses
            addrinfos = socket.getaddrinfo(domain, None) # port=None
            ips = list(set(info[4][0] for info in addrinfos)) # Extract IP, remove duplicates
            result["ips"] = ips
            result["status"] = "success"
            self.logger.info(f"ReconX: Resolved domain '{domain}' to IPs: {ips}")
        except socket.gaierror as e:
            result["status"] = "error"
            result["error"] = f"DNS resolution failed: {str(e)}"
            self.logger.error(f"ReconX: DNS resolution failed for '{domain}': {e}")
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"Unexpected error during DNS resolution: {str(e)}"
            self.logger.error(f"ReconX: Unexpected error resolving '{domain}': {e}", exc_info=True)
        return result

    def reverse_lookup(self, ip_address):
        """
        Performs a reverse DNS lookup for an IP address.

        Args:
            ip_address (str): The IP address to lookup.

        Returns:
            dict: A dictionary containing the IP, resolved hostname, and status.
        """
        result = {
            "type": "reverse_lookup",
            "target": ip_address,
            "hostname": None,
            "status": "unknown",
            "error": None
        }
        try:
            # Validate IP address format
            ip_obj = ipaddress.ip_address(ip_address)
            hostname = socket.gethostbyaddr(str(ip_obj))[0]
            result["hostname"] = hostname
            result["status"] = "success"
            self.logger.info(f"ReconX: Reverse lookup for IP '{ip_address}' resolved to hostname: {hostname}")
        except ValueError as e:
            result["status"] = "error"
            result["error"] = f"Invalid IP address format: {str(e)}"
            self.logger.error(f"ReconX: Invalid IP address for reverse lookup '{ip_address}': {e}")
        except socket.herror as e:
            result["status"] = "error"
            result["error"] = f"Reverse DNS lookup failed: No hostname found for {ip_address} ({str(e)})"
            self.logger.warning(f"ReconX: Reverse DNS lookup failed for '{ip_address}': {e}")
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"Unexpected error during reverse lookup: {str(e)}"
            self.logger.error(f"ReconX: Unexpected error during reverse lookup for '{ip_address}': {e}", exc_info=True)
        return result

    def whois_lookup(self, domain):
        """
        Performs a Whois lookup for a domain.

        Args:
            domain (str): The domain name to lookup.

        Returns:
            dict: A dictionary containing Whois data and status.
        """
        result = {
            "type": "whois_lookup",
            "target": domain,
            "data": {},
            "status": "unknown",
            "error": None
        }
        try:
            w = whois.whois(domain)
            # Convert whois result to a dictionary (handles various formats)
            # whois result might be a WhoisEntry object or dict-like
            if hasattr(w, '__dict__'):
                result["data"] = w.__dict__
            else:
                # Fallback, might need adjustment based on whois library version
                result["data"] = dict(w) if w else {}
            
            result["status"] = "success"
            self.logger.info(f"ReconX: Whois lookup for '{domain}' completed successfully.")
        except whois.parser.PywhoisError as e: # Specific whois error
            result["status"] = "error"
            result["error"] = f"Whois lookup failed: {str(e)}"
            self.logger.warning(f"ReconX: Whois lookup failed for '{domain}': {e}")
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"Unexpected error during Whois lookup: {str(e)}"
            self.logger.error(f"ReconX: Unexpected error during Whois lookup for '{domain}': {e}", exc_info=True)
        return result

    def dns_query(self, domain, record_type='A'):
        """
        Queries DNS for a specific record type.

        Args:
            domain (str): The domain name to query.
            record_type (str): The DNS record type (e.g., 'A', 'MX', 'NS', 'TXT'). Default is 'A'.

        Returns:
            dict: A dictionary containing the query results and status.
        """
        result = {
            "type": f"dns_query_{record_type}",
            "target": domain,
            "record_type": record_type,
            "answers": [],
            "status": "unknown",
            "error": None
        }
        try:
            answers = dns.resolver.resolve(domain, record_type)
            result["answers"] = [str(rdata) for rdata in answers]
            result["status"] = "success"
            self.logger.info(f"ReconX: DNS query for '{domain}' type '{record_type}' succeeded. Answers: {result['answers']}")
        except dns.resolver.NXDOMAIN:
            result["status"] = "error"
            result["error"] = f"DNS query failed: Domain {domain} does not exist."
            self.logger.warning(f"ReconX: DNS query for '{domain}' type '{record_type}' failed: NXDOMAIN.")
        except dns.resolver.NoAnswer:
            result["status"] = "error"
            result["error"] = f"DNS query failed: No answer for {record_type} record for {domain}."
            self.logger.info(f"ReconX: DNS query for '{domain}' type '{record_type}' returned no answer.")
        except dns.exception.Timeout:
            result["status"] = "error"
            result["error"] = f"DNS query failed: Timeout while querying {domain}."
            self.logger.warning(f"ReconX: DNS query for '{domain}' type '{record_type}' timed out.")
        except Exception as e:
            result["status"] = "error"
            result["error"] = f"Unexpected error during DNS query: {str(e)}"
            self.logger.error(f"ReconX: Unexpected error during DNS query for '{domain}' type '{record_type}': {e}", exc_info=True)
        return result

    def run_basic_recon(self, target):
        """
        Runs a basic set of reconnaissance tasks on a target (domain or IP).

        Args:
            target (str): The target domain name or IP address.

        Returns:
            list: A list of dictionaries, each containing the result of a recon task.
        """
        self.logger.info(f"ReconX: Starting basic reconnaissance for target: {target}")
        results = []

        # Determine if target is an IP or Domain
        is_ip = False
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            pass # Not a valid IP, assume it's a domain

        if is_ip:
            # Target is an IP, perform reverse lookup
            self.logger.debug(f"ReconX: Target {target} identified as IP address.")
            reverse_result = self.reverse_lookup(target)
            results.append(reverse_result)
            # Optionally, perform Whois on the reversed hostname if successful?
            # if reverse_result['status'] == 'success' and reverse_result['hostname']:
            #     whois_result = self.whois_lookup(reverse_result['hostname'])
            #     results.append(whois_result)

        else:
            # Target is assumed to be a domain, perform forward lookup, whois, dns queries
            self.logger.debug(f"ReconX: Target {target} identified as domain name.")
            
            resolve_result = self.resolve_domain(target)
            results.append(resolve_result)
            
            whois_result = self.whois_lookup(target)
            results.append(whois_result)
            
            # Perform common DNS queries
            for record_type in ['A', 'MX', 'NS', 'TXT']:
                dns_result = self.dns_query(target, record_type)
                results.append(dns_result)

        self.logger.info(f"ReconX: Basic reconnaissance for {target} completed.")
        return results

# Example usage (if run directly)
if __name__ == '__main__':
    # Ensure basic logging is configured if run standalone
    # The logger setup at the top handles this.
    # You can adjust the level here if needed for standalone run
    # logger.setLevel(logging.INFO) # Uncomment to change level for standalone

    recon = ReconX()
    
    print("--- ReconX Basic Recon Demo ---")
    
    # Test with a domain
    domain_target = "example.com"
    print(f"\nRunning basic recon on domain: {domain_target}")
    domain_results = recon.run_basic_recon(domain_target)
    for res in domain_results:
        print(res)

    # Test with an IP
    ip_target = "93.184.216.34" # IP for example.com
    print(f"\nRunning basic recon on IP: {ip_target}")
    ip_results = recon.run_basic_recon(ip_target)
    for res in ip_results:
        print(res)
