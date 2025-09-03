# BlueDefenderX/modules/threatfeedsync.py
import json
import requests
import os
from utils.logger import bd_logger

class ThreatFeedSync:
    def __init__(self, config_path="config/feedsources.json"):
        self.config_path = config_path
        self.feeds = self.load_feeds()
        self.iocs = {
            'ip': set(),
            'domain': set(),
            'hash': set()
            # Add more types as needed
        }
        bd_logger.info("ThreatFeedSync initialized.")

    def load_feeds(self):
        """Loads threat feed sources from JSON config."""
        try:
            with open(self.config_path, 'r') as f:
                config = json.load(f)
                feeds = config.get('feeds', [])
                enabled_feeds = [feed for feed in feeds if feed.get('enabled', False)]
                bd_logger.info(f"Loaded {len(enabled_feeds)} enabled threat feeds from {self.config_path}")
                return enabled_feeds
        except FileNotFoundError:
            bd_logger.error(f"Feed sources file not found: {self.config_path}")
            return []
        except json.JSONDecodeError as e:
            bd_logger.error(f"Error parsing JSON feed sources file: {e}")
            return []
        except Exception as e:
            bd_logger.error(f"Unexpected error loading feed sources: {e}")
            return []

    def fetch_file_feed(self, feed_config):
        """Fetches IOCs from a local file."""
        file_path = feed_config['url'].replace('file://', '')
        ioc_type = feed_config['type']
        iocs_fetched = set()

        if not os.path.exists(file_path):
            bd_logger.error(f"Local IOC file not found: {file_path}")
            return iocs_fetched

        try:
            with open(file_path, 'r') as f:
                for line in f:
                    ioc = line.strip()
                    if ioc and not ioc.startswith('#'): # Skip empty lines and comments
                        iocs_fetched.add(ioc)
            bd_logger.info(f"Fetched {len(iocs_fetched)} {ioc_type} IOCs from local file {file_path}")
        except Exception as e:
            bd_logger.error(f"Error reading local IOC file {file_path}: {e}")

        return iocs_fetched

    def fetch_http_feed(self, feed_config):
        """Fetches IOCs from an HTTP(S) source. (Placeholder for more complex logic)"""
        url = feed_config['url']
        ioc_type = feed_config['type']
        # For simplicity, assuming a plain text list of IOCs per line
        # Real implementation would handle API keys, JSON parsing, etc.
        iocs_fetched = set()
        try:
            headers = {}
            # Example: Add API key if present in config
            # api_key = feed_config.get('api_key')
            # if api_key:
            #     headers['Authorization'] = f'Bearer {api_key}' # Or specific header format

            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status() # Raise an exception for bad status codes

            # Simple line-by-line parsing for txt format
            # For JSON feeds, you'd parse response.json() and extract IOCs accordingly
            for line in response.text.splitlines():
                ioc = line.strip()
                if ioc and not ioc.startswith('#'):
                    iocs_fetched.add(ioc)

            bd_logger.info(f"Fetched {len(iocs_fetched)} {ioc_type} IOCs from HTTP feed {url}")
        except requests.exceptions.RequestException as e:
            bd_logger.error(f"Error fetching HTTP IOC feed {url}: {e}")
        except Exception as e:
            bd_logger.error(f"Unexpected error processing HTTP IOC feed {url}: {e}")

        return iocs_fetched

    def sync_feeds(self):
        """Synchronizes all enabled threat feeds."""
        self.iocs = {key: set() for key in self.iocs} # Clear previous IOCs

        if not self.feeds:
            bd_logger.warning("No enabled threat feeds configured.")
            return

        bd_logger.info("Starting threat feed synchronization...")
        for feed in self.feeds:
            feed_name = feed.get('name', 'Unknown Feed')
            feed_url = feed.get('url', '')
            feed_type = feed.get('type', 'unknown')

            bd_logger.info(f"Syncing feed: {feed_name} ({feed_type})")

            try:
                if feed_url.startswith('file://'):
                    fetched_iocs = self.fetch_file_feed(feed)
                elif feed_url.startswith(('http://', 'https://')):
                    fetched_iocs = self.fetch_http_feed(feed)
                else:
                    bd_logger.warning(f"Unsupported URL scheme for feed {feed_name}: {feed_url}")
                    continue

                # Add fetched IOCs to the main collection
                if feed_type in self.iocs:
                    self.iocs[feed_type].update(fetched_iocs)
                else:
                    bd_logger.warning(f"Unsupported IOC type '{feed_type}' for feed {feed_name}. Supported types: {list(self.iocs.keys())}")

            except Exception as e:
                bd_logger.error(f"Error synchronizing feed {feed_name}: {e}")

        total_iocs = sum(len(ioc_set) for ioc_set in self.iocs.values())
        bd_logger.info(f"Threat feed synchronization complete. Total IOCs loaded: {total_iocs}")

    def check_ip(self, ip_address):
        """Checks if an IP address is in the known malicious IPs."""
        is_malicious = ip_address in self.iocs.get('ip', set())
        # bd_logger.debug(f"Checking IP '{ip_address}': {'Malicious' if is_malicious else 'Clean'}")
        return is_malicious

    def check_domain(self, domain):
        """Checks if a domain is in the known malicious domains."""
        return domain in self.iocs.get('domain', set())

    def check_hash(self, file_hash):
        """Checks if a file hash is in the known malicious hashes."""
        return file_hash in self.iocs.get('hash', set())

    def enrich_alerts(self, alerts):
        """
        Enriches a list of alerts with threat intelligence.
        Adds a 'threat_intel' key to alerts if IOCs are matched.
        """
        # --- ADD DETAILED LOGGING FOR ENRICHMENT ---
        bd_logger.debug(f"Starting threat intel enrichment for {len(alerts)} alerts.")
        enriched_alerts = []
        total_matches = 0
        for alert in alerts:
            alert_rule_id = alert.get('rule_id', 'Unknown')
            bd_logger.debug(f"Enriching alert ID: {alert_rule_id}")
            enriched_alert = alert.copy() # Shallow copy
            enriched_alert['threat_intel'] = []

            # Check source events for IOCs
            source_events = alert.get('source_events', [])
            matched_iocs = set() # To avoid duplicate entries in alert
            bd_logger.debug(f"Alert {alert_rule_id} has {len(source_events)} source events to check.")

            for i, event in enumerate(source_events):
                bd_logger.debug(f"Alert {alert_rule_id}, Event {i+1}/{len(source_events)}: {event}")
                src_ip = event.get('src_ip')
                if src_ip:
                    bd_logger.debug(f"Alert {alert_rule_id}: Checking src_ip '{src_ip}' against malicious IPs.")
                    if self.check_ip(src_ip) and src_ip not in matched_iocs:
                        matched_iocs.add(src_ip)
                        ti_entry = {
                            "type": "malicious_ip",
                            "value": src_ip,
                            "feed": "LocalMaliciousIPs" # Simplified
                        }
                        enriched_alert['threat_intel'].append(ti_entry)
                        bd_logger.debug(f"Alert {alert_rule_id}: Matched malicious IP: {src_ip}")
                        bd_logger.debug(f"Alert {alert_rule_id}: Current TI matches: {enriched_alert['threat_intel']}")
                    # else:
                    #     bd_logger.debug(f"Alert {alert_rule_id}: IP {src_ip} is NOT flagged as malicious or already matched.")

            # If any IOCs were matched, update the alert severity or add a flag
            if enriched_alert['threat_intel']:
                total_matches += 1
                # Example: Increase severity if not already critical
                original_severity = enriched_alert.get('severity')
                if original_severity in ['low', 'medium']:
                    enriched_alert['severity'] = 'high'
                    bd_logger.info(f"Alert {alert_rule_id} severity increased from '{original_severity}' to 'high' due to threat intel match.")

            enriched_alerts.append(enriched_alert)
            bd_logger.debug(f"Finished enriching alert ID: {alert_rule_id}")

        bd_logger.info(f"Enriched {total_matches} out of {len(alerts)} alerts with threat intelligence.")
        return enriched_alerts
        # --- END DETAILED LOGGING ---

    def get_loaded_iocs(self):
        """Returns a summary of loaded IOCs."""
        return {k: len(v) for k, v in self.iocs.items()}

# Example usage
if __name__ == '__main__':
    tfs = ThreatFeedSync()
    tfs.sync_feeds()
    print("Loaded IOCs:", tfs.get_loaded_iocs())

    # Test check
    test_ip = "192.168.1.100"
    if tfs.check_ip(test_ip):
        print(f"IP {test_ip} is flagged as malicious.")
    else:
        print(f"IP {test_ip} is NOT flagged as malicious.")
