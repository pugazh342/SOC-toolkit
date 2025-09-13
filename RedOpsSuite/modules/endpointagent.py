# RedOpsSuite/modules/endpointagent.py
import psutil
import platform
import time
import json
import os
import csv
from datetime import datetime
import logging

# --- Setup basic logging for standalone execution ---
logger = logging.getLogger(__name__)
logger.propagate = False
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)
# --- End logging setup ---

class EndpointAgent:
    """
    A basic cross-platform telemetry collector for RedOpsSuite.
    Gathers system, process, network, and user information using psutil.
    """

    def __init__(self, default_timeout=10,max_workers=10,delay=0.1,user_agent=None,config=None):
        """
        Initializes the EndpointAgent.

        Args:
            config (dict, optional): Configuration dictionary.
                                     Defaults to None, using internal defaults.
                                     Expected keys:
                                        - 'collection_interval' (int): Seconds between collections (for continuous mode).
                                        - 'output_dir' (str): Directory to save collected data.
                                        - 'output_format' (str): 'json' or 'csv'.
        """
        self.config = config or self._get_default_config()
        self.collection_interval = self.config.get('collection_interval', 60)
        self.output_dir = self.config.get('output_dir', './telemetry_output')
        self.output_format = self.config.get('output_format', 'json').lower()
        self.hostname = platform.node()
        self.os_info = f"{platform.system()} {platform.release()}"
        self.is_collecting = False

        os.makedirs(self.output_dir, exist_ok=True) # Ensure output directory exists
        logger.info(f"EndpointAgent initialized. Host: {self.hostname} ({self.os_info}). Config: Interval={self.collection_interval}s, OutputDir={self.output_dir}, Format={self.output_format}")

    def _get_default_config(self):
        """Provides default configuration values."""
        return {
            'collection_interval': 60, # Collect every 60 seconds
            'output_dir': './telemetry_output',
            'output_format': 'json' # 'json' or 'csv'
        }

    def _collect_system_info(self):
        """Collects basic system information."""
        try:
            boot_time_timestamp = psutil.boot_time()
            boot_time = datetime.fromtimestamp(boot_time_timestamp)
            uptime = datetime.now() - boot_time
            cpu_percent = psutil.cpu_percent(interval=1) # 1 sec sample
            virtual_mem = psutil.virtual_memory()
            
            return {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "host": self.hostname,
                "os": self.os_info,
                "architecture": platform.machine(),
                "boot_time": boot_time.isoformat() + 'Z',
                "uptime_seconds": uptime.total_seconds(),
                "cpu_cores_logical": psutil.cpu_count(logical=True),
                "cpu_cores_physical": psutil.cpu_count(logical=False),
                "cpu_percent": cpu_percent,
                "memory_total_gb": round(virtual_mem.total / (1024**3), 2),
                "memory_available_gb": round(virtual_mem.available / (1024**3), 2),
                "memory_percent": virtual_mem.percent
            }
        except Exception as e:
            logger.error(f"EndpointAgent: Error collecting system info: {e}")
            return {"error": f"System info collection failed: {str(e)}"}

    def _collect_processes(self):
        """Collects information about running processes."""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'status', 'cpu_percent', 'memory_percent', 'create_time', 'cmdline']):
                try:
                    # Get process info, handling potential access issues
                    pinfo = proc.info
                    # Calculate process uptime
                    create_time = pinfo['create_time']
                    if create_time:
                        proc_uptime = time.time() - create_time
                    else:
                        proc_uptime = None
                    
                    # Get command line, handle potential access issues
                    cmdline = pinfo['cmdline']
                    if isinstance(cmdline, list):
                        cmdline_str = ' '.join(cmdline)
                    else:
                        cmdline_str = str(cmdline) if cmdline else ""

                    processes.append({
                        "pid": pinfo['pid'],
                        "name": pinfo['name'],
                        "username": pinfo['username'],
                        "status": pinfo['status'],
                        "cpu_percent": round(pinfo['cpu_percent'] or 0.0, 2),
                        "memory_percent": round(pinfo['memory_percent'] or 0.0, 2),
                        "uptime_seconds": round(proc_uptime, 2) if proc_uptime else None,
                        "cmdline": cmdline_str[:500] # Truncate very long command lines
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Process might have disappeared or access denied
                    pass
            
            # Sort by PID for consistent ordering
            processes.sort(key=lambda x: x['pid'])
            return processes
        except Exception as e:
            logger.error(f"EndpointAgent: Error collecting processes: {e}")
            return [{"error": f"Process collection failed: {str(e)}"}]

    def _collect_network_connections(self):
        """Collects information about network connections."""
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                try:
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None
                    connections.append({
                        "fd": conn.fd,
                        "family": str(conn.family.name), # Use .name for human-readable family
                        "type": str(conn.type.name),     # Use .name for human-readable type
                        "laddr": laddr,
                        "raddr": raddr,
                        "status": conn.status
                    })
                except Exception as e:
                    logger.debug(f"EndpointAgent: Skipping connection due to error: {e}")
                    pass # Skip problematic connections
            return connections
        except Exception as e:
            logger.error(f"EndpointAgent: Error collecting network connections: {e}")
            return [{"error": f"Network connection collection failed: {str(e)}"}]

    def _collect_network_interfaces(self):
        """Collects information about network interfaces."""
        try:
            interfaces = []
            net_if_addrs = psutil.net_if_addrs()
            net_if_stats = psutil.net_if_stats()
            
            for interface_name, addresses in net_if_addrs.items():
                interface_info = {
                    "name": interface_name,
                    "addresses": [],
                    "stats": {}
                }
                
                # Add address information
                for addr in addresses:
                    interface_info["addresses"].append({
                        "family": str(addr.family.name) if hasattr(addr.family, 'name') else str(addr.family),
                        "address": addr.address,
                        "netmask": addr.netmask,
                        "broadcast": addr.broadcast
                    })
                
                # Add statistics
                stat = net_if_stats.get(interface_name)
                if stat:
                    interface_info["stats"] = {
                        "isup": stat.isup,
                        "duplex": str(stat.duplex.name) if hasattr(stat.duplex, 'name') else str(stat.duplex),
                        "speed": stat.speed,
                        "mtu": stat.mtu
                    }
                
                interfaces.append(interface_info)
            
            return interfaces
        except Exception as e:
            logger.error(f"EndpointAgent: Error collecting network interfaces: {e}")
            return [{"error": f"Network interface collection failed: {str(e)}"}]

    def _collect_users(self):
        """Collects information about currently logged-in users."""
        try:
            users = []
            for user in psutil.users():
                users.append({
                    "name": user.name,
                    "terminal": user.terminal,
                    "host": user.host,
                    "started": datetime.fromtimestamp(user.started).isoformat() + 'Z'
                })
            return users
        except Exception as e:
            logger.error(f"EndpointAgent: Error collecting users: {e}")
            return [{"error": f"User collection failed: {str(e)}"}]

    def _collect_telemetry(self):
        """
        Collects a full snapshot of endpoint telemetry.

        Returns:
            dict: A dictionary containing all collected telemetry for this cycle.
        """
        logger.info("EndpointAgent: Starting telemetry collection cycle...")
        telemetry_snapshot = {
            "collection_timestamp": datetime.utcnow().isoformat() + 'Z',
            "host": self.hostname,
            "os": self.os_info,
            "system_info": self._collect_system_info(),
            "processes": self._collect_processes(),
            "network_connections": self._collect_network_connections(),
            "network_interfaces": self._collect_network_interfaces(),
            "logged_in_users": self._collect_users()
        }
        logger.info("EndpointAgent: Telemetry collection cycle completed.")
        return telemetry_snapshot

    def _save_telemetry(self, telemetry_data):
        """
        Saves telemetry data to a file in the configured format.

        Args:
            telemetry_data (dict): The telemetry data to save.
        """
        timestamp_str = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        filename_base = f"endpoint_telemetry_{self.hostname}_{timestamp_str}"
        
        if self.output_format == 'json':
            filepath = os.path.join(self.output_dir, f"{filename_base}.json")
            try:
                with open(filepath, 'w') as f:
                    json.dump(telemetry_data, f, indent=4, default=str) # default=str handles non-serializable objects
                logger.info(f"EndpointAgent: Telemetry data saved to {filepath}")
            except Exception as e:
                logger.error(f"EndpointAgent: Error saving telemetry to JSON {filepath}: {e}")
        elif self.output_format == 'csv':
            # For CSV, we need to flatten the data structure significantly.
            # This is a simplified approach, saving key sections to separate CSV files.
            # A full flattening would be complex.
            sections_to_save = ['system_info', 'processes', 'network_connections', 'network_interfaces', 'logged_in_users']
            for section_name in sections_to_save:
                section_data = telemetry_data.get(section_name, [])
                if section_data:
                    # Handle single dict vs list of dicts
                    if isinstance(section_data, dict):
                        section_data = [section_data]
                    
                    if section_data and isinstance(section_data, list) and isinstance(section_data[0], dict):
                        filepath = os.path.join(self.output_dir, f"{filename_base}_{section_name}.csv")
                        try:
                            # Get fieldnames from the first item's keys
                            fieldnames = list(section_data[0].keys())
                            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                                writer.writeheader()
                                # Handle potential non-dict items in list (e.g., error dicts)
                                for item in section_data:
                                    if isinstance(item, dict):
                                        # Ensure all values are strings for CSV
                                        row = {k: str(v) for k, v in item.items()}
                                        writer.writerow(row)
                            logger.info(f"EndpointAgent: Telemetry section '{section_name}' saved to {filepath}")
                        except Exception as e:
                            logger.error(f"EndpointAgent: Error saving telemetry section '{section_name}' to CSV {filepath}: {e}")
                    else:
                        logger.debug(f"EndpointAgent: Skipping CSV save for section '{section_name}' (empty or invalid format).")
                else:
                    logger.debug(f"EndpointAgent: Skipping CSV save for section '{section_name}' (no data).")
        else:
            logger.error(f"EndpointAgent: Unsupported output format: {self.output_format}. Supported formats: 'json', 'csv'.")

    def collect_and_save_once(self):
        """Performs a single telemetry collection cycle and saves the data."""
        logger.info("EndpointAgent: Running single collection cycle.")
        data = self._collect_telemetry()
        self._save_telemetry(data)
        logger.info("EndpointAgent: Single collection cycle finished.")

    def start_continuous_collection(self):
        """
        Starts the agent to run continuously, collecting telemetry at intervals.
        This is a blocking call.
        """
        self.is_collecting = True
        logger.info(f"EndpointAgent started continuous collection. Interval: {self.collection_interval} seconds. Output Dir: {self.output_dir}. Format: {self.output_format}")
        try:
            while self.is_collecting:
                data = self._collect_telemetry()
                self._save_telemetry(data)
                logger.debug(f"EndpointAgent: Sleeping for {self.collection_interval} seconds...")
                time.sleep(self.collection_interval)
        except KeyboardInterrupt:
            logger.info("EndpointAgent: Continuous collection stopped by user (KeyboardInterrupt).")
        except Exception as e:
            logger.error(f"EndpointAgent: Continuous collection encountered an error and stopped: {e}")
        finally:
            self.is_collecting = False
            logger.info("EndpointAgent: Continuous collection shutdown complete.")

    def stop_continuous_collection(self):
        """Signals the agent to stop continuous collection."""
        logger.info("EndpointAgent: Stop continuous collection signal received.")
        self.is_collecting = False

    def get_latest_telemetry(self):
        """
        Collects and returns the latest telemetry snapshot without saving it.
        Useful for immediate inspection or integration.

        Returns:
            dict: The latest telemetry snapshot.
        """
        return self._collect_telemetry()

    def list_saved_telemetry_files(self):
        """
        Lists the telemetry files saved in the output directory.

        Returns:
            list: A list of filenames in the output directory.
        """
        try:
            files = os.listdir(self.output_dir)
            # Filter for relevant files (json or csv)
            relevant_files = [f for f in files if f.endswith(('.json', '.csv'))]
            logger.debug(f"EndpointAgent: Found {len(relevant_files)} saved telemetry files in {self.output_dir}.")
            return relevant_files
        except Exception as e:
            logger.error(f"EndpointAgent: Error listing saved telemetry files in {self.output_dir}: {e}")
            return []
    


# Example usage (if run directly)
if __name__ == '__main__':
    # Example: Collect telemetry once and save
    agent = EndpointAgent(config={
        'collection_interval': 30, # 30 seconds for demo
        'output_dir': './demo_telemetry_output',
        'output_format': 'json' # or 'csv'
    })

    print("--- EndpointAgent Basic Demo ---")
    print(f"Host: {agent.hostname}")
    print(f"OS: {agent.os_info}")
    print(f"Config: Interval={agent.collection_interval}s, OutputDir={agent.output_dir}, Format={agent.output_format}")
    print("-" * 30)

    # Run a single collection cycle
    agent.collect_and_save_once()

    # List saved files
    saved_files = agent.list_saved_telemetry_files()
    print(f"\nSaved telemetry files in {agent.output_dir}:")
    if saved_files:
        for f in saved_files:
            print(f" - {f}")
    else:
        print("No files saved yet.")

    print("-" * 30)
    print("EndpointAgent demo completed.")


