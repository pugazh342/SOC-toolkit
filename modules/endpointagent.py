# BlueDefenderX/modules/endpointagent.py
import psutil
import platform
import time
import json
import os
from datetime import datetime
from utils.logger import bd_logger

class EndpointAgent:
    """
    Simulates an endpoint telemetry collector.
    Gathers system, process, and network information using psutil.
    In a real deployment, this would run as a service on the endpoint.
    """
    def __init__(self, collection_interval=60, output_path="endpoint_telemetry.jsonl"):
        """
        Initializes the EndpointAgent.

        Args:
            collection_interval (int): Time in seconds between telemetry collections. Default 60s.
            output_path (str): Path to the file where telemetry data will be written (JSON Lines format).
        """
        self.collection_interval = collection_interval
        self.output_path = output_path
        self.is_running = False
        self.hostname = platform.node()
        self.os_info = f"{platform.system()} {platform.release()}"
        bd_logger.info(f"EndpointAgent initialized for host '{self.hostname}' ({self.os_info}). Collection interval: {self.collection_interval}s. Output: {self.output_path}")

    def _collect_system_info(self):
        """Collects basic system information."""
        try:
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            cpu_percent = psutil.cpu_percent(interval=1) # 1 sec sample
            virtual_mem = psutil.virtual_memory()
            
            return {
                "timestamp": datetime.utcnow().isoformat() + 'Z',
                "host": self.hostname,
                "os": self.os_info,
                "boot_time": boot_time.isoformat() + 'Z',
                "uptime_seconds": uptime.total_seconds(),
                "cpu_percent": cpu_percent,
                "memory_percent": virtual_mem.percent,
                "memory_total_gb": round(virtual_mem.total / (1024**3), 2),
                "memory_available_gb": round(virtual_mem.available / (1024**3), 2)
            }
        except Exception as e:
            bd_logger.error(f"Error collecting system info: {e}")
            return {"error": f"System info collection failed: {str(e)}"}

    def _collect_processes(self, top_n=10):
        """Collects information about running processes."""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    # Get process info, handling potential access issues
                    pinfo = proc.info
                    # Calculate process uptime
                    create_time = pinfo['create_time']
                    if create_time:
                        proc_uptime = time.time() - create_time
                    else:
                        proc_uptime = None
                    
                    processes.append({
                        "pid": pinfo['pid'],
                        "name": pinfo['name'],
                        "username": pinfo['username'],
                        "cpu_percent": pinfo['cpu_percent'] or 0.0,
                        "memory_percent": pinfo['memory_percent'] or 0.0,
                        "uptime_seconds": proc_uptime
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Process might have disappeared or access denied
                    pass
            
            # Sort by CPU usage and take top N
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            return processes[:top_n]
        except Exception as e:
            bd_logger.error(f"Error collecting processes: {e}")
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
                        "family": str(conn.family),
                        "type": str(conn.type),
                        "laddr": laddr,
                        "raddr": raddr,
                        "status": conn.status
                    })
                except Exception as e:
                    bd_logger.debug(f"Skipping connection due to error: {e}")
                    pass # Skip problematic connections
            return connections
        except Exception as e:
            bd_logger.error(f"Error collecting network connections: {e}")
            return [{"error": f"Network connection collection failed: {str(e)}"}]

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
            bd_logger.error(f"Error collecting users: {e}")
            return [{"error": f"User collection failed: {str(e)}"}]

    def collect_telemetry(self):
        """
        Performs a single collection cycle of all telemetry data.
        
        Returns:
            dict: A dictionary containing all collected telemetry for this cycle.
        """
        bd_logger.debug("Starting telemetry collection cycle...")
        telemetry_data = {
            "collection_timestamp": datetime.utcnow().isoformat() + 'Z',
            "host": self.hostname,
            "system_info": self._collect_system_info(),
            "top_processes": self._collect_processes(top_n=5), # Limit for brevity
            "network_connections": self._collect_network_connections(),
            "logged_in_users": self._collect_users()
        }
        bd_logger.debug("Telemetry collection cycle completed.")
        return telemetry_data

    def send_telemetry(self, telemetry_data):
        """
        Sends telemetry data. In this prototype, we'll write it to a file.
        In a real system, this might send data over HTTP, Kafka, etc.

        Args:
            telemetry_data (dict): The telemetry data to send.
        """
        try:
            # Write data in JSON Lines format (each line is a separate JSON object)
            with open(self.output_path, 'a') as f:
                f.write(json.dumps(telemetry_data, default=str) + '\n')
            bd_logger.info(f"Telemetry data written to {self.output_path}")
        except Exception as e:
            bd_logger.error(f"Error writing telemetry data to {self.output_path}: {e}")

    def run_once(self):
        """Runs a single telemetry collection and send cycle."""
        bd_logger.info("EndpointAgent: Running single collection cycle.")
        data = self.collect_telemetry()
        self.send_telemetry(data)
        bd_logger.info("EndpointAgent: Single collection cycle finished.")

    def start(self):
        """
        Starts the agent to run continuously, collecting telemetry at intervals.
        This is a blocking call.
        """
        self.is_running = True
        bd_logger.info(f"EndpointAgent started. Collecting telemetry every {self.collection_interval} seconds.")
        try:
            while self.is_running:
                data = self.collect_telemetry()
                self.send_telemetry(data)
                bd_logger.debug(f"Sleeping for {self.collection_interval} seconds...")
                time.sleep(self.collection_interval)
        except KeyboardInterrupt:
            bd_logger.info("EndpointAgent stopped by user (KeyboardInterrupt).")
        except Exception as e:
            bd_logger.error(f"EndpointAgent encountered an error and stopped: {e}")
        finally:
            self.is_running = False
            bd_logger.info("EndpointAgent shutdown complete.")

    def stop(self):
        """Signals the agent to stop running."""
        bd_logger.info("EndpointAgent stop signal received.")
        self.is_running = False

# Example usage (if run as a script)
if __name__ == '__main__':
    # Example: Run once
    agent = EndpointAgent(collection_interval=10, output_path="sample_endpoint_data.jsonl")
    agent.run_once()
    print(f"Sample telemetry data written to 'sample_endpoint_data.jsonl'.")
    print("To run continuously, call agent.start() instead of agent.run_once().")

    # Example: Run continuously (uncomment to use)
    # print("Starting EndpointAgent in continuous mode. Press Ctrl+C to stop.")
    # agent.start()
