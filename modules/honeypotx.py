# BlueDefenderX/modules/honeypotx.py
import socket
import threading
import time
import json
from datetime import datetime
from utils.logger import bd_logger

class HoneyPotX:
    """
    A basic deceptive trap generator.
    Simulates network services to attract and log potential attackers.
    """
    def __init__(self, config=None):
        """
        Initializes the HoneyPotX.

        Args:
            config (dict, optional): Configuration dictionary.
                                     Defaults to None, using internal defaults.
                                     Expected keys: 'host', 'port', 'service_type', 'log_file'.
        """
        self.config = config or self._get_default_config()
        self.host = self.config.get('host', '0.0.0.0') # Listen on all interfaces by default
        self.port = self.config.get('port', 2222)      # Default non-standard port to avoid conflict
        self.service_type = self.config.get('service_type', 'generic_tcp') # e.g., 'ssh', 'http', 'generic_tcp'
        self.log_file = self.config.get('log_file', 'honeypot_interactions.jsonl')
        self.is_running = False
        self.server_socket = None
        self.interactions = [] # In-memory log of interactions (for demo)
        bd_logger.info(f"HoneyPotX initialized. Config: Host={self.host}, Port={self.port}, Service={self.service_type}")

    def _get_default_config(self):
        """Provides default configuration values."""
        return {
            'host': '0.0.0.0',
            'port': 2222,
            'service_type': 'generic_tcp',
            'log_file': 'honeypot_interactions.jsonl'
        }

    def _simulate_service_response(self, client_socket, client_address):
        """
        Simulates a basic response based on the configured service type.
        This is a very basic simulation.

        Args:
            client_socket (socket.socket): The connected client socket.
            client_address (tuple): The client's (IP, port).
        """
        ip, port = client_address
        bd_logger.debug(f"HoneyPotX: Simulating response for {self.service_type} to {ip}:{port}")

        try:
            if self.service_type == 'ssh':
                # Simulate SSH banner
                banner = b"SSH-2.0-OpenSSH_7.9p1 Debian-10+deb10u2\r\n"
                client_socket.send(banner)
                # Wait for client data (e.g., username)
                data = client_socket.recv(1024)
                bd_logger.info(f"HoneyPotX ({self.service_type}): Received data from {ip}:{port}: {data!r}")
                
            elif self.service_type == 'http':
                # Simulate basic HTTP response
                response = (
                    b"HTTP/1.1 401 Unauthorized\r\n"
                    b"WWW-Authenticate: Basic realm=\"HoneyPot\"\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Content-Length: 17\r\n"
                    b"\r\n"
                    b"<h1>Unauthorized</h1>"
                )
                client_socket.send(response)
                # Wait for client data (e.g., headers, potential exploit)
                data = client_socket.recv(1024)
                bd_logger.info(f"HoneyPotX ({self.service_type}): Received data from {ip}:{port}: {data!r}")

            else: # generic_tcp or others
                # Send a simple prompt or banner
                prompt = b"Welcome to HoneyPotX Service\r\nLogin: "
                client_socket.send(prompt)
                # Wait for client data
                data = client_socket.recv(1024)
                bd_logger.info(f"HoneyPotX ({self.service_type}): Received data from {ip}:{port}: {data!r}")

        except socket.error as e:
            bd_logger.warning(f"HoneyPotX: Socket error while simulating service for {ip}:{port}: {e}")
        except Exception as e:
            bd_logger.error(f"HoneyPotX: Unexpected error while simulating service for {ip}:{port}: {e}")

    def _handle_client(self, client_socket, client_address):
        """
        Handles a single connected client.

        Args:
            client_socket (socket.socket): The connected client socket.
            client_address (tuple): The client's (IP, port).
        """
        ip, port = client_address
        interaction = {
            "timestamp": datetime.utcnow().isoformat() + 'Z',
            "source_ip": ip,
            "source_port": port,
            "destination_port": self.port,
            "service_type": self.service_type,
            "data_received": ""
        }

        try:
            bd_logger.info(f"HoneyPotX: New connection from {ip}:{port}")
            
            # Set a timeout for the client socket to prevent hanging
            client_socket.settimeout(30.0) # 30 second timeout

            # Simulate the service and get initial data
            self._simulate_service_response(client_socket, client_address)

            # Log the interaction
            # Note: In a real honeypot, you might keep the connection open longer
            # and log more detailed interactions.
            
            # For demo, we'll close the connection quickly after initial interaction
            client_socket.close()
            bd_logger.info(f"HoneyPotX: Connection with {ip}:{port} closed.")

            # Update interaction record and log it
            # (In a full implementation, you'd capture more data over time)
            # For now, we just log the basic connection event.
            self.interactions.append(interaction)
            self._log_interaction(interaction)

        except socket.timeout:
            bd_logger.info(f"HoneyPotX: Connection with {ip}:{port} timed out.")
            interaction['data_received'] = "[TIMEOUT]"
            self.interactions.append(interaction)
            self._log_interaction(interaction)
        except Exception as e:
            bd_logger.error(f"HoneyPotX: Error handling client {ip}:{port}: {e}")
            interaction['error'] = str(e)
            self.interactions.append(interaction)
            self._log_interaction(interaction)
        finally:
            try:
                client_socket.close()
            except:
                pass # Ignore errors on close

    def _log_interaction(self, interaction_data):
        """
        Logs an interaction to a file.

        Args:
            interaction_data (dict): The interaction data to log.
        """
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(interaction_data, default=str) + '\n')
            bd_logger.info(f"HoneyPotX: Interaction logged to {self.log_file}")
        except Exception as e:
            bd_logger.error(f"HoneyPotX: Failed to log interaction to {self.log_file}: {e}")

    def start(self):
        """
        Starts the honeypot server.
        This method will block, so it's recommended to run it in a thread.
        """
        if self.is_running:
            bd_logger.warning("HoneyPotX is already running.")
            return

        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Allow reuse of the address
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            # Listen for up to 5 connections
            self.server_socket.listen(5)
            self.is_running = True
            bd_logger.info(f"HoneyPotX: Server started on {self.host}:{self.port} (Service: {self.service_type})")

            while self.is_running:
                try:
                    # Accept connections (blocking call)
                    client_socket, client_address = self.server_socket.accept()
                    # Handle each client in a new thread
                    client_thread = threading.Thread(target=self._handle_client, args=(client_socket, client_address))
                    client_thread.daemon = True # Dies when main thread dies
                    client_thread.start()
                except socket.error as e:
                    if self.is_running: # Only log if not stopping
                        bd_logger.error(f"HoneyPotX: Socket error while accepting connections: {e}")
                except Exception as e:
                    if self.is_running:
                        bd_logger.error(f"HoneyPotX: Unexpected error while accepting connections: {e}")

        except Exception as e:
            bd_logger.critical(f"HoneyPotX: Failed to start server on {self.host}:{self.port}: {e}")
            self.is_running = False
        finally:
            self.stop()

    def stop(self):
        """Stops the honeypot server."""
        bd_logger.info("HoneyPotX: Stop signal received.")
        self.is_running = False
        if self.server_socket:
            try:
                self.server_socket.close()
                bd_logger.info("HoneyPotX: Server socket closed.")
            except Exception as e:
                bd_logger.error(f"HoneyPotX: Error closing server socket: {e}")
        bd_logger.info("HoneyPotX: Server stopped.")

    def get_recent_interactions(self, count=10):
        """
        Gets the most recent interactions (from in-memory list).

        Args:
            count (int): Number of recent interactions to return.

        Returns:
            list: A list of recent interaction dictionaries.
        """
        return self.interactions[-count:] if self.interactions else []

    def is_active(self):
        """Checks if the honeypot is currently running."""
        return self.is_running


# Example usage (if run directly)
if __name__ == '__main__':
    import logging
    # Ensure logger is set up for standalone run
    if not bd_logger.handlers:
        logging.basicConfig(level=logging.INFO)

    # Example 1: Generic TCP Honeypot
    print("--- Starting Generic TCP Honeypot on port 2222 ---")
    config_generic = {
        'host': '127.0.0.1', # Listen only locally for safety
        'port': 2222,
        'service_type': 'generic_tcp',
        'log_file': 'honeypot_generic.log'
    }
    honeypot_generic = HoneyPotX(config_generic)

    # Start in a background thread so we can interact
    server_thread = threading.Thread(target=honeypot_generic.start)
    server_thread.daemon = True
    server_thread.start()

    # Give it a moment to start
    time.sleep(2)

    if honeypot_generic.is_active():
        print("Honeypot is running. You can test it using 'telnet 127.0.0.1 2222' or 'nc 127.0.0.1 2222' in another terminal.")
        print("Press Enter to stop the honeypot...")
        input() # Wait for user input
    else:
        print("Honeypot failed to start.")

    honeypot_generic.stop()
    server_thread.join(timeout=5) # Wait for thread to finish (max 5 seconds)
    print("Generic TCP Honeypot stopped.")
    print(f"Recent interactions: {honeypot_generic.get_recent_interactions()}")

    # Example 2: Simulated SSH Honeypot (on a different port)
    print("\n--- Starting Simulated SSH Honeypot on port 2223 ---")
    config_ssh = {
        'host': '127.0.0.1',
        'port': 2223,
        'service_type': 'ssh',
        'log_file': 'honeypot_ssh.log'
    }
    honeypot_ssh = HoneyPotX(config_ssh)

    server_thread_ssh = threading.Thread(target=honeypot_ssh.start)
    server_thread_ssh.daemon = True
    server_thread_ssh.start()

    time.sleep(2)

    if honeypot_ssh.is_active():
        print("SSH Honeypot is running. You can test it using 'ssh user@127.0.0.1 -p 2223' in another terminal.")
        print("(It will likely fail after the banner, but the connection attempt will be logged).")
        print("Press Enter to stop the SSH honeypot...")
        input()
    else:
        print("SSH Honeypot failed to start.")

    honeypot_ssh.stop()
    server_thread_ssh.join(timeout=5)
    print("SSH Honeypot stopped.")
