# BlueDefenderX/modules/uba_monitor.py
import json
from datetime import datetime, time
from collections import defaultdict
from utils.logger import bd_logger

class UBAMonitor:
    """
    Performs basic User Behavior Analytics on parsed log data.
    Initially focuses on SSH login patterns.
    """
    def __init__(self, config=None):
        """
        Initializes the UBAMonitor.

        Args:
            config (dict, optional): Configuration dictionary for UBA settings.
                                     Defaults to None, using internal defaults.
        """
        self.config = config or self._get_default_config()
        # Store user profiles: { username: { 'login_ips': set(), 'login_hours': list(), 'login_count': int, ... } }
        self.user_profiles = defaultdict(lambda: {
            'login_ips': set(),
            'login_hours': [], # Store hour of day (0-23) for successful logins
            'login_count': 0,
            'first_seen': None,
            'last_seen': None
        })
        # Thresholds for anomaly detection
        self.hourly_login_threshold = self.config.get('hourly_login_threshold', 5)
        self.unusual_hour_start = self.config.get('unusual_hour_start', 22) # 10 PM
        self.unusual_hour_end = self.config.get('unusual_hour_end', 6)    # 6 AM
        bd_logger.info("UBAMonitor initialized.")

    def _get_default_config(self):
        """Provides default configuration values."""
        return {
            'hourly_login_threshold': 5,
            'unusual_hour_start': 22,
            'unusual_hour_end': 6,
            # Add more config options as needed
        }

    def _is_unusual_hour(self, hour):
        """
        Checks if a given hour is considered unusual based on config.

        Args:
            hour (int): Hour of the day (0-23).

        Returns:
            bool: True if the hour is unusual, False otherwise.
        """
        start = self.unusual_hour_start
        end = self.unusual_hour_end
        # Handle wrap-around (e.g., 22 to 6)
        if start > end:
            return hour >= start or hour <= end
        else:
            return start <= hour <= end

    def build_profiles(self, parsed_events):
        """
        Builds user behavior profiles from parsed log events.
        Focuses on successful SSH logins for now.

        Args:
            parsed_events (list): A list of dictionaries representing parsed log events.
        """
        bd_logger.info("UBAMonitor: Building user profiles...")
        profiled_events = 0
        for event in parsed_events:
            # Check if it's a successful SSH login event
            if event.get('event_type') == 'ssh_successful_login':
                username = event.get('message', '').split('for ')[-1].split(' from')[0] # Basic extraction
                src_ip = event.get('src_ip')
                timestamp_str = event.get('timestamp') # This is currently a string like "Jan 10 10:01:00"
                # For simplicity, assume timestamp is today or parse it if it's more complete
                
                # Update profile
                profile = self.user_profiles[username]
                
                # Track IPs
                if src_ip:
                    profile['login_ips'].add(src_ip)
                
                # Track login hours (very simplified)
                try:
                    # This is a very basic time parsing, assuming fixed format and current year
                    # A real implementation would parse the full timestamp correctly.
                    # Let's assume the timestamp string has hour:min:sec at the end
                    time_part = timestamp_str.split()[-1] # Get "10:01:00"
                    hour = int(time_part.split(':')[0])
                    profile['login_hours'].append(hour)
                except (ValueError, IndexError):
                    bd_logger.debug(f"Could not parse hour from timestamp '{timestamp_str}' for user '{username}'")
                    # Default to hour 12 if parsing fails
                    profile['login_hours'].append(12)

                # Track counts and timestamps
                profile['login_count'] += 1
                profile['last_seen'] = timestamp_str # Simplified
                if profile['first_seen'] is None:
                    profile['first_seen'] = timestamp_str

                profiled_events += 1

        bd_logger.info(f"UBAMonitor: Built/updated profiles for {profiled_events} SSH login events.")

    def detect_anomalies(self, parsed_events):
        """
        Detects anomalies in user behavior based on built profiles and current events.

        Args:
            parsed_events (list): A list of dictionaries representing parsed log events.

        Returns:
            list: A list of dictionaries, each representing a detected UBA anomaly.
        """
        bd_logger.info("UBAMonitor: Detecting user behavior anomalies...")
        anomalies = []
        checked_events = 0

        for event in parsed_events:
            is_anomaly = False
            anomaly_reason = ""
            details = {}

            if event.get('event_type') == 'ssh_successful_login':
                checked_events += 1
                username = event.get('message', '').split('for ')[-1].split(' from')[0]
                src_ip = event.get('src_ip')
                timestamp_str = event.get('timestamp')
                
                profile = self.user_profiles.get(username)
                if not profile:
                    bd_logger.warning(f"UBA: No profile found for user '{username}' during anomaly check.")
                    continue # Skip if no profile exists

                # --- Anomaly Checks ---
                # 1. Login from a new IP
                if src_ip and src_ip not in profile['login_ips']:
                    is_anomaly = True
                    anomaly_reason = f"User '{username}' logged in from a new IP address: {src_ip}"
                    details['anomaly_type'] = 'new_ip_login'
                    details['new_ip'] = src_ip
                    details['known_ips'] = list(profile['login_ips'])

                # 2. Login at unusual hour (if profile has enough data)
                # This check is tricky with current data format, so we'll do a basic one
                try:
                    time_part = timestamp_str.split()[-1]
                    current_hour = int(time_part.split(':')[0])
                    
                    if self._is_unusual_hour(current_hour):
                        # Check if user usually logs in during this time
                        # Very basic check: if less than 10% of logins are in unusual hours, flag it
                        unusual_logins = sum(1 for h in profile['login_hours'] if self._is_unusual_hour(h))
                        total_logins = len(profile['login_hours'])
                        if total_logins > 0:
                            unusual_ratio = unusual_logins / total_logins
                            # If less than 10% of historical logins were unusual, flag this one
                            if unusual_ratio < 0.1: 
                                # Combine with existing anomaly or create new one
                                if not is_anomaly:
                                    is_anomaly = True
                                    anomaly_reason = f"User '{username}' logged in at unusual hour ({current_hour}:00)."
                                    details['anomaly_type'] = 'unusual_login_time'
                                else:
                                    anomaly_reason += f" Also logged in at unusual hour ({current_hour}:00)."
                                details['login_hour'] = current_hour
                                details['historical_unusual_ratio'] = round(unusual_ratio, 2)
                except (ValueError, IndexError):
                    pass # Ignore time parsing errors for anomaly detection

                # 3. High frequency login (brute-force like, but for successful ones)
                # This would need stateful tracking per user/IP in a real system.
                # For prototype, we can't easily detect this from a single batch.

                # --- End Anomaly Checks ---

                if is_anomaly:
                    anomaly = {
                        "timestamp": datetime.utcnow().isoformat() + 'Z', # Detection time
                        "alert_type": "uba_anomaly",
                        "severity": "medium", # Default severity
                        "title": f"UBA Anomaly Detected for User '{username}'",
                        "description": anomaly_reason,
                        "source_event": event, # Link back to the original event
                        "uba_details": details,
                        "user": username,
                        # raw field for consistency if needed
                        "raw": json.dumps({"uba_anomaly": details, "source_event": event}, default=str)
                    }
                    # Increase severity if multiple factors
                    if details.get('anomaly_type') == 'new_ip_login' and 'unusual_login_time' in anomaly_reason:
                        anomaly['severity'] = 'high'

                    anomalies.append(anomaly)
                    bd_logger.info(f"UBA Anomaly Detected: {anomaly_reason}")

        bd_logger.info(f"UBAMonitor: Checked {checked_events} events. Detected {len(anomalies)} anomalies.")
        return anomalies

    def analyze(self, parsed_events):
        """
        Main analysis function: builds profiles and detects anomalies.

        Args:
            parsed_events (list): A list of dictionaries representing parsed log events.

        Returns:
            list: A list of detected UBA anomalies.
        """
        bd_logger.info("UBAMonitor: Starting user behavior analysis cycle.")
        self.build_profiles(parsed_events)
        anomalies = self.detect_anomalies(parsed_events)
        bd_logger.info("UBAMonitor: User behavior analysis cycle completed.")
        return anomalies

    def get_user_profile(self, username):
        """
        Retrieves the profile for a specific user.

        Args:
            username (str): The username.

        Returns:
            dict: The user profile dictionary, or None if not found.
        """
        profile = self.user_profiles.get(username)
        if profile:
            # Convert set to list for JSON serialization if needed
            serializable_profile = profile.copy()
            serializable_profile['login_ips'] = list(profile['login_ips'])
            return serializable_profile
        return None

    def get_all_profiles(self):
        """
        Retrieves all user profiles in a serializable format.

        Returns:
            dict: A dictionary of all user profiles.
        """
        serializable_profiles = {}
        for user, profile in self.user_profiles.items():
            serializable_profiles[user] = {
                'login_ips': list(profile['login_ips']),
                'login_hours': profile['login_hours'],
                'login_count': profile['login_count'],
                'first_seen': profile['first_seen'],
                'last_seen': profile['last_seen']
            }
        return serializable_profiles


# Example usage (if run directly)
if __name__ == '__main__':
    uba = UBAMonitor()

    # Example parsed events (similar to what LogDefenderX would produce)
    sample_events = [
        {
            "timestamp": "Jan 10 09:00:00",
            "hostname": "server1",
            "service": "sshd",
            "event_type": "ssh_successful_login",
            "message": "Accepted password for alice from 192.168.1.10 port 22 ssh2",
            "src_ip": "192.168.1.10",
            "raw": "..."
        },
        {
            "timestamp": "Jan 10 09:05:00",
            "hostname": "server1",
            "service": "sshd",
            "event_type": "ssh_successful_login",
            "message": "Accepted password for bob from 10.0.0.5 port 22 ssh2",
            "src_ip": "10.0.0.5",
            "raw": "..."
        },
        # --- Anomalous Events for alice ---
        # 1. New IP login
        {
            "timestamp": "Jan 10 10:00:00",
            "hostname": "server1",
            "service": "sshd",
            "event_type": "ssh_successful_login",
            "message": "Accepted password for alice from 8.8.8.8 port 22 ssh2", # New IP
            "src_ip": "8.8.8.8",
            "raw": "..."
        },
        # 2. Unusual hour login (assuming 2 AM is unusual based on config)
        {
            "timestamp": "Jan 11 02:00:00", # 2 AM
            "hostname": "server1",
            "service": "sshd",
            "event_type": "ssh_successful_login",
            "message": "Accepted password for bob from 10.0.0.5 port 22 ssh2",
            "src_ip": "10.0.0.5",
            "raw": "..."
        }
    ]

    print("--- UBA Analysis ---")
    detected_anomalies = uba.analyze(sample_events)
    
    print(f"\nDetected {len(detected_anomalies)} anomalies:")
    for anomaly in detected_anomalies:
        print(f"  - {anomaly['title']}: {anomaly['description']}")
        print(f"    Severity: {anomaly['severity']}")
        print(f"    Details: {anomaly['uba_details']}")
        print("-" * 20)

    print("\n--- User Profiles ---")
    profiles = uba.get_all_profiles()
    for user, profile in profiles.items():
        print(f"User: {user}")
        print(f"  Known IPs: {profile['login_ips']}")
        print(f"  Login Hours: {profile['login_hours']}")
        print(f"  Total Logins: {profile['login_count']}")
        print("-" * 10)
