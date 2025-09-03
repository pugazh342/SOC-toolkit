# BlueDefenderX/modules/incidentrespondr.py
import yaml
import re # For regex-based placeholder substitution
import json # For safely converting non-string values if needed
from utils.logger import bd_logger
# from utils.notifier import send_slack_alert, send_email_alert # Import notifier functions

class IncidentRespondr:
    """
    Automates response actions (playbooks) based on security alerts/anomalies.
    """
    def __init__(self, playbooks_config_path="config/playbooks.yaml"):
        """
        Initializes the IncidentRespondr by loading playbooks.

        Args:
            playbooks_config_path (str): Path to the YAML file containing playbooks.
        """
        self.playbooks_config_path = playbooks_config_path
        self.playbooks = self._load_playbooks()
        bd_logger.info("IncidentRespondr initialized.")

    def _load_playbooks(self):
        """
        Loads response playbooks from a YAML configuration file.

        Returns:
            list: A list of playbook dictionaries.
        """
        try:
            with open(self.playbooks_config_path, 'r') as f:
                config = yaml.safe_load(f)
                playbooks = config.get('playbooks', [])
                bd_logger.info(f"Loaded {len(playbooks)} response playbooks from {self.playbooks_config_path}")
                return playbooks
        except FileNotFoundError:
            bd_logger.error(f"Playbooks file not found: {self.playbooks_config_path}")
            return []
        except yaml.YAMLError as e:
            bd_logger.error(f"Error parsing YAML playbooks file {self.playbooks_config_path}: {e}")
            return []
        except Exception as e:
            bd_logger.error(f"Unexpected error loading playbooks: {e}")
            return []

    def _get_nested_value(self, data_dict, key_path):
        """
        Retrieves a value from a nested dictionary using a dot-separated key path.
        Handles list indices if needed (e.g., "key.0.subkey").

        Args:
            data_dict (dict): The dictionary to search.
            key_path (str): The dot-separated path (e.g., "details.matched_value").

        Returns:
            The value if found, None otherwise.
        """
        if not isinstance(data_dict, dict):
             return None # Cannot navigate into a non-dict

        keys = key_path.split('.')
        current_data = data_dict
        try:
            for key in keys:
                # Handle potential list indices
                if isinstance(current_data, list):
                    # This assumes key is an integer index string
                    index = int(key)
                    current_data = current_data[index]
                elif isinstance(current_data, dict) and key in current_data:
                    current_data = current_data[key]
                else:
                    # If we hit a non-dict/non-list before the end of the path,
                    # or the key is missing in the current dict level
                    return None
            return current_data
        except (KeyError, IndexError, ValueError, TypeError) as e:
            # KeyError: key not found in dict
            # IndexError: list index out of range
            # ValueError: key is not a valid integer for list indexing
            # TypeError: current_data is not subscriptable or key is wrong type
            bd_logger.debug(f"Error navigating key path '{key_path}': {e}")
            return None

    def _substitute_placeholders(self, template_string, alert_data):
        """
        Replaces placeholders like {{ details.matched_value }} in a string with values from alert_data.

        Args:
            template_string (str): The string containing placeholders.
            alert_data (dict): The dictionary with data to substitute.

        Returns:
            str: The string with placeholders replaced by values.
        """
        if not isinstance(template_string, str):
            return template_string # Don't process non-strings

        # Find all placeholders like {{ ... }}
        # This regex captures the content between {{ and }}, trimming internal whitespace
        # e.g., "{{ details.count }}" -> "details.count"
        pattern = r"\{\{([^}]+)\}\}"

        def replace_match(match):
            full_placeholder = match.group(0) # e.g., "{{ details.count }}"
            inner_key = match.group(1).strip() # e.g., " details.count " -> "details.count"

            # Special case: if inner_key is exactly empty
            if not inner_key:
                bd_logger.warning(f"Empty placeholder found: '{full_placeholder}'")
                return full_placeholder

            # Get the value using the nested key path on the alert_data itself
            value = self._get_nested_value(alert_data, inner_key)

            if value is not None:
                # Convert value to string for replacement in the template string
                if isinstance(value, (str, int, float, bool)):
                    str_value = str(value)
                else:
                    # For complex objects (dicts, lists), convert to a readable string (e.g., JSON)
                    try:
                        str_value = json.dumps(value, indent=2)
                    except (TypeError, ValueError):
                        str_value = str(value)
                bd_logger.debug(f"Substituted placeholder '{full_placeholder}' with value (truncated): '{str_value[:100]}...'")
                return str_value
            else:
                bd_logger.warning(f"Could not substitute placeholder '{full_placeholder}'. Key path '{inner_key}' not found or value is None in alert data.")
                # Optionally replace with a default marker
                # return f"[MISSING: {inner_key}]"
                return full_placeholder # Leave original placeholder if not found

        # Use re.sub with the replacement function
        result_string = re.sub(pattern, replace_match, template_string)
        return result_string

    def _substitute_action_placeholders(self, action_config, alert_data):
        """
        Recursively substitutes placeholders in an action configuration dictionary or list.

        Args:
            action_config (dict/list/str): The action config which may contain placeholders.
            alert_data (dict): The alert data for substitution.

        Returns:
            dict/list/str: The action config with placeholders substituted.
        """
        if isinstance(action_config, dict):
            substituted = {}
            for key, value in action_config.items():
                substituted[key] = self._substitute_action_placeholders(value, alert_data)
            return substituted
        elif isinstance(action_config, list):
            return [self._substitute_action_placeholders(item, alert_data) for item in action_config]
        elif isinstance(action_config, str):
            return self._substitute_placeholders(action_config, alert_data)
        else:
            # For numbers, booleans, None, etc., return as is
            return action_config

    def _match_trigger(self, alert_or_anomaly, trigger_criteria):
        """
        Checks if an alert/anomaly matches the trigger criteria of a playbook.

        Args:
            alert_or_anomaly (dict): The alert or anomaly dictionary.
            trigger_criteria (dict): The 'trigger' section of a playbook.

        Returns:
            bool: True if it matches, False otherwise.
        """
        # Check rule_id match
        if 'rule_id' in trigger_criteria:
            if alert_or_anomaly.get('rule_id') != trigger_criteria['rule_id']:
                return False

        # Check MITRE technique match
        if 'mitre_technique_id' in trigger_criteria:
            mitre_info = alert_or_anomaly.get('mitre')
            if not mitre_info or mitre_info.get('technique_id') != trigger_criteria['mitre_technique_id']:
                return False

        # Check severity match (if defined in trigger)
        # if 'severity' in trigger_criteria:
        #     if alert_or_anomaly.get('severity') != trigger_criteria['severity']:
        #         return False

        # Add more trigger conditions as needed (e.g., specific IP ranges, hostnames)

        return True # If all specified criteria match
    pass

    def _execute_action(self, action_config, alert_or_anomaly):
        """
        Executes a single action defined in a playbook.
        This is a simplified executor. Real actions would interface with systems.

        Args:
            action_config (dict): The action configuration (type, parameters).
            alert_or_anomaly (dict): The alert/anomaly data for parameter substitution.
        """
        # --- CRITICAL: Substitute placeholders in the action config before execution ---
        # Pass the full alert_or_anomaly dictionary.
        processed_action = self._substitute_action_placeholders(action_config, alert_or_anomaly)
        # --- END SUBSTITUTION ---
        
        action_type = processed_action.get('type')
        bd_logger.info(f"Executing action: {action_type}")

        # --- SIMULATED ACTION EXECUTION ---
        # In a real implementation, these would call actual system APIs or scripts.

        if action_type == "isolate_ip":
            target_ip = processed_action.get('target_ip', 'N/A')
            reason = processed_action.get('reason', 'No reason provided')
            # Example: Call a function to isolate the IP on the firewall
            # firewall_api.isolate_ip(target_ip, reason)
            bd_logger.warning(f"[SIMULATED] IP Isolation Action: Isolating IP '{target_ip}' on network devices. Reason: {reason}")
            print(f"[SIMULATED ACTION] Isolating IP: {target_ip} - Reason: {reason}") # For demo in terminal

        elif action_type == "send_notification":
            message = processed_action.get('message', 'No message provided')
            channels = processed_action.get('channels', [])
            # Example: Use notifier.py functions
            # for channel in channels:
            #     if channel == "slack":
            #         send_slack_alert(message)
            #     elif channel == "email":
            #         send_email_alert("Security Alert", message)
            bd_logger.info(f"[SIMULATED] Notification Action: Sending message via {channels}")
            print(f"[SIMULATED ACTION] Sending Notification:\n{message}\n---") # For demo in terminal

        elif action_type == "disable_user":
            username = processed_action.get('username', 'N/A')
            # Example: Call an identity management API
            # idm_api.disable_user(username)
            bd_logger.warning(f"[SIMULATED] User Disable Action: Disabling user account '{username}'.")
            print(f"[SIMULATED ACTION] Disabling user: {username}") # For demo in terminal

        else:
            bd_logger.warning(f"Unknown action type '{action_type}' encountered. Skipping.")
        # --- END SIMULATED EXECUTION ---

    def respond_to_incident(self, alert_or_anomaly):
        """
        Finds a matching playbook for an alert/anomaly and executes its actions.

        Args:
            alert_or_anomaly (dict): The alert or anomaly dictionary to respond to.
        """
        # --- DEBUG LOGGING (Optional, can be removed later) ---
        # import json
        # bd_logger.debug(f"IncidentRespondr received data for response: {json.dumps(alert_or_anomaly, indent=2, default=str)}")
        # --- END DEBUG LOGGING ---

        if not self.playbooks:
            bd_logger.warning("No playbooks loaded. Cannot respond to incident.")
            return

        matched_playbook = None
        for playbook in self.playbooks:
            trigger_criteria = playbook.get('trigger', {})
            if self._match_trigger(alert_or_anomaly, trigger_criteria):
                matched_playbook = playbook
                bd_logger.info(f"Matched playbook: '{playbook.get('name')}'")
                break # Execute the first matching playbook

        if matched_playbook:
            playbook_name = matched_playbook.get('name')
            actions = matched_playbook.get('actions', [])
            bd_logger.info(f"Executing {len(actions)} actions for playbook '{playbook_name}'...")
            for i, action in enumerate(actions):
                bd_logger.debug(f"Executing action {i+1}/{len(actions)}")
                try:
                    self._execute_action(action, alert_or_anomaly)
                except Exception as e:
                    bd_logger.error(f"Error executing action {i+1} in playbook '{playbook_name}': {e}")

            bd_logger.info(f"Playbook '{playbook_name}' execution completed.")
        else:
            bd_logger.info("No matching playbook found for the incident.")

    def list_playbooks(self):
        """Lists the currently loaded playbooks."""
        if not self.playbooks:
            print("No playbooks loaded.")
            return
        print("\n--- Loaded Playbooks ---")
        for pb in self.playbooks:
            print(f"- Name: {pb.get('name')}")
            print(f"  Description: {pb.get('description')}")
            print(f"  Trigger: {pb.get('trigger')}")
            print(f"  Actions: {len(pb.get('actions', []))} defined")
            print("-" * 20)

# Example usage (if run directly)
# (Keep the example usage section as it was, or remove if not needed for the module itself)
# if __name__ == '__main__':
#     ir = IncidentRespondr()
#     # ... example code ...
