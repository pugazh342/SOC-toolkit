# BlueDefenderX/utils/notifier.py
from utils.logger import bd_logger
import json

class Notifier:
    """
    Handles sending notifications for security alerts.
    Initially, this will log alerts. Can be extended for email, Slack, etc.
    """
    def __init__(self):
        bd_logger.info("Notifier initialized.")

    def send_alert(self, alert: dict):
        """
        Sends a security alert.
        For now, it logs the alert using the application logger.
        
        Args:
            alert (dict): The alert dictionary containing details like rule_id,
                          title, level, description, matched_events, etc.
        """
        if not isinstance(alert, dict):
            bd_logger.error(f"Invalid alert format provided to Notifier: {alert}")
            return

        alert_id = alert.get('alert_id', 'N/A')
        rule_title = alert.get('title', 'Unknown Rule')
        level = alert.get('level', 'info').upper()
        
        # Log the alert
        bd_logger.log(getattr(bd_logger, level, bd_logger.info), 
                      f"ALERT [{level}] - ID: {alert_id} - Rule: {rule_title}")
        bd_logger.debug(f"Full alert details: {json.dumps(alert, indent=2, default=str)}") # Log full alert in debug for richer detail

        # In a real scenario, you'd add logic here to send via:
        # - Email (using smtplib)
        # - Slack (using webhooks)
        # - Microsoft Teams
        # - PagerDuty / Opsgenie
        # - Write to a dedicated alerts file/database
        # Example placeholder for future expansion:
        # self._send_email(alert)
        # self._send_slack_message(alert)

    # Example of a private method for future email integration
    # def _send_email(self, alert):
    #     # Placeholder for email sending logic
    #     bd_logger.info(f"Simulating email send for alert: {alert.get('title')}")
    #     pass

    # Example of a private method for future Slack integration
    # def _send_slack_message(self, alert):
    #     # Placeholder for Slack webhook sending logic
    #     bd_logger.info(f"Simulating Slack message for alert: {alert.get('title')}")
    #     pass

# For direct testing of the notifier
if __name__ == '__main__':
    notifier = Notifier()
    sample_alert = {
        "alert_id": "ALERT_001",
        "rule_id": "T1110_001_brute_force_ssh",
        "title": "Potential SSH Brute Force Attempt",
        "description": "Multiple failed SSH login attempts from 192.168.1.100.",
        "level": "high",
        "timestamp": "2025-07-29T10:30:00Z",
        "matched_events": [
            # ... list of relevant log events ...
        ],
        "source_ip": "192.168.1.100",
        "count": 7
    }
    notifier.send_alert(sample_alert)

    sample_info_alert = {
        "alert_id": "INFO_001",
        "rule_id": "R002",
        "title": "New User Account Created",
        "description": "A new user 'testuser' was created on server 'app-server'.",
        "level": "info",
        "timestamp": "2025-07-29T10:35:00Z"
    }
    notifier.send_alert(sample_info_alert) 
