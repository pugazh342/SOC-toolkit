# BlueDefenderX/modules/trustcontroller.py
import json
import datetime as dt
import time
from datetime import datetime, timedelta
from collections import defaultdict
# Import other BlueDefenderX modules for potential integration
# from modules.uba_monitor import UBAMonitor
# from modules.policywatcher import PolicyWatcher
# from modules.threatfeedsync import ThreatFeedSync
# from modules.honeypotx import HoneyPotX
# from modules.endpointagent import EndpointAgent

from utils.logger import bd_logger

class TrustController:
    """
    Manages Zero Trust scores for entities (e.g., IPs, users).
    Calculates trust based on various security factors and events.
    """
    def __init__(self, config=None):
        """
        Initializes the TrustController.

        Args:
            config (dict, optional): Configuration dictionary.
                                     Defaults to None, using internal defaults.
        """
        self.config = config or self._get_default_config()
        # Store trust scores: { entity_id: { 'score': float, 'factors': dict, 'history': list, 'last_updated': str } }
        # For prototype, let's focus on IP addresses as entities
        self.trust_scores = defaultdict(lambda: {
            'score': 100.0, # Start with maximum trust
            'factors': {}, # e.g., {'ssh_brute_force': -20, 'compliance_pass': 5}
            'history': [], # List of { 'timestamp', 'score', 'reason' }
            'last_updated': None
        })
        # Define scoring weights/rules (simplified)
        self.scoring_rules = self.config.get('scoring_rules', self._get_default_scoring_rules())
        
        bd_logger.info("TrustController initialized.")

    def _get_default_config(self):
        """Provides default configuration values."""
        return {
            'default_score': 100.0,
            'minimum_score': 0.0,
            'maximum_score': 100.0,
            'score_decay_rate': 0.1, # % decay per day for inactivity
            'scoring_rules': self._get_default_scoring_rules()
        }

    def _get_default_scoring_rules(self):
        """Defines default scoring rules for various factors."""
        return {
            'ssh_brute_force_attempt': -15,
            'ssh_successful_login_new_ip': -5,
            'ssh_login_unusual_hour': -3,
            'compliance_check_failed': -10,
            'compliance_check_passed': 2,
            'threat_intel_match': -25,
            'honeypot_interaction': -20,
            'endpoint_agent_offline': -5,
            'endpoint_high_cpu': -2, # Per 10% above threshold
            'endpoint_high_memory': -2, # Per 10% above threshold
            # Add more rules as factors are integrated
        }

    def _calculate_score(self, current_score, factors):
        """
        Calculates the new trust score based on current score and contributing factors.

        Args:
            current_score (float): The current trust score.
            factors (dict): A dictionary of factor names and their raw values or flags.

        Returns:
            float: The calculated new score.
        """
        new_score = current_score
        applied_factors = {}

        for factor_name, factor_value in factors.items():
            rule_value = self.scoring_rules.get(factor_name, 0)
            
            if factor_name == 'ssh_brute_force_attempt':
                # factor_value is the count of attempts
                penalty = rule_value * factor_value
                new_score += penalty
                applied_factors[factor_name] = penalty

            elif factor_name in ['ssh_successful_login_new_ip', 'ssh_login_unusual_hour',
                                'compliance_check_failed', 'compliance_check_passed',
                                'threat_intel_match', 'honeypot_interaction']:
                # factor_value is boolean (True/False or 1/0)
                if factor_value:
                    new_score += rule_value
                    applied_factors[factor_name] = rule_value

            elif factor_name in ['endpoint_high_cpu', 'endpoint_high_memory']:
                # factor_value is the percentage over threshold (e.g., 15.5 for 15.5% over)
                if factor_value > 0:
                    # Apply penalty for every 10% over threshold
                    num_intervals = int(factor_value / 10)
                    penalty = rule_value * num_intervals
                    new_score += penalty
                    applied_factors[factor_name] = penalty

            elif factor_name == 'endpoint_agent_offline':
                 if factor_value: # If offline
                    new_score += rule_value
                    applied_factors[factor_name] = rule_value

            # Add more factor calculations as needed

        # Clamp score within min/max
        new_score = max(self.config['minimum_score'], min(self.config['maximum_score'], new_score))
        return new_score, applied_factors

    def update_trust_score(self, entity_id, entity_type, factors, reason="Score update"):
        """
        Updates the trust score for a specific entity based on new factors.

        Args:
            entity_id (str): The identifier for the entity (e.g., IP address '192.168.1.10').
            entity_type (str): The type of entity (e.g., 'ip', 'user').
            factors (dict): A dictionary of factors contributing to the score change.
            reason (str): A brief description of why the score is being updated.
        """
        # For simplicity, we'll use entity_id directly as the key, assuming unique IDs across types
        # A more robust system might use a tuple (entity_type, entity_id)
        key = f"{entity_type}:{entity_id}"
        
        bd_logger.debug(f"TrustController: Updating trust score for {key} with factors {factors}. Reason: {reason}")

        profile = self.trust_scores[key]
        current_score = profile['score']
        
        new_score, applied_factors = self._calculate_score(current_score, factors)
        
        # Update profile
        profile['score'] = new_score
        # Merge new factors with existing ones (or overwrite)
        profile['factors'].update(applied_factors) 
        profile['last_updated'] = datetime.utcnow().isoformat() + 'Z'
        
        # Add to history
        history_entry = {
            'timestamp': profile['last_updated'],
            'previous_score': current_score,
            'new_score': new_score,
            'factors_applied': applied_factors,
            'reason': reason
        }
        profile['history'].append(history_entry)
        # Keep only last N history entries to prevent unbounded growth
        max_history = self.config.get('max_history_entries', 20)
        if len(profile['history']) > max_history:
            profile['history'] = profile['history'][-max_history:]

        bd_logger.info(f"TrustController: Updated trust score for {key}. New Score: {new_score:.2f}. Factors: {applied_factors}. Reason: {reason}")
        return new_score

    def get_trust_score(self, entity_id, entity_type):
        """
        Retrieves the current trust score and details for an entity.

        Args:
            entity_id (str): The identifier for the entity.
            entity_type (str): The type of entity.

        Returns:
            dict: A dictionary containing the score, factors, history, etc. or None if not found.
        """
        key = f"{entity_type}:{entity_id}"
        return self.trust_scores.get(key)

    def get_all_scores(self):
        """
        Retrieves all trust scores.

        Returns:
            dict: A dictionary of all trust score profiles.
        """
        # Convert defaultdict to regular dict for easier handling outside
        return dict(self.trust_scores)

    def apply_score_decay(self):
        """
        Applies a decay to trust scores over time for entities that haven't been active.
        This encourages re-evaluation of trust.
        """
        decay_rate = self.config.get('score_decay_rate', 0.1) # e.g., 0.1 = 10% per day
        now = dt.datetime.utcnow()
        
        bd_logger.info("TrustController: Applying score decay...")
        decayed_count = 0
        for key, profile in self.trust_scores.items():
            last_update_str = profile.get('last_updated')
            if not last_update_str:
                continue # Skip if never updated
            
            try:
                last_update = dt.datetime.fromisoformat(last_update_str.replace('Z',''))
                days_since_update = (now - last_update).days
                
                if days_since_update > 0:
                    current_score = profile['score']
                    # Calculate decay: reduce score by decay_rate * days
                    decay_amount = current_score * decay_rate * days_since_update
                    # Ensure score doesn't go below minimum
                    new_score = max(self.config['minimum_score'], current_score - decay_amount)
                    
                    if new_score != current_score:
                        profile['score'] = new_score
                        profile['last_updated'] = now.isoformat() + 'Z'
                        decayed_count += 1
                        bd_logger.debug(f"TrustController: Applied decay to {key}. Old: {current_score:.2f}, New: {new_score:.2f} (Decay: {decay_amount:.2f})")
            except ValueError:
                bd_logger.warning(f"TrustController: Could not parse last_updated timestamp for {key}: {last_update_str}. Error:{e}")
            except Exception as e : 
                bd_logger.error(f"TrustController: Unexpected error applying decay to {key}: {e}", exe_info=True)

        bd_logger.info(f"TrustController: Score decay applied to {decayed_count} entities.")

    def generate_report(self, entity_id=None, entity_type=None):
        """
        Generates a simple text report of trust scores or a specific entity's score.

        Args:
            entity_id (str, optional): Specific entity ID to report on.
            entity_type (str, optional): Specific entity type to report on.

        Returns:
            str: A formatted report string.
        """
        report_lines = ["--- Trust Score Report ---"]
        
        if entity_id and entity_type:
            key = f"{entity_type}:{entity_id}"
            profile = self.trust_scores.get(key)
            if not profile:
                return f"No trust score found for {entity_type}:{entity_id}"
            
            report_lines.append(f"Entity: {entity_type}:{entity_id}")
            report_lines.append(f"Current Score: {profile['score']:.2f}")
            report_lines.append("Contributing Factors:")
            for factor, value in profile['factors'].items():
                report_lines.append(f"  - {factor}: {value}")
            report_lines.append("Score History (Recent):")
            for entry in profile['history'][-5:]: # Show last 5
                report_lines.append(f"  - {entry['timestamp']}: {entry['previous_score']:.2f} -> {entry['new_score']:.2f} ({entry['reason']})")
        else:
            # Report on all scores
            scores = self.get_all_scores()
            report_lines.append(f"Total Entities Scored: {len(scores)}")
            report_lines.append("-" * 25)
            for key, profile in scores.items():
                report_lines.append(f"{key}: Score {profile['score']:.2f} (Last Updated: {profile['last_updated']})")
        
        report_lines.append("-" * 25)
        return "\n".join(report_lines)


# Example usage (if run directly)
if __name__ == '__main__':
    import logging
    # Ensure logger is set up for standalone run
    if not bd_logger.handlers:
        logging.basicConfig(level=logging.INFO)

    tc = TrustController()

    print("--- Updating Trust Scores ---")
    # Simulate some events affecting trust scores
    
    # 1. SSH Brute Force Attempt
    ssh_brute_factors = {'ssh_brute_force_attempt': 8} # 8 failed attempts
    tc.update_trust_score('10.0.0.50', 'ip', ssh_brute_factors, "8 SSH brute force attempts detected")

    # 2. Login from New IP
    new_ip_factors = {'ssh_successful_login_new_ip': True}
    tc.update_trust_score('10.0.0.50', 'ip', new_ip_factors, "Successful login from new IP")

    # 3. Compliance Check Failed
    compliance_factors = {'compliance_check_failed': True}
    tc.update_trust_score('server01', 'host', compliance_factors, "CIS benchmark check failed")

    # 4. Threat Intel Match
    ti_factors = {'threat_intel_match': True}
    tc.update_trust_score('192.168.1.100', 'ip', ti_factors, "IP matched in threat feed")

    # 5. Honeypot Interaction
    hp_factors = {'honeypot_interaction': True}
    tc.update_trust_score('10.10.10.100', 'ip', hp_factors, "Interaction with honeypot detected")

    # 6. Endpoint Agent Offline
    endpoint_factors = {'endpoint_agent_offline': True}
    tc.update_trust_score('laptop_user1', 'device', endpoint_factors, "Endpoint agent reported offline")

    print("\n--- Generating Reports ---")
    # Report on a specific IP
    print(tc.generate_report('10.0.0.50', 'ip'))
    
    print("\n--- Generating Full Report ---")
    # Report on all scores
    print(tc.generate_report())

    print("\n--- Applying Score Decay ---")
    # Apply decay (conceptual, as time hasn't passed in simulation)
    tc.apply_score_decay()
    print("Score decay process completed (no effect in static simulation).")
