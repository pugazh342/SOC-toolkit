# BlueDefenderX/modules/siemlite.py
import yaml
from datetime import datetime, timedelta
from collections import defaultdict
from utils.logger import bd_logger

class SIEMLite:
    def __init__(self, rules_config_path="config/rules.yaml"):
        self.rules_config_path = rules_config_path
        self.rules = self.load_rules()
        self.alerts = []
        bd_logger.info("SIEMLite initialized.")

    def load_rules(self):
        """Loads Sigma rules from YAML config."""
        try:
            with open(self.rules_config_path, 'r') as f:
                config = yaml.safe_load(f)
                rules = config.get('rules', [])
                bd_logger.info(f"Loaded {len(rules)} rules from {self.rules_config_path}")
                return rules
        except FileNotFoundError:
            bd_logger.error(f"Rules file not found: {self.rules_config_path}")
            return []
        except yaml.YAMLError as e:
            bd_logger.error(f"Error parsing YAML rules file: {e}")
            return []
        except Exception as e:
            bd_logger.error(f"Unexpected error loading rules: {e}")
            return []

    def _match_selection(self, event, selection_criteria):
        """Helper to check if an event matches selection criteria."""
        # bd_logger.debug(f"_match_selection called with event: {event} and criteria: {selection_criteria}")
        for key, value_pattern in selection_criteria.items():
            # bd_logger.debug(f"Checking key: '{key}', pattern: '{value_pattern}'")
            if key in event:
                event_value = str(event[key])
                # bd_logger.debug(f"Event has key '{key}' with value: '{event_value}' (type: {type(event_value)})")
                if isinstance(value_pattern, str):
                    # bd_logger.debug(f"Checking if pattern '{value_pattern}' is in event value '{event_value}'")
                    if value_pattern not in event_value:
                        # bd_logger.debug(f"Pattern '{value_pattern}' NOT found in '{event_value}'. Returning False.")
                        return False
                    # else:
                    #     bd_logger.debug(f"Pattern '{value_pattern}' FOUND in '{event_value}'.")
                # Add more complex matching logic here if needed (regex, etc.)
            else:
                # bd_logger.debug(f"Event does not have required key '{key}'. Returning False.")
                return False
        # bd_logger.debug("All selection criteria matched. Returning True.")
        return True

    def evaluate_rule(self, rule, parsed_events):
        """
        Evaluates a single rule against a list of parsed events.
        This is a simplified evaluator for basic conditions.
        """
        rule_id = rule.get('id', 'unknown')
        title = rule.get('title', 'Untitled Rule')
        level = rule.get('level', 'low')
        description = rule.get('description', '')
        detection = rule.get('detection', {})
        condition = detection.get('condition', '').strip()
        timeframe_str = detection.get('timeframe', '1h') # Default 1 hour

        bd_logger.debug(f"Evaluating rule: {rule_id} - {title}")
        bd_logger.debug(f"Rule detection config: {detection}")

        # --- Simplified Timeframe Parsing ---
        time_multipliers = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400}
        unit = timeframe_str[-1]
        try:
            value = int(timeframe_str[:-1]) if timeframe_str[:-1].isdigit() else 1
        except ValueError:
            value = 1
        timeframe_seconds = value * time_multipliers.get(unit, 3600) # Default to hour

        # --- Simplified Condition Evaluation ---
        try:
            if "count() by" in condition and ">" in condition:
                # Example: "selection | count() by src_ip > 5"
                # Find the part after '|'
                parts = condition.split('|')
                if len(parts) < 2:
                     raise ValueError("Invalid count condition format")

                count_part = parts[1].strip()
                # Extract field (src_ip) and threshold (5)
                # This is very fragile and simplified
                if 'by' in count_part and '>' in count_part:
                    by_field_part, threshold_part = count_part.split('>')
                    by_field = by_field_part.split('by')[-1].strip() if 'by' in by_field_part else None
                    try:
                        threshold = int(threshold_part.strip())
                    except ValueError:
                        bd_logger.error(f"Invalid threshold in rule {rule_id}: {threshold_part}")
                        return

                    # Filter events matching the 'selection' criteria
                    selection_criteria = detection.get('selection', {})
                    bd_logger.debug(f"Selection criteria for rule {rule_id}: {selection_criteria}")

                    matching_events = []
                    for event in parsed_events:
                        bd_logger.debug(f"Checking event for rule {rule_id}: {event}")
                        if self._match_selection(event, selection_criteria):
                            bd_logger.debug(f"Event matched selection for rule {rule_id}")
                            matching_events.append(event)
                        #else:
                        #    bd_logger.debug(f"Event did NOT match selection for rule {rule_id}")

                    bd_logger.info(f"Rule {rule_id}: Found {len(matching_events)} matching events out of {len(parsed_events)} total events.")

                    # Group and count by the specified field within timeframe
                    # Note: Simplified, ignores actual timestamps for now
                    grouped_counts = defaultdict(int)
                    for event in matching_events:
                        key_value = event.get(by_field)
                        if key_value:
                            grouped_counts[key_value] += 1

                    bd_logger.debug(f"Rule {rule_id}: Grouped counts by {by_field}: {dict(grouped_counts)}")

                    # --- Generate alerts for counts exceeding threshold ---
                    # This is the section we are adding detailed logging to.
                    alert_count = 0
                    bd_logger.debug(f"Rule {rule_id}: Checking counts against threshold {threshold}")
                    for key_val, count in grouped_counts.items():
                        bd_logger.debug(f"Rule {rule_id}: Checking key_val='{key_val}', count={count}")
                        if count > threshold:
                            alert_count += 1
                            bd_logger.debug(f"Rule {rule_id}: Count {count} > Threshold {threshold}. Preparing to create alert #{alert_count}.")

                            # --- ADD DETAILED LOGGING FOR ALERT CREATION ---
                            alert_details = {
                                "matched_field": by_field,
                                "matched_value": key_val,
                                "count": count,
                                "threshold": threshold,
                                "timeframe_seconds": timeframe_seconds
                            }
                            bd_logger.debug(f"Rule {rule_id}: Alert details prepared: {alert_details}")

                            source_events_for_alert = [e for e in matching_events if e.get(by_field) == key_val]
                            bd_logger.debug(f"Rule {rule_id}: Found {len(source_events_for_alert)} source events for this alert.")

                            alert = {
                                "rule_id": rule_id,
                                "title": title,
                                "description": description,
                                "severity": level,
                                "timestamp": datetime.utcnow().isoformat() + 'Z',
                                "details": alert_details,
                                "source_events": source_events_for_alert
                            }
                            bd_logger.debug(f"Rule {rule_id}: Alert dictionary created.")

                            # --- CRITICAL LOGGING AROUND APPEND ---
                            initial_alerts_len = len(self.alerts)
                            bd_logger.debug(f"Rule {rule_id}: Current number of alerts in self.alerts before append: {initial_alerts_len}")
                            self.alerts.append(alert)
                            bd_logger.debug(f"Rule {rule_id}: Alert appended. New length of self.alerts: {len(self.alerts)}. Expected: {initial_alerts_len + 1}")
                            # --- END CRITICAL LOGGING ---

                            bd_logger.warning(f"Alert generated by rule {rule_id}: {title} for {key_val} (Count: {count})")
                        else:
                            bd_logger.debug(f"Rule {rule_id}: Count {count} <= Threshold {threshold}. No alert.")

                    bd_logger.info(f"Rule {rule_id}: Generated {alert_count} alerts for count condition.")
                    # --- End Alert Generation ---

                else:
                    bd_logger.error(f"Malformed count condition in rule {rule_id}: {count_part}")

            # Add more condition types as needed (e.g., simple boolean matches)
            # For now, we assume rules are of the count type or similar simple aggregations.

        except Exception as e:
            bd_logger.error(f"Error evaluating rule {rule_id} ({title}): {e}", exc_info=True) # Log full traceback


    def correlate_events(self, parsed_events):
        """Runs all loaded rules against the parsed events."""
        self.alerts = [] # Clear previous alerts
        if not self.rules:
            bd_logger.warning("No rules loaded, skipping correlation.")
            return []

        bd_logger.info(f"Correlating {len(parsed_events)} events against {len(self.rules)} rules.")
        for rule in self.rules:
            self.evaluate_rule(rule, parsed_events)

        bd_logger.info(f"Correlation complete. Generated {len(self.alerts)} alerts.")
        return self.alerts

    def get_alerts(self):
        """Returns the list of generated alerts."""
        return self.alerts

# Example usage message
if __name__ == '__main__':
    print("SIEMLite module loaded successfully for direct execution/testing.")
    # Actual testing should ideally be done via the main app or dedicated test scripts.
