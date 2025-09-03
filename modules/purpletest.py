# BlueDefenderX/modules/purpletest.py
import os
import time
import tempfile
from datetime import datetime, timedelta
from utils.logger import bd_logger

# Import BlueDefenderX modules for integration (conceptual)
# In a full integration, you might interact directly with these or use APIs
# from modules.logdefenderx import LogDefenderX
# from modules.siemlite import SIEMLite

class PurpleTest:
    """
    Simulates Red Team operations and validates Blue Team detections.
    Performs Purple Team exercises by running attack simulations
    and checking if BlueDefenderX detects them.
    """
    def __init__(self, config=None):
        """
        Initializes the PurpleTest framework.

        Args:
            config (dict, optional): Configuration dictionary.
                                     Defaults to None, using internal defaults.
        """
        self.config = config or self._get_default_config()
        self.test_results = []
        # Define test scenarios
        self.test_scenarios = self._define_test_scenarios()
        bd_logger.info("PurpleTest framework initialized.")

    def _get_default_config(self):
        """Provides default configuration values."""
        return {
            'simulation_log_path': 'purple_test_simulation.log', # Default path for simulated logs
            'check_delay_seconds': 5, # Time to wait after simulation before checking for alerts
            # Add more config options as needed
        }

    def _define_test_scenarios(self):
        """
        Defines the built-in test scenarios.
        Each scenario is a dictionary with details on how to simulate and validate.

        Returns:
            dict: A dictionary of test scenario definitions.
        """
        return {
            "ssh_brute_force_simulation": {
                "name": "SSH Brute Force Simulation",
                "description": "Simulates multiple failed SSH login attempts from a single IP.",
                "simulate_func": self._simulate_ssh_brute_force,
                "validate_func": self._validate_ssh_brute_force_alert,
                "expected_rule_id": "T1110_001_brute_force_ssh", # Based on rules.yaml
                "severity": "high"
            },
            # Add more scenarios here, e.g., for honeypot interaction, web scan simulation
            # "web_app_scan_simulation": {
            #     "name": "Web Application Scan Simulation",
            #     "description": "Simulates common web scanning activity.",
            #     "simulate_func": self._simulate_web_scan,
            #     "validate_func": self._validate_web_scan_alert,
            #     "expected_rule_id": "T1071.001_web_scan_detected", # Hypothetical rule
            #     "severity": "medium"
            # }
        }

    def _simulate_ssh_brute_force(self, params):
        """
        Simulates an SSH brute force attack by writing mock log entries to a file.

        Args:
            params (dict): Parameters for the simulation (e.g., target_ip, log_path).

        Returns:
            dict: A dictionary containing simulation results (e.g., log file path, entries written).
        """
        log_path = params.get('log_path', self.config['simulation_log_path'])
        target_ip = params.get('target_ip', '192.168.1.200') # Default target
        attacker_ip = params.get('attacker_ip', '10.0.0.50') # Simulated attacker IP
        num_attempts = params.get('num_attempts', 10) # Number of failed attempts
        base_port = params.get('base_port', 50000)

        bd_logger.info(f"PurpleTest: Simulating SSH brute force from {attacker_ip} to {target_ip} ({num_attempts} attempts). Log: {log_path}")

        # Generate mock SSH log lines
        mock_logs = []
        base_time = datetime.now() - timedelta(seconds=num_attempts * 2) # Stagger timestamps
        for i in range(num_attempts):
            timestamp = (base_time + timedelta(seconds=i * 2)).strftime("%b %d %H:%M:%S")
            port = base_port + i
            # Mimic the format parsed by LogDefenderX
            log_line = f"{timestamp} {target_ip} sshd[{1000+i}]: Failed password for invalid user testuser{i} from {attacker_ip} port {port} ssh2"
            mock_logs.append(log_line)

        try:
            # Write logs to the specified file
            with open(log_path, 'w') as f:
                for log_line in mock_logs:
                    f.write(log_line + "\n")
            bd_logger.info(f"PurpleTest: Wrote {len(mock_logs)} mock SSH log entries to {log_path}")
            return {
                "status": "success",
                "log_file": log_path,
                "entries_written": len(mock_logs),
                "attacker_ip": attacker_ip
            }
        except Exception as e:
            bd_logger.error(f"PurpleTest: Failed to write mock logs to {log_path}: {e}")
            return {
                "status": "error",
                "error": str(e),
                "log_file": log_path
            }

    def _validate_ssh_brute_force_alert(self, simulation_result, alert_cache):
        """
        Validates if the SSH brute force simulation triggered the expected alert.

        Args:
            simulation_result (dict): The result dictionary from the simulation function.
            alert_cache (list): A list of alert dictionaries (e.g., from st.session_state.alerts_cache).

        Returns:
            dict: A dictionary containing validation results (passed/failed, reason).
        """
        if simulation_result.get('status') != 'success':
            return {
                "passed": False,
                "reason": f"Simulation failed: {simulation_result.get('error')}"
            }

        expected_rule_id = self.test_scenarios["ssh_brute_force_simulation"]["expected_rule_id"]
        attacker_ip = simulation_result.get('attacker_ip')

        # Check alert cache for the expected rule ID and IP
        matching_alerts = [
            alert for alert in alert_cache
            if alert.get('rule_id') == expected_rule_id and
               any(event.get('src_ip') == attacker_ip for event in alert.get('source_events', []))
        ]

        if matching_alerts:
            alert = matching_alerts[0]
            count = alert.get('details', {}).get('count', 'N/A')
            threshold = alert.get('details', {}).get('threshold', 'N/A')
            return {
                "passed": True,
                "reason": f"Alert '{expected_rule_id}' generated for IP {attacker_ip}. Count: {count}, Threshold: {threshold}.",
                "alert": alert # Include the alert for further inspection if needed
            }
        else:
            return {
                "passed": False,
                "reason": f"No alert '{expected_rule_id}' found for IP {attacker_ip} in the provided alert cache."
            }

    # Placeholder methods for other simulations (not implemented yet)
    def _simulate_web_scan(self, params):
        """Placeholder for web scan simulation."""
        bd_logger.warning("Web scan simulation not yet implemented.")
        return {"status": "not_implemented"}

    def _validate_web_scan_alert(self, simulation_result, alert_cache):
        """Placeholder for web scan alert validation."""
        return {"passed": False, "reason": "Validation for web scan not yet implemented."}

    def run_test_scenario(self, scenario_name, simulation_params=None):
        """
        Runs a single test scenario: simulate -> wait -> validate.

        Args:
            scenario_name (str): The name of the scenario to run (key in test_scenarios).
            simulation_params (dict, optional): Parameters to pass to the simulation function.

        Returns:
            dict: A dictionary containing the overall test result.
        """
        if scenario_name not in self.test_scenarios:
            result = {
                "scenario": scenario_name,
                "status": "error",
                "details": f"Test scenario '{scenario_name}' not found."
            }
            self.test_results.append(result)
            return result

        scenario = self.test_scenarios[scenario_name]
        bd_logger.info(f"PurpleTest: Running scenario '{scenario['name']}'")

        # 1. Simulate the attack
        sim_params = simulation_params or {}
        simulation_result = scenario['simulate_func'](sim_params)

        # 2. Wait for detection (conceptual)
        # In a real integration, you might trigger a re-parse or correlation here
        # and then wait or poll for results.
        delay = self.config.get('check_delay_seconds', 5)
        bd_logger.info(f"PurpleTest: Waiting {delay} seconds for detection...")
        time.sleep(delay)

        # 3. Validate the result (conceptual)
        # This requires access to the current alert state from BlueDefenderX
        # For prototype, we'll pass an empty list or mock data.
        # In a full integration, this would be `st.session_state.alerts_cache` or similar.
        # mock_alert_cache = [
        #     {
        #         "rule_id": "T1110_001_brute_force_ssh",
        #         "source_events": [{"src_ip": "10.0.0.50"}],
        #         "details": {"count": 10, "threshold": 5}
        #     }
        # ] # Example of a matching alert
        mock_alert_cache = [] # Placeholder - in reality, get this from BlueDefenderX state
        validation_result = scenario['validate_func'](simulation_result, mock_alert_cache)

        # 4. Compile final result
        overall_passed = validation_result.get('passed', False)
        result = {
            "scenario": scenario_name,
            "name": scenario['name'],
            "description": scenario['description'],
            "simulation_result": simulation_result,
            "validation_result": validation_result,
            "passed": overall_passed,
            "timestamp": datetime.utcnow().isoformat() + 'Z'
        }
        self.test_results.append(result)
        status_log = "PASSED" if overall_passed else "FAILED"
        bd_logger.info(f"PurpleTest: Scenario '{scenario['name']}' {status_log}. Reason: {validation_result.get('reason', 'N/A')}")
        return result

    def run_all_tests(self, common_simulation_params=None):
        """
        Runs all defined test scenarios.

        Args:
            common_simulation_params (dict, optional): Common parameters to pass to all simulations.

        Returns:
            list: A list of dictionaries, each containing the result of a test.
        """
        bd_logger.info("PurpleTest: Starting execution of all test scenarios.")
        results = []
        for scenario_name in self.test_scenarios:
            # Merge common params with scenario-specific ones if needed
            params = common_simulation_params or {}
            result = self.run_test_scenario(scenario_name, params)
            results.append(result)
        bd_logger.info("PurpleTest: Completed execution of all test scenarios.")
        return results

    def get_test_results(self):
        """Returns the results from the last run of tests."""
        return self.test_results

    def generate_report(self, results=None):
        """
        Generates a simple text report of test results.

        Args:
            results (list, optional): List of test results. Uses internal results if None.

        Returns:
            str: A formatted report string.
        """
        if results is None:
            results = self.test_results

        if not results:
            return "No test results available."

        passed_count = sum(1 for r in results if r.get('passed'))
        total_count = len(results)

        report_lines = ["--- Purple Team Test Report ---"]
        report_lines.append(f"Total Tests Run: {total_count}")
        report_lines.append(f"Passed: {passed_count}")
        report_lines.append(f"Failed: {total_count - passed_count}")
        report_lines.append("-" * 30)

        for result in results:
            status_icon = "✅" if result.get('passed') else "❌"
            report_lines.append(f"{status_icon} [{result['scenario']}] {result['name']}")
            report_lines.append(f"    Description: {result['description']}")
            report_lines.append(f"    Status: {'PASSED' if result.get('passed') else 'FAILED'}")
            report_lines.append(f"    Reason: {result.get('validation_result', {}).get('reason', 'N/A')}")
            # Optionally add more details from simulation_result
            # sim_res = result.get('simulation_result', {})
            # if sim_res.get('status') == 'success':
            #     report_lines.append(f"    Simulated: {sim_res.get('entries_written')} log entries.")
            report_lines.append("-" * 20)

        report_lines.append("-" * 30)
        return "\n".join(report_lines)


# Example usage (if run directly)
if __name__ == '__main__':
    import logging
    # Ensure logger is set up for standalone run
    if not bd_logger.handlers:
        logging.basicConfig(level=logging.INFO)

    pt = PurpleTest()

    print("--- Running SSH Brute Force Simulation Test ---")
    # Run a specific test with custom parameters
    test_params = {
        'log_path': 'test_ssh_brute_force.log',
        'attacker_ip': '10.10.10.100', # Unique IP for this test
        'num_attempts': 8 # Slightly above threshold of 5
    }
    result = pt.run_test_scenario("ssh_brute_force_simulation", test_params)
    print(f"Test Result: {result}")

    print("\n--- Running All Tests ---")
    # Run all tests with some common parameters
    common_params = {
        'log_path': 'purple_test_run.log' # Default log path for simulations
    }
    all_results = pt.run_all_tests(common_params)
    print(pt.generate_report(all_results))

    # Clean up test log file
    test_log_file = test_params.get('log_path', 'test_ssh_brute_force.log')
    if os.path.exists(test_log_file):
        os.remove(test_log_file)
        print(f"\nCleaned up test log file: {test_log_file}")

    common_log_file = common_params.get('log_path', 'purple_test_run.log')
    if os.path.exists(common_log_file) and common_log_file != test_log_file:
        os.remove(common_log_file)
        print(f"Cleaned up common log file: {common_log_file}")
    print("\n--- PurpleTest Module Execution Complete ---")