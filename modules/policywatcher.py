# BlueDefenderX/modules/policywatcher.py
import yaml
import subprocess
import re
import platform
from utils.logger import bd_logger

class PolicyWatcher:
    """
    Tracks compliance with security policies/baselines (CIS, NIST).
    Executes checks defined in config/compliance_baselines.yaml.
    """
    def __init__(self, config_path="config/compliance_baselines.yaml"):
        """
        Initializes the PolicyWatcher by loading baselines.

        Args:
            config_path (str): Path to the YAML file containing compliance baselines.
        """
        self.config_path = config_path
        self.baselines = self._load_baselines()
        self.last_run_results = []
        bd_logger.info("PolicyWatcher initialized.")

    def _load_baselines(self):
        """
        Loads compliance baselines from a YAML configuration file.

        Returns:
            dict: A dictionary of baselines and their checks.
        """
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
                baselines = config.get('baselines', {})
                # Count total enabled checks
                total_checks = sum(1 for checks in baselines.values() for check in checks if check.get('enabled', False))
                bd_logger.info(f"Loaded compliance baselines. Total enabled checks: {total_checks}")
                return baselines
        except FileNotFoundError:
            bd_logger.error(f"Compliance baselines file not found: {self.config_path}")
            return {}
        except yaml.YAMLError as e:
            bd_logger.error(f"Error parsing YAML baselines file {self.config_path}: {e}")
            return {}
        except Exception as e:
            bd_logger.error(f"Unexpected error loading compliance baselines: {e}")
            return {}

    def _evaluate_check_result(self, check_config, actual_output):
        """
        Evaluates the result of a check against its expected outcome.

        Args:
            check_config (dict): The configuration for the specific check.
            actual_output (str): The output captured from running the check.

        Returns:
            tuple: (bool: passed, str: reason)
        """
        expected_exact = check_config.get('expected_output')
        expected_regex = check_config.get('expected_output_regex')
        expected_contains = check_config.get('expected_output_contains')

        # Normalize newlines in actual output for comparison
        normalized_output = actual_output.strip()

        # --- Evaluation Logic ---
        if expected_exact is not None:
            if normalized_output == expected_exact.strip():
                return True, f"Output matches expected value: '{expected_exact}'"
            else:
                return False, f"Output mismatch. Expected: '{expected_exact}', Got: '{normalized_output}'"

        elif expected_regex is not None:
            try:
                if re.search(expected_regex, normalized_output):
                    return True, f"Output matches regex: '{expected_regex}'"
                else:
                    return False, f"Output does not match regex: '{expected_regex}'. Got: '{normalized_output}'"
            except re.error as e:
                return False, f"Invalid regex '{expected_regex}': {e}"

        elif expected_contains is not None:
            if expected_contains in normalized_output:
                return True, f"Output contains expected string: '{expected_contains}'"
            else:
                return False, f"Output does not contain expected string: '{expected_contains}'. Got: '{normalized_output}'"

        else:
            # If no expected output is defined, assume check passes if it ran without error
            # This is a weak check, better to define expectations.
            return True, "Check executed successfully (no specific expectation defined)."

    def _run_single_check(self, check_config):
        """
        Runs a single compliance check.

        Args:
            check_config (dict): The configuration for the check.

        Returns:
            dict: A dictionary representing the result of the check.
        """
        check_id = check_config.get('id', 'Unknown')
        description = check_config.get('description', 'No description')
        check_type = check_config.get('check_type', 'unknown')
        check_command = check_config.get('check_command', '')
        severity = check_config.get('severity', 'low')

        bd_logger.debug(f"Running compliance check [{check_id}]: {description}")

        result = {
            "check_id": check_id,
            "description": description,
            "severity": severity,
            "check_type": check_type,
            "command": check_command,
            "status": "unknown", # passed, failed, error
            "reason": "",
            "actual_output": "",
            "timestamp": ""
        }

        try:
            if check_type == "command":
                if not check_command:
                    result['status'] = 'error'
                    result['reason'] = "Check type is 'command' but 'check_command' is empty."
                    bd_logger.error(f"Check {check_id} failed: {result['reason']}")
                    return result

                # --- Execute the command ---
                # Note: shell=True can be a security risk. For production, consider safer alternatives.
                # For a prototype on a trusted system, it's often acceptable.
                # Consider using `shlex.split()` for safer command parsing if not using shell=True.
                bd_logger.debug(f"Executing command for check {check_id}: {check_command}")
                
                # Add a timeout to prevent hanging
                proc = subprocess.run(
                    check_command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, # Capture stderr with stdout
                    text=True,
                    timeout=30 # 30 second timeout
                )
                
                output = proc.stdout
                result['actual_output'] = output
                result['timestamp'] = bd_logger.handlers[0].formatter.formatTime(logging.LogRecord('', 0, '', 0, '', (), None)) if bd_logger.handlers else "N/A"

                if proc.returncode == 0:
                    # Command executed successfully, evaluate output
                    passed, reason = self._evaluate_check_result(check_config, output)
                    result['status'] = 'passed' if passed else 'failed'
                    result['reason'] = reason
                    if passed:
                        bd_logger.info(f"Compliance check [{check_id}] PASSED: {reason}")
                    else:
                        bd_logger.warning(f"Compliance check [{check_id}] FAILED: {reason}")
                else:
                    # Command failed to execute (non-zero exit code)
                    result['status'] = 'error'
                    result['reason'] = f"Command failed with exit code {proc.returncode}. Output: {output[:200]}..." # Truncate long output
                    bd_logger.error(f"Compliance check [{check_id}] ERROR: {result['reason']}")

            elif check_type == "manual":
                # Manual checks require human review. Mark as info/pending.
                result['status'] = 'manual_review'
                result['reason'] = "This check requires manual verification."
                bd_logger.info(f"Compliance check [{check_id}] requires MANUAL REVIEW: {description}")

            elif check_type == "file_content":
                # Placeholder for future implementation
                # This would involve reading a file and checking its content
                result['status'] = 'error'
                result['reason'] = "Check type 'file_content' not yet implemented."
                bd_logger.warning(f"Compliance check [{check_id}] not run: {result['reason']}")

            else:
                result['status'] = 'error'
                result['reason'] = f"Unknown check type: {check_type}"
                bd_logger.error(f"Compliance check [{check_id}] ERROR: {result['reason']}")

        except subprocess.TimeoutExpired:
            result['status'] = 'error'
            result['reason'] = f"Command timed out after 30 seconds."
            bd_logger.error(f"Compliance check [{check_id}] ERROR: {result['reason']}")
        except Exception as e:
            result['status'] = 'error'
            result['reason'] = f"Exception occurred while running check: {str(e)}"
            bd_logger.error(f"Compliance check [{check_id}] ERROR: {result['reason']}", exc_info=True) # Log full traceback

        return result

    def run_checks(self, baseline_name=None):
        """
        Runs compliance checks.

        Args:
            baseline_name (str, optional): Specific baseline to run (e.g., 'cis_linux').
                                         If None, runs all enabled checks from all baselines.

        Returns:
            list: A list of dictionaries, each representing the result of a check.
        """
        bd_logger.info(f"PolicyWatcher: Starting compliance check run. Baseline: {baseline_name or 'All Enabled'}")
        results = []

        # Determine which checks to run
        checks_to_run = []
        if baseline_name:
            checks_to_run.extend(self.baselines.get(baseline_name, []))
        else:
            for checks in self.baselines.values():
                checks_to_run.extend(checks)

        # Filter for enabled checks
        enabled_checks = [check for check in checks_to_run if check.get('enabled', False)]

        if not enabled_checks:
            bd_logger.warning("No enabled compliance checks found to run.")
            return results

        bd_logger.info(f"Running {len(enabled_checks)} enabled compliance checks...")

        for check_config in enabled_checks:
            # Skip checks not relevant to the current OS (basic check)
            # A more robust system would have OS-specific baselines or tags
            if platform.system() != "Linux" and "Linux" in check_config.get('id', ''):
                 bd_logger.debug(f"Skipping Linux-specific check {check_config['id']} on {platform.system()}")
                 continue

            result = self._run_single_check(check_config)
            results.append(result)

        self.last_run_results = results # Store for later access
        passed = sum(1 for r in results if r['status'] == 'passed')
        failed = sum(1 for r in results if r['status'] == 'failed')
        errors = sum(1 for r in results if r['status'] == 'error')
        manual = sum(1 for r in results if r['status'] == 'manual_review')

        bd_logger.info(f"PolicyWatcher: Compliance check run completed. "
                      f"Total: {len(results)}, Passed: {passed}, Failed: {failed}, Errors: {errors}, Manual: {manual}")
        return results

    def get_last_run_results(self):
        """Returns the results from the last run of checks."""
        return self.last_run_results

    def generate_report(self, results=None):
        """
        Generates a simple text report of compliance check results.

        Args:
            results (list, optional): List of check results. Uses last run results if None.

        Returns:
            str: A formatted report string.
        """
        if results is None:
            results = self.last_run_results

        if not results:
            return "No compliance check results available."

        report_lines = ["--- Compliance Check Report ---"]
        report_lines.append(f"Total Checks Run: {len(results)}")
        report_lines.append(f"Passed: {sum(1 for r in results if r['status'] == 'passed')}")
        report_lines.append(f"Failed: {sum(1 for r in results if r['status'] == 'failed')}")
        report_lines.append(f"Errors: {sum(1 for r in results if r['status'] == 'error')}")
        report_lines.append(f"Manual Review: {sum(1 for r in results if r['status'] == 'manual_review')}")
        report_lines.append("-" * 30)

        for result in results:
            status_icon = {
                'passed': '✅',
                'failed': '❌',
                'error': '⚠️',
                'manual_review': '📘'
            }.get(result['status'], '❓')
            report_lines.append(f"{status_icon} [{result['check_id']}] ({result['severity'].upper()}) {result['description']}")
            if result['status'] in ['failed', 'error', 'manual_review']:
                report_lines.append(f"    Reason: {result['reason']}")
            # Optionally add command and output for failed/error checks
            # if result['status'] in ['failed', 'error'] and result.get('actual_output'):
            #     report_lines.append(f"    Command: {result['command']}")
            #     report_lines.append(f"    Output: {result['actual_output'][:200]}...") # Truncate

        report_lines.append("-" * 30)
        return "\n".join(report_lines)


# Example usage (if run directly)
if __name__ == '__main__':
    import logging
    # Ensure logger is set up for standalone run
    # (In the full app, bd_logger is already configured)
    if not bd_logger.handlers:
        logging.basicConfig(level=logging.INFO)

    pw = PolicyWatcher()

    print("--- Running CIS Linux Checks ---")
    # Run only CIS Linux checks
    cis_results = pw.run_checks(baseline_name="cis_linux")
    print(pw.generate_report(cis_results))

    print("\n--- Running NIST Checks ---")
    # Run only NIST checks
    nist_results = pw.run_checks(baseline_name="nist_800_53")
    print(pw.generate_report(nist_results))

    print("\n--- Running All Enabled Checks ---")
    # Run all enabled checks
    all_results = pw.run_checks()
    print(pw.generate_report(all_results))
