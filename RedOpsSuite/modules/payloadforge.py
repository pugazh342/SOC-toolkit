# RedOpsSuite/modules/payloadforge.py
import base64
import binascii
import urllib.parse
import html
import codecs
import json
import os
import uuid
import logging
from datetime import datetime

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

class PayloadForge:
    """
    A basic payload crafting system for RedOpsSuite.
    Generates payloads from templates, fuzzing patterns, and applies encodings.
    """

    def __init__(self, templates_dir="config/payload_templates"):
        """
        Initializes the PayloadForge.

        Args:
            templates_dir (str): Path to the directory containing payload templates.
                                 Default is 'config/payload_templates'.
        """
        self.templates_dir = templates_dir
        self.supported_encodings = [
            'base64', 'hex', 'url', 'html_entity', 'unicode_escape',
            'rot13'
            # 'xor_simple' could be added, but requires a key
        ]
        logger.info(f"PayloadForge module initialized with templates_dir={templates_dir}")

    def _apply_encoding(self, payload_str, encoding_type, **kwargs):
        """
        Applies a single encoding technique to a string payload.

        Args:
            payload_str (str): The payload string to encode.
            encoding_type (str): The type of encoding to apply.
            **kwargs: Additional arguments for specific encodings (e.g., 'key' for xor).

        Returns:
            str or None: The encoded payload string, or None on error.
        """
        try:
            if encoding_type == 'base64':
                # Encode string to bytes, then B64 encode bytes, then back to string
                encoded_bytes = base64.b64encode(payload_str.encode('utf-8'))
                return encoded_bytes.decode('ascii')

            elif encoding_type == 'hex':
                # Encode string to bytes, then to hex string
                return payload_str.encode('utf-8').hex()

            elif encoding_type == 'url':
                # URL encode the string
                return urllib.parse.quote_plus(payload_str) # quote_plus encodes spaces as +

            elif encoding_type == 'html_entity':
                # Encode characters as HTML entities
                return html.escape(payload_str, quote=True)

            elif encoding_type == 'unicode_escape':
                # Encode as unicode escape sequences
                return payload_str.encode('unicode_escape').decode('ascii')

            elif encoding_type == 'rot13':
                # ROT13 encoding
                return codecs.encode(payload_str, 'rot_13')

            # elif encoding_type == 'xor_simple':
            #     # This requires a key and returns bytes, complicating chaining in this simple function.
            #     # Better handled by obfuscator.py or a more complex internal method.
            #     key = kwargs.get('key', 0xAA) # Example default key
            #     # Implementation similar to obfuscator.py's _apply_encoding
            #     # ...

            else:
                logger.error(f"PayloadForge: Unsupported encoding type: {encoding_type}")
                return None

        except Exception as e:
            logger.error(f"PayloadForge: Error applying {encoding_type} encoding: {e}")
            return None

    def load_template(self, template_name):
        """
        Loads a payload template from a file.

        Args:
            template_name (str): The name of the template file (e.g., 'xss_basic.txt').

        Returns:
            str or None: The template content as a string, or None if not found/error.
        """
        template_path = os.path.join(self.templates_dir, template_name)
        if not os.path.exists(template_path):
            logger.warning(f"PayloadForge: Template file not found: {template_path}")
            # Try to find it with common extensions
            for ext in ['.txt', '.tpl', '.template']:
                alt_path = template_path + ext
                if os.path.exists(alt_path):
                    template_path = alt_path
                    logger.info(f"PayloadForge: Found template with alternate extension: {alt_path}")
                    break
            else:
                logger.error(f"PayloadForge: Template file not found with common extensions: {template_path}{{.txt,.tpl,.template}}")
                return None

        try:
            with open(template_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            logger.debug(f"PayloadForge: Loaded template from {template_path}")
            return content
        except Exception as e:
            logger.error(f"PayloadForge: Error reading template {template_path}: {e}")
            return None

    def generate_from_template(self, template_content, substitutions=None):
        """
        Generates a payload by substituting placeholders in a template string.

        Args:
            template_content (str): The template string containing placeholders.
            substitutions (dict, optional): A dictionary of placeholder:value pairs.
                                             Example: {'COMMAND': 'whoami', 'MARKER': 'XYZ'}

        Returns:
            str: The generated payload string.
        """
        if substitutions is None:
            substitutions = {}

        generated_payload = template_content
        for placeholder, value in substitutions.items():
            # Simple string replacement. Could use more advanced templating (Jinja2) if needed.
            # Supports placeholders like {PLACEHOLDER} or {{PLACEHOLDER}}
            generated_payload = generated_payload.replace(f"{{{placeholder}}}", str(value))
            generated_payload = generated_payload.replace(f"{{{{{placeholder}}}}}", str(value)) # Double brace support

        logger.debug(f"PayloadForge: Generated payload from template with {len(substitutions)} substitutions.")
        return generated_payload

    def generate_fuzzing_payloads(self, pattern_type, count_or_params):
        """
        Generates payloads based on common fuzzing patterns.

        Args:
            pattern_type (str): The type of fuzzing pattern.
                                Options: 'buffer_overflow', 'format_string', 'directory_traversal',
                                         'xml_entities', 'long_string', 'special_chars'.
            count_or_params (int or dict): Parameters for the pattern.
                                            For 'buffer_overflow', 'format_string', 'long_string': int (count/length).
                                            For 'directory_traversal': dict like {'depth': 5, 'prefix': '../'}.
                                            For 'xml_entities': dict like {'count': 10, 'entity_name': 'xxe'}.
                                            For 'special_chars': dict like {'chars': ['\x00', '\n', '%00']}.

        Returns:
            list: A list of generated fuzzing payload strings.
        """
        payloads = []
        try:
            if pattern_type == 'buffer_overflow':
                length = int(count_or_params) if isinstance(count_or_params, (int, str)) else 1000
                payloads.append("A" * length)
                logger.debug(f"PayloadForge: Generated buffer overflow payload of length {length}.")

            elif pattern_type == 'format_string':
                count = int(count_or_params) if isinstance(count_or_params, (int, str)) else 10
                payloads.append("%s%n" * count)
                logger.debug(f"PayloadForge: Generated format string payload with {count} repetitions.")

            elif pattern_type == 'directory_traversal':
                 params = count_or_params if isinstance(count_or_params, dict) else {}
                 depth = params.get('depth', 5)
                 prefix = params.get('prefix', '../')
                 payloads.append(prefix * depth)
                 logger.debug(f"PayloadForge: Generated directory traversal payload: {prefix * depth}")

            elif pattern_type == 'xml_entities':
                params = count_or_params if isinstance(count_or_params, dict) else {}
                count = params.get('count', 10)
                entity_name = params.get('entity_name', 'xxe')
                # Basic XXE payload structure
                dtd_part = f'<!ENTITY % {entity_name} "<!ENTITY &#x25; eval \"<!ENTITY &#x26;#x25; error SYSTEM \'file:///nonexistent/%eval;\'>\">">'
                payloads.append(dtd_part)
                # Add variations or expansions if needed
                logger.debug(f"PayloadForge: Generated basic XML entity payload.")

            elif pattern_type == 'long_string':
                length = int(count_or_params) if isinstance(count_or_params, (int, str)) else 5000
                # Generate a long string of mixed characters
                import random
                import string
                chars = string.ascii_letters + string.digits + string.punctuation
                long_str = ''.join(random.choice(chars) for _ in range(length))
                payloads.append(long_str)
                logger.debug(f"PayloadForge: Generated long random string payload of length {length}.")

            elif pattern_type == 'special_chars':
                params = count_or_params if isinstance(count_or_params, dict) else {}
                chars = params.get('chars', ['\x00', '\n', '\r', '\x1a', '%00', '%0d%0a'])
                payloads.extend(chars)
                logger.debug(f"PayloadForge: Generated special chars payloads: {chars}")

            else:
                logger.error(f"PayloadForge: Unsupported fuzzing pattern type: {pattern_type}")

        except Exception as e:
            logger.error(f"PayloadForge: Error generating fuzzing payloads for type {pattern_type}: {e}")
            payloads.append(f"[ERROR_GENERATING_{pattern_type.upper()}]")

        return payloads

    def forge(self, base_payload, encodings=None, wrapper_template=None, **wrapper_kwargs):
        """
        Forges a payload by applying a series of encodings and optionally wrapping it.

        Args:
            base_payload (str): The initial payload string.
            encodings (list, optional): A list of encoding techniques to apply sequentially.
                                         Supported: 'base64', 'hex', 'url', 'html_entity',
                                                    'unicode_escape', 'rot13'.
                                         If None, no encoding is applied.
            wrapper_template (str, optional): A template string to wrap the final encoded payload.
                                              Use {encoded_payload} as the placeholder.
                                              Example: 'eval(base64_decode("{encoded_payload}"));'
            **wrapper_kwargs: Additional keyword arguments for the wrapper (e.g., specific keys).

        Returns:
            dict: A dictionary containing the original payload, final forged payload,
                  list of applied encodings, and any errors.
        """
        if encodings is None:
            encodings = []

        result = {
            "original_payload": base_payload,
            "encoded_payload": base_payload, # Start with original
            "applied_encodings": [],
            "wrapper_used": wrapper_template,
            "final_payload": base_payload, # Will be updated
            "errors": []
        }

        current_payload = base_payload

        # --- Apply Encodings Sequentially ---
        for encoding in encodings:
            logger.debug(f"PayloadForge: Applying encoding '{encoding}'...")
            encoded_result = self._apply_encoding(current_payload, encoding)
            if encoded_result is None:
                error_msg = f"Failed to apply encoding '{encoding}'"
                result["errors"].append(error_msg)
                logger.error(f"PayloadForge: {error_msg}")
                # Depending on requirements, you might want to stop on error or continue
                # For now, let's stop to prevent corrupting the payload chain.
                break

            result["applied_encodings"].append(encoding)
            current_payload = encoded_result
            result["encoded_payload"] = current_payload # Update intermediate result
            logger.info(f"PayloadForge: Applied encoding '{encoding}'.")

        result["final_payload"] = current_payload # Set after encoding chain

        # --- Apply Wrapper ---
        if wrapper_template and not result["errors"]:
            try:
                # Simple placeholder replacement
                wrapped_payload = wrapper_template.replace("{encoded_payload}", result["final_payload"])
                wrapped_payload = wrapped_payload.replace("{original_payload}", result["original_payload"])
                # Add more placeholders if needed

                result["final_payload"] = wrapped_payload
                logger.info("PayloadForge: Applied wrapper to final encoded payload.")
            except Exception as e:
                error_msg = f"Error applying wrapper: {str(e)}"
                result["errors"].append(error_msg)
                logger.error(f"PayloadForge: {error_msg}")

        logger.info(f"PayloadForge: Completed forging. Applied {len(result['applied_encodings'])} encodings.")
        return result

    def load_wordlist(self, wordlist_source):
        """
        Loads a list of payloads/words from a file or a Python list.

        Args:
            wordlist_source (str or list): Path to a wordlist file (one payload per line)
                                           or a Python list of payload strings.

        Returns:
            list: A list of payload strings.
        """
        payload_list = []
        if isinstance(wordlist_source, str):
            # Assume it's a file path
            try:
                with open(wordlist_source, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        payload = line.strip()
                        # Skip empty lines and comments (starting with #)
                        if payload and not payload.startswith('#'):
                            payload_list.append(payload)
                logger.info(f"PayloadForge: Loaded {len(payload_list)} payloads from wordlist file {wordlist_source}.")
            except FileNotFoundError:
                logger.error(f"PayloadForge: Wordlist file not found: {wordlist_source}")
            except Exception as e:
                logger.error(f"PayloadForge: Error reading wordlist file {wordlist_source}: {e}")
        elif isinstance(wordlist_source, list):
            # Assume it's a list of words
            payload_list = [str(item) for item in wordlist_source if item] # Ensure strings and filter empty
            logger.info(f"PayloadForge: Loaded {len(payload_list)} payloads from provided list.")
        else:
            logger.error("PayloadForge: Invalid wordlist source. Must be a file path (str) or a list.")
        return payload_list

    def save_payloads(self, payloads, output_path, format='plaintext'):
        """
        Saves a list of payloads to a file.

        Args:
            payloads (list): A list of payload strings.
            output_path (str): The path to the output file.
            format (str): The format to save in ('plaintext', 'json').
        """
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                if format.lower() == 'plaintext':
                    for payload in payloads:
                        f.write(f"{payload}\n")
                    logger.info(f"PayloadForge: Saved {len(payloads)} payloads to {output_path} (plaintext).")
                elif format.lower() == 'json':
                    # Save as a JSON array
                    json.dump(payloads, f, indent=4)
                    logger.info(f"PayloadForge: Saved {len(payloads)} payloads to {output_path} (JSON).")
                else:
                    logger.error(f"PayloadForge: Unsupported save format: {format}")
        except Exception as e:
            logger.error(f"PayloadForge: Error saving payloads to {output_path}: {e}")

    def list_templates(self):
        """
        Lists available payload templates in the templates directory.

        Returns:
            list: A list of template filenames.
        """
        if not os.path.exists(self.templates_dir):
            logger.warning(f"PayloadForge: Templates directory not found: {self.templates_dir}")
            return []

        try:
            templates = [f for f in os.listdir(self.templates_dir) if os.path.isfile(os.path.join(self.templates_dir, f))]
            logger.debug(f"PayloadForge: Found {len(templates)} templates in {self.templates_dir}.")
            return templates
        except Exception as e:
            logger.error(f"PayloadForge: Error listing templates in {self.templates_dir}: {e}")
            return []


# Example usage (if run directly)
if __name__ == '__main__':
    # Example: Demonstrate payload generation and forging
    forge = PayloadForge(templates_dir="config/payload_templates_demo") # Use a demo path

    # Ensure demo template directory and a sample template exist
    os.makedirs("config/payload_templates_demo", exist_ok=True)
    sample_template_content = "'; alert('{{MESSAGE}}'); //"
    with open("config/payload_templates_demo/xss_alert.tpl", "w") as f:
        f.write(sample_template_content)

    print("--- PayloadForge Basic Demo ---")
    print(f"Templates Directory: {forge.templates_dir}")
    print("-" * 30)

    # 1. List templates
    print("\n1. Available Templates:")
    templates = forge.list_templates()
    for t in templates:
        print(f" - {t}")

    # 2. Generate from template
    print("\n2. Generating Payload from Template:")
    template_content = forge.load_template("xss_alert.tpl")
    if template_content:
        substitutions = {"MESSAGE": "XSS_FORGED_BY_PAYLOADFORGE"}
        generated_payload = forge.generate_from_template(template_content, substitutions)
        print(f"Template: {template_content}")
        print(f"Substitutions: {substitutions}")
        print(f"Generated Payload: {generated_payload}")
    else:
        print("Failed to load template.")

    # 3. Forge the generated payload (encode + wrap)
    print("\n3. Forging the Generated Payload (Base64 + Wrapper):")
    if 'generated_payload' in locals():
        forged_result = forge.forge(
            base_payload=generated_payload,
            encodings=['base64'],
            wrapper_template='eval(atob("{encoded_payload}")); // Wrapped by PayloadForge'
        )
        print("Forging Result:")
        print(f"  Original: {forged_result['original_payload']}")
        print(f"  Encoded: {forged_result['encoded_payload']}")
        print(f"  Final (Wrapped): {forged_result['final_payload']}")
        print(f"  Encodings Applied: {forged_result['applied_encodings']}")
        if forged_result['errors']:
            print(f"  Errors: {forged_result['errors']}")

    # 4. Generate fuzzing payloads
    print("\n4. Generating Fuzzing Payloads:")
    fuzz_payloads = forge.generate_fuzzing_payloads('buffer_overflow', 500)
    fuzz_payloads.extend(forge.generate_fuzzing_payloads('directory_traversal', {'depth': 3}))
    print(f"Generated {len(fuzz_payloads)} fuzzing payloads (BO + DT). First few:")
    for fp in fuzz_payloads[:3]:
        print(f" - {fp[:50]}..." if len(fp) > 50 else f" - {fp}")

    # 5. Save payloads
    print("\n5. Saving Payloads:")
    all_payloads = [generated_payload] if 'generated_payload' in locals() else []
    all_payloads.extend(fuzz_payloads[:5]) # Save first 5 fuzz payloads
    output_file_plaintext = "generated_payloads.txt"
    output_file_json = "generated_payloads.json"
    forge.save_payloads(all_payloads, output_file_plaintext, format='plaintext')
    forge.save_payloads(all_payloads, output_file_json, format='json')
    print(f"Saved {len(all_payloads)} payloads to {output_file_plaintext} and {output_file_json}.")

    print("-" * 30)
    print("PayloadForge demo completed.")
