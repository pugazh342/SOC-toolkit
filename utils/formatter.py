# BlueDefenderX/utils/formatter.py
import json

def format_event_to_json(event_dict):
    """Converts a dictionary to a formatted JSON string."""
    try:
        return json.dumps(event_dict, indent=4, sort_keys=True, default=str)
    except Exception as e:
        # Handle potential serialization issues
        return json.dumps({"error": f"Formatting failed: {str(e)}", "raw_data": str(event_dict)}, indent=4)

def beautify_text(text, prefix="> "):
    """Simple text beautifier."""
    lines = text.split('\n')
    beautified = '\n'.join([f"{prefix}{line}" for line in lines])
    return beautified
