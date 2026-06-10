def parse_email(data):
    """
    Temporary email parser.
    Returns a standardized structure expected by the rest of the system.
    """

    return {
        "sender": data.get("sender", "unknown"),
        "urls": data.get("urls", []),
        "headers": data.get("headers", {}),
        "text_features": {},
        "flags": []
    }
