def parse_headers(headers):
    parsed = {}
    
    # Validation 1: Ensure headers is actually a list before we try to loop through it
    if not isinstance(headers, list):
        return parsed

    for header in headers:
        # Validation 2: Ensure each header is a dictionary and contains the keys we need
        if isinstance(header, dict) and "name" in header and "value" in header:
            parsed[header["name"]] = header["value"]

    return parsed