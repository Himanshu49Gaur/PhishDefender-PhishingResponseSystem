def parse_headers(headers):
    if headers is None or not isinstance(headers,list):
        return {}
    try:
        parsed = {}
        for header in headers:
            if isinstance(header,dict):
                name=header.get("name")
                value=header.get("value")
                if name is not None and value is not None:
                   parsed[name] = value
        return parsed
    except Exception as e:
        print(f"error is {e}")
        return {}
            
