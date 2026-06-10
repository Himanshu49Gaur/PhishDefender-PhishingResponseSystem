def scan_url(url):
    """
    Wrapper around VirusTotal URL scanning.
    Import is done lazily to avoid circular imports.
    """

    from threat_intel import scan_url_virustotal

    return scan_url_virustotal(url)