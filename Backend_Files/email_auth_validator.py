def validate_email_auth(headers):

    if not headers or not isinstance(headers, dict):
        return {
            "spf_pass": False,
            "dkim_pass": False,
            "dmarc_pass": False
        }

    auth_results = headers.get(
        "Authentication-Results",
        ""
    )

    return {

        "spf_pass":
            "spf=pass"
            in auth_results.lower(),

        "dkim_pass":
            "dkim=pass"
            in auth_results.lower(),

        "dmarc_pass":
            "dmarc=pass"
            in auth_results.lower()

    }