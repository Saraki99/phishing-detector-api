import whois
from urllib.parse import urlparse

def get_whois_info(url):
    try:
        domain = urlparse(url).netloc
        w = whois.whois(domain)

        return {
            "domain": domain,
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "country": str(w.country),
        }

    except:
        return {"domain": domain, "error": "not available"}
