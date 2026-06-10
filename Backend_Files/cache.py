import time
from metrics import scan_metrics

url_cache = {}

CACHE_TTL = 86400


def get_cached_url(url):

    if url not in url_cache:
        scan_metrics["cache_misses"] += 1
        return None

    entry = url_cache[url]

    if time.time() - entry["timestamp"] > CACHE_TTL:
        del url_cache[url]
        scan_metrics["cache_misses"] += 1
        return None

    scan_metrics["cache_hits"] += 1

    return entry["result"]


def cache_url(url, result):

    url_cache[url] = {
        "result": result,
        "timestamp": time.time()
    }