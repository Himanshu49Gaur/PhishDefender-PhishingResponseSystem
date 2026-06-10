from celery_app import celery_app

from scanner import scan_url

from cache import (
    get_cached_url,
    cache_url
)

from metrics import scan_metrics


@celery_app.task(
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_kwargs={"max_retries": 3}
)
def scan_url_task(self, url):

    cached = get_cached_url(url)

    if cached:
        return cached

    scan_metrics["urls_scanned"] += 1

    result = scan_url(url)

    cache_url(
        url,
        result
    )

    return result