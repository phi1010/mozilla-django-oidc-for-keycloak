import logging
import time

import requests
from django.core.cache import caches
from django.core.exceptions import ImproperlyConfigured

from mozilla_django_oidc.utils import import_from_settings

LOGGER = logging.getLogger(__name__)

WELL_KNOWN_PATH = "/.well-known/openid-configuration"

# Maps mozilla-django-oidc settings names to keys of the OIDC provider
# metadata document.
ENDPOINT_SETTINGS_MAP = {
    "OIDC_OP_AUTHORIZATION_ENDPOINT": "authorization_endpoint",
    "OIDC_OP_TOKEN_ENDPOINT": "token_endpoint",
    "OIDC_OP_USER_ENDPOINT": "userinfo_endpoint",
    "OIDC_OP_JWKS_ENDPOINT": "jwks_uri",
    "OIDC_OP_LOGOUT_ENDPOINT": "end_session_endpoint",
}

# In-process fallback cache: {url: (fetched_at, metadata)}. Keeps discovery
# working (and stale metadata available on outages) even with dummy or
# unavailable Django cache backends.
_local_cache = {}


def discovery_url():
    """Return the normalized well-known URL, or None if discovery is not configured."""
    endpoint = import_from_settings("OIDC_OP_DISCOVERY_ENDPOINT", None)
    if not endpoint:
        return None
    endpoint = endpoint.rstrip("/")
    if not endpoint.endswith(WELL_KNOWN_PATH):
        endpoint += WELL_KNOWN_PATH
    return endpoint


def fetch_oidc_metadata(url):
    """Fetch the OIDC provider metadata document from the given well-known URL."""
    response = requests.get(
        url,
        verify=import_from_settings("OIDC_VERIFY_SSL", True),
        timeout=import_from_settings("OIDC_TIMEOUT", None),
        proxies=import_from_settings("OIDC_PROXY", None),
    )
    response.raise_for_status()
    return response.json()


def get_oidc_metadata():
    """Return the (cached) OIDC provider metadata.

    Raises ImproperlyConfigured if OIDC_OP_DISCOVERY_ENDPOINT is not set or
    metadata cannot be fetched and no stale copy is available.
    """
    url = discovery_url()
    if not url:
        raise ImproperlyConfigured("Setting OIDC_OP_DISCOVERY_ENDPOINT not found")

    timeout = import_from_settings("OIDC_DISCOVERY_CACHE_TIMEOUT", 86400)
    now = time.time()

    local = _local_cache.get(url)
    if local and now - local[0] < timeout:
        return local[1]

    cache = caches[import_from_settings("OIDC_DISCOVERY_CACHE_ALIAS", "default")]
    cache_key = "mozilla_django_oidc:discovery:{}".format(url)
    metadata = cache.get(cache_key)
    if metadata is not None:
        _local_cache[url] = (now, metadata)
        return metadata

    try:
        metadata = fetch_oidc_metadata(url)
    except requests.RequestException as exc:
        if local:
            LOGGER.warning(
                "Fetching OIDC discovery metadata from %s failed (%s); "
                "reusing stale cached metadata",
                url,
                exc,
            )
            return local[1]
        raise ImproperlyConfigured(
            "Could not fetch OIDC discovery metadata from {}: {}".format(url, exc)
        )

    cache.set(cache_key, metadata, timeout)
    _local_cache[url] = (now, metadata)
    return metadata


def get_endpoint_setting(attr, *args):
    """Resolve an OIDC endpoint setting.

    Resolution order: an explicitly configured Django setting always wins;
    otherwise the value is taken from the discovery metadata when
    OIDC_OP_DISCOVERY_ENDPOINT is configured; otherwise fall back to the
    normal import_from_settings behavior (default or ImproperlyConfigured).
    """
    sentinel = object()
    value = import_from_settings(attr, sentinel)
    if value is not sentinel and value is not None:
        return value

    if attr in ENDPOINT_SETTINGS_MAP and discovery_url():
        metadata_value = get_oidc_metadata().get(ENDPOINT_SETTINGS_MAP[attr])
        if metadata_value:
            return metadata_value

    return import_from_settings(attr, *args)
