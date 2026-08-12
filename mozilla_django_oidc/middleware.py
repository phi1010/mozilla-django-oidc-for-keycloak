import logging
import time
from re import Pattern as re_Pattern
from urllib.parse import quote, urlencode

import requests
from django.contrib.auth import BACKEND_SESSION_KEY
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils.crypto import get_random_string
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import cached_property
from django.utils.module_loading import import_string

from mozilla_django_oidc import discovery
from mozilla_django_oidc.auth import OIDCAuthenticationBackend
from mozilla_django_oidc.utils import (
    absolutify,
    add_state_and_verifier_and_nonce_to_session,
    generate_code_challenge,
    import_from_settings,
)

LOGGER = logging.getLogger(__name__)


class SessionRefresh(MiddlewareMixin):
    """Refreshes the session with the OIDC RP after expiry seconds

    For users authenticated with the OIDC RP, verify tokens are still valid and
    if not, force the user to re-authenticate silently.

    """

    def __init__(self, get_response):
        super(SessionRefresh, self).__init__(get_response)
        self.OIDC_EXEMPT_URLS = self.get_settings("OIDC_EXEMPT_URLS", [])
        if discovery.discovery_url() is None:
            # Without discovery configured, resolve the endpoint eagerly as
            # upstream does. With discovery, it stays lazy (cached_property)
            # so that no network I/O happens at server startup.
            self.OIDC_OP_AUTHORIZATION_ENDPOINT = self.get_settings(
                "OIDC_OP_AUTHORIZATION_ENDPOINT"
            )
        self.OIDC_RP_CLIENT_ID = self.get_settings("OIDC_RP_CLIENT_ID")
        self.OIDC_STATE_SIZE = self.get_settings("OIDC_STATE_SIZE", 32)
        self.OIDC_AUTHENTICATION_CALLBACK_URL = self.get_settings(
            "OIDC_AUTHENTICATION_CALLBACK_URL",
            "oidc_authentication_callback",
        )
        self.OIDC_RP_SCOPES = self.get_settings("OIDC_RP_SCOPES", "openid email")
        self.OIDC_USE_NONCE = self.get_settings("OIDC_USE_NONCE", True)
        self.OIDC_NONCE_SIZE = self.get_settings("OIDC_NONCE_SIZE", 32)

    @staticmethod
    def get_settings(attr, *args):
        return import_from_settings(attr, *args)

    # Only reached when discovery is configured; otherwise __init__ sets the
    # instance attribute eagerly (upstream behavior) and shadows this.
    @cached_property
    def OIDC_OP_AUTHORIZATION_ENDPOINT(self):
        return discovery.get_endpoint_setting("OIDC_OP_AUTHORIZATION_ENDPOINT")

    @cached_property
    def exempt_urls(self):
        """Generate and return a set of url paths to exempt from SessionRefresh

        This takes the value of ``settings.OIDC_EXEMPT_URLS`` and appends three
        urls that mozilla-django-oidc uses. These values can be view names or
        absolute url paths.

        :returns: list of url paths (for example "/oidc/callback/")

        """
        exempt_urls = []
        for url in self.OIDC_EXEMPT_URLS:
            if not isinstance(url, re_Pattern):
                exempt_urls.append(url)
        exempt_urls.extend(
            [
                "oidc_authentication_init",
                "oidc_authentication_callback",
                "oidc_logout",
            ]
        )

        return set(
            [url if url.startswith("/") else reverse(url) for url in exempt_urls]
        )

    @cached_property
    def exempt_url_patterns(self):
        """Generate and return a set of url patterns to exempt from SessionRefresh

        This takes the value of ``settings.OIDC_EXEMPT_URLS`` and returns the
        values that are compiled regular expression patterns.

        :returns: list of url patterns (for example,
            ``re.compile(r"/user/[0-9]+/image")``)
        """
        exempt_patterns = set()
        for url_pattern in self.OIDC_EXEMPT_URLS:
            if isinstance(url_pattern, re_Pattern):
                exempt_patterns.add(url_pattern)
        return exempt_patterns

    def is_refreshable_url(self, request):
        """Takes a request and returns whether it triggers a refresh examination

        :arg HttpRequest request:

        :returns: boolean

        """
        # Do not attempt to refresh the session if the OIDC backend is not used
        backend_session = request.session.get(BACKEND_SESSION_KEY)
        is_oidc_enabled = True
        if backend_session:
            auth_backend = import_string(backend_session)
            is_oidc_enabled = issubclass(auth_backend, OIDCAuthenticationBackend)

        return (
            request.method == "GET"
            and request.user.is_authenticated
            and is_oidc_enabled
            and request.path not in self.exempt_urls
            and not any(pat.match(request.path) for pat in self.exempt_url_patterns)
        )

    def process_request(self, request):
        if not self.is_refreshable_url(request):
            LOGGER.debug("request is not refreshable")
            return

        expiration = request.session.get("oidc_id_token_expiration", 0)
        now = time.time()
        if expiration > now:
            # The id_token is still valid, so we don't have to do anything.
            LOGGER.debug("id token is still valid (%s > %s)", expiration, now)
            return

        LOGGER.debug("id token has expired")
        # The id_token has expired, so we have to re-authenticate silently.
        auth_url = self.OIDC_OP_AUTHORIZATION_ENDPOINT
        client_id = self.OIDC_RP_CLIENT_ID
        state = get_random_string(self.OIDC_STATE_SIZE)

        # Build the parameters as if we were doing a real auth handoff, except
        # we also include prompt=none.
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": absolutify(
                request, reverse(self.OIDC_AUTHENTICATION_CALLBACK_URL)
            ),
            "state": state,
            "scope": self.OIDC_RP_SCOPES,
            "prompt": "none",
        }

        params.update(self.get_settings("OIDC_AUTH_REQUEST_EXTRA_PARAMS", {}))

        if self.OIDC_USE_NONCE:
            nonce = get_random_string(self.OIDC_NONCE_SIZE)
            params.update({"nonce": nonce})

        if self.get_settings("OIDC_USE_PKCE", False):
            code_verifier_length = self.get_settings("OIDC_PKCE_CODE_VERIFIER_SIZE", 64)
            # Check that code_verifier_length is between the min and max length
            # defined in https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
            if not (43 <= code_verifier_length <= 128):
                raise ValueError("code_verifier_length must be between 43 and 128")

            # Generate code_verifier and code_challenge pair
            code_verifier = get_random_string(code_verifier_length)
            code_challenge_method = self.get_settings(
                "OIDC_PKCE_CODE_CHALLENGE_METHOD", "S256"
            )
            code_challenge = generate_code_challenge(
                code_verifier, code_challenge_method
            )

            # Append code_challenge to authentication request parameters
            params.update(
                {
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                }
            )
        else:
            code_verifier = None

        add_state_and_verifier_and_nonce_to_session(
            request, state, params, code_verifier
        )

        request.session["oidc_login_next"] = request.get_full_path()

        query = urlencode(params, quote_via=quote)
        redirect_url = "{url}?{query}".format(url=auth_url, query=query)
        if request.headers.get("x-requested-with") == "XMLHttpRequest":
            # Almost all XHR request handling in client-side code struggles
            # with redirects since redirecting to a page where the user
            # is supposed to do something is extremely unlikely to work
            # in an XHR request. Make a special response for these kinds
            # of requests.
            # The use of 403 Forbidden is to match the fact that this
            # middleware doesn't really want the user in if they don't
            # refresh their session.
            response = JsonResponse({"refresh_url": redirect_url}, status=403)
            response["refresh_url"] = redirect_url
            return response
        return HttpResponseRedirect(redirect_url)


class RefreshOIDCToken(SessionRefresh):
    """Refreshes expired tokens server-side with the OIDC refresh token grant.

    When the session tokens have expired, this middleware POSTs a
    ``grant_type=refresh_token`` request to the token endpoint from the
    backend — transparently, without redirecting the browser. If no refresh
    token is available or the refresh fails (e.g. the SSO session ended),
    it falls back to the front-channel ``prompt=none`` flow of
    ``SessionRefresh``.

    Requires ``OIDC_STORE_REFRESH_TOKEN = True``.
    """

    def __init__(self, get_response):
        super(RefreshOIDCToken, self).__init__(get_response)
        if not self.get_settings("OIDC_STORE_REFRESH_TOKEN", False):
            raise ImproperlyConfigured(
                "RefreshOIDCToken middleware requires OIDC_STORE_REFRESH_TOKEN "
                "to be set to True."
            )

    def is_refreshable_url(self, request):
        """Like SessionRefresh, but without the GET-only restriction.

        A back-channel refresh is transparent to the client, so any HTTP
        method can be refreshed safely.
        """
        backend_session = request.session.get(BACKEND_SESSION_KEY)
        is_oidc_enabled = True
        if backend_session:
            auth_backend = import_string(backend_session)
            is_oidc_enabled = issubclass(auth_backend, OIDCAuthenticationBackend)

        return (
            request.user.is_authenticated
            and is_oidc_enabled
            and request.path not in self.exempt_urls
            and not any(pat.match(request.path) for pat in self.exempt_url_patterns)
        )

    def get_backend(self, request):
        """Return an OIDC backend instance bound to this request."""
        backend_session = request.session.get(BACKEND_SESSION_KEY)
        backend_class = OIDCAuthenticationBackend
        if backend_session:
            candidate = import_string(backend_session)
            if issubclass(candidate, OIDCAuthenticationBackend):
                backend_class = candidate
        backend = backend_class()
        backend.request = request
        return backend

    def fallback(self, request):
        """Fall back to the front-channel prompt=none flow."""
        request.session.pop("oidc_refresh_token", None)
        if request.method == "GET":
            return super(RefreshOIDCToken, self).process_request(request)
        # Non-GET requests cannot be redirected through the authorization
        # endpoint; tell the client to refresh via the login flow.
        response = JsonResponse(
            {"refresh_url": reverse("oidc_authentication_init")}, status=403
        )
        response["refresh_url"] = reverse("oidc_authentication_init")
        return response

    def process_request(self, request):
        if not self.is_refreshable_url(request):
            LOGGER.debug("request is not refreshable")
            return

        expiration = request.session.get("oidc_id_token_expiration", 0)
        now = time.time()
        if expiration > now:
            LOGGER.debug("id token is still valid (%s > %s)", expiration, now)
            return

        refresh_token = request.session.get("oidc_refresh_token")
        if not refresh_token:
            LOGGER.debug("no refresh token stored in session")
            return self.fallback(request)

        refresh_expiration = request.session.get("oidc_refresh_token_expiration")
        if refresh_expiration and refresh_expiration <= now:
            LOGGER.debug("refresh token has expired")
            return self.fallback(request)

        try:
            self._refresh_token(request, refresh_token)
        except (requests.RequestException, SuspiciousOperation) as exc:
            LOGGER.warning(
                "back-channel token refresh failed (%s); falling back to "
                "front-channel re-authentication",
                exc,
            )
            return self.fallback(request)

    def _refresh_token(self, request, refresh_token):
        """Refresh the tokens with the refresh token grant and update the session."""
        backend = self.get_backend(request)

        payload = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.get_settings("OIDC_RP_CLIENT_ID"),
            "client_secret": self.get_settings("OIDC_RP_CLIENT_SECRET"),
        }

        token_info = backend.get_token(payload)
        id_token = token_info.get("id_token")
        access_token = token_info.get("access_token")
        new_refresh_token = token_info.get("refresh_token")

        # Refresh responses carry no nonce claim; verify signature/claims only.
        payload_data = backend.verify_token(id_token, nonce=None)

        # Guard against the OP handing back tokens for a different subject.
        previous_id_token = request.session.get("oidc_id_token")
        if previous_id_token:
            previous_payload = backend.verify_token(previous_id_token, nonce=None)
            if previous_payload.get("sub") != payload_data.get("sub"):
                raise SuspiciousOperation(
                    "Refreshed id_token subject does not match session subject"
                )

        backend.store_token_expirations(token_info)
        # Keycloak rotates refresh tokens; always persist the newest one.
        backend.store_tokens_compat(
            access_token, id_token, new_refresh_token or refresh_token
        )

        expires_in = token_info.get("expires_in")
        if expires_in is not None and self.get_settings(
            "OIDC_USE_TOKEN_EXPIRATION", False
        ):
            request.session["oidc_id_token_expiration"] = time.time() + expires_in
        else:
            request.session["oidc_id_token_expiration"] = time.time() + self.get_settings(
                "OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS", 60 * 15
            )

        LOGGER.debug("tokens refreshed via refresh_token grant")
