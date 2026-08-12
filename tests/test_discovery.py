from unittest.mock import Mock, patch

from django.core.cache import cache
from django.core.exceptions import ImproperlyConfigured
from django.test import TestCase, override_settings

from mozilla_django_oidc import discovery

METADATA = {
    "authorization_endpoint": "https://kc.example.com/realms/test/protocol/openid-connect/auth",
    "token_endpoint": "https://kc.example.com/realms/test/protocol/openid-connect/token",
    "userinfo_endpoint": "https://kc.example.com/realms/test/protocol/openid-connect/userinfo",
    "jwks_uri": "https://kc.example.com/realms/test/protocol/openid-connect/certs",
    "end_session_endpoint": "https://kc.example.com/realms/test/protocol/openid-connect/logout",
}


def mock_metadata_response():
    response = Mock(status_code=200)
    response.json.return_value = METADATA
    return response


class DiscoveryUrlTestCase(TestCase):
    def test_not_configured(self):
        self.assertIsNone(discovery.discovery_url())

    @override_settings(OIDC_OP_DISCOVERY_ENDPOINT="https://kc.example.com/realms/test")
    def test_realm_base_url_is_normalized(self):
        self.assertEqual(
            discovery.discovery_url(),
            "https://kc.example.com/realms/test/.well-known/openid-configuration",
        )

    @override_settings(
        OIDC_OP_DISCOVERY_ENDPOINT="https://kc.example.com/realms/test/"
    )
    def test_trailing_slash_is_stripped(self):
        self.assertEqual(
            discovery.discovery_url(),
            "https://kc.example.com/realms/test/.well-known/openid-configuration",
        )

    @override_settings(
        OIDC_OP_DISCOVERY_ENDPOINT=(
            "https://kc.example.com/realms/test/.well-known/openid-configuration"
        )
    )
    def test_full_well_known_url_kept(self):
        self.assertEqual(
            discovery.discovery_url(),
            "https://kc.example.com/realms/test/.well-known/openid-configuration",
        )


@override_settings(OIDC_OP_DISCOVERY_ENDPOINT="https://kc.example.com/realms/test")
class GetEndpointSettingTestCase(TestCase):
    def setUp(self):
        cache.clear()
        discovery._local_cache.clear()

    @patch("mozilla_django_oidc.discovery.requests.get")
    def test_endpoints_resolved_from_metadata(self, mock_get):
        mock_get.return_value = mock_metadata_response()

        self.assertEqual(
            discovery.get_endpoint_setting("OIDC_OP_TOKEN_ENDPOINT"),
            METADATA["token_endpoint"],
        )
        self.assertEqual(
            discovery.get_endpoint_setting("OIDC_OP_AUTHORIZATION_ENDPOINT"),
            METADATA["authorization_endpoint"],
        )
        self.assertEqual(
            discovery.get_endpoint_setting("OIDC_OP_USER_ENDPOINT"),
            METADATA["userinfo_endpoint"],
        )
        self.assertEqual(
            discovery.get_endpoint_setting("OIDC_OP_JWKS_ENDPOINT", None),
            METADATA["jwks_uri"],
        )
        # Metadata is fetched only once thanks to caching.
        self.assertEqual(mock_get.call_count, 1)

    @override_settings(OIDC_OP_TOKEN_ENDPOINT="https://explicit.example.com/token")
    @patch("mozilla_django_oidc.discovery.requests.get")
    def test_explicit_setting_wins(self, mock_get):
        self.assertEqual(
            discovery.get_endpoint_setting("OIDC_OP_TOKEN_ENDPOINT"),
            "https://explicit.example.com/token",
        )
        mock_get.assert_not_called()

    @patch("mozilla_django_oidc.discovery.requests.get")
    def test_stale_metadata_reused_on_fetch_failure(self, mock_get):
        mock_get.return_value = mock_metadata_response()
        discovery.get_endpoint_setting("OIDC_OP_TOKEN_ENDPOINT")

        # Expire both caches, then make the next fetch fail.
        cache.clear()
        url = discovery.discovery_url()
        fetched_at, metadata = discovery._local_cache[url]
        discovery._local_cache[url] = (fetched_at - 999999, metadata)

        import requests

        mock_get.side_effect = requests.ConnectionError("op down")
        self.assertEqual(
            discovery.get_endpoint_setting("OIDC_OP_TOKEN_ENDPOINT"),
            METADATA["token_endpoint"],
        )

    @patch("mozilla_django_oidc.discovery.requests.get")
    def test_fetch_failure_without_cache_raises(self, mock_get):
        import requests

        mock_get.side_effect = requests.ConnectionError("op down")
        with self.assertRaises(ImproperlyConfigured):
            discovery.get_oidc_metadata()


class NoDiscoveryTestCase(TestCase):
    def test_missing_setting_raises(self):
        with self.assertRaises(ImproperlyConfigured):
            discovery.get_endpoint_setting("OIDC_OP_TOKEN_ENDPOINT")

    def test_default_is_returned(self):
        self.assertIsNone(
            discovery.get_endpoint_setting("OIDC_OP_JWKS_ENDPOINT", None)
        )
