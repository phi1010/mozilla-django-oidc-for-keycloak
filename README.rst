===================
mozilla-django-oidc
===================

.. image:: https://img.shields.io/pypi/v/mozilla-django-oidc
   :target: https://pypi.org/project/mozilla-django-oidc/

.. image:: https://github.com/mozilla/mozilla-django-oidc/actions/workflows/unit_tests.yml/badge.svg?branch=main
   :target: https://github.com/mozilla/mozilla-django-oidc/actions/workflows/unit_tests.yml

.. image:: https://github.com/mozilla/mozilla-django-oidc/actions/workflows/integration_tests.yml/badge.svg?branch=main
   :target: https://github.com/mozilla/mozilla-django-oidc/actions/workflows/integration_tests.yml

.. image:: https://codecov.io/gh/mozilla/mozilla-django-oidc/graph/badge.svg?token=QrytQ8IwrM
   :target: https://codecov.io/gh/mozilla/mozilla-django-oidc

A lightweight authentication and access management library for integration with OpenID Connect enabled authentication services.

This fork adds Keycloak-friendly features on top of upstream
`mozilla-django-oidc <https://github.com/mozilla/mozilla-django-oidc>`_:
server-side token refresh and OIDC endpoint discovery. All additions are
opt-in; with default settings the fork behaves exactly like upstream.


Keycloak integration
--------------------

Server-side token refresh
=========================

Upstream's ``SessionRefresh`` middleware renews expired sessions by
redirecting the browser through the authorization endpoint with
``prompt=none`` — which only works for GET requests and interrupts XHR/POST
flows. This fork adds ``mozilla_django_oidc.middleware.RefreshOIDCToken``,
which instead renews tokens transparently from the backend using the OAuth2
``refresh_token`` grant before your application uses an expired token:

* Works for **all HTTP methods**, including POST and XHR requests — the
  request simply continues after the refresh.
* Verifies the refreshed ``id_token`` (signature and subject match) and
  stores the **rotated** refresh token that Keycloak returns.
* Falls back to the front-channel ``SessionRefresh`` flow only when the
  refresh token is no longer valid (e.g. the SSO session was ended in
  Keycloak).

OIDC endpoint discovery
=======================

Instead of configuring ``OIDC_OP_AUTHORIZATION_ENDPOINT``,
``OIDC_OP_TOKEN_ENDPOINT``, ``OIDC_OP_USER_ENDPOINT`` and
``OIDC_OP_JWKS_ENDPOINT`` by hand, set a single
``OIDC_OP_DISCOVERY_ENDPOINT`` and the endpoints are resolved from the
realm's ``/.well-known/openid-configuration`` document. The metadata is
fetched lazily (never at server startup) and cached in the Django cache;
explicitly configured endpoint settings always take precedence.

Quick start
===========

.. code-block:: python

    AUTHENTICATION_BACKENDS = (
        'mozilla_django_oidc.auth.OIDCAuthenticationBackend',
        # ...
    )

    MIDDLEWARE = [
        # middleware involving session and authentication must come first
        # ...
        'mozilla_django_oidc.middleware.RefreshOIDCToken',
        # ...
    ]

    # All OP endpoints are discovered from the realm's well-known document;
    # accepts the realm base URL or the full well-known URL
    OIDC_OP_DISCOVERY_ENDPOINT = 'https://keycloak.example.com/realms/myrealm'

    OIDC_RP_CLIENT_ID = 'myclient'
    OIDC_RP_CLIENT_SECRET = 'sekret'
    OIDC_RP_SIGN_ALGO = 'RS256'

    # Keep the refresh token in the (server-side) session and refresh based
    # on the real token lifetimes reported by Keycloak
    OIDC_STORE_REFRESH_TOKEN = True
    OIDC_USE_TOKEN_EXPIRATION = True

New settings
============

+----------------------------------+-------------+---------------------------------------------------------------+
| Setting                          | Default     | Purpose                                                       |
+==================================+=============+===============================================================+
| ``OIDC_OP_DISCOVERY_ENDPOINT``   | ``None``    | Realm/issuer base URL (or full well-known URL) used to        |
|                                  |             | auto-discover the ``OIDC_OP_*`` endpoints.                    |
+----------------------------------+-------------+---------------------------------------------------------------+
| ``OIDC_STORE_REFRESH_TOKEN``     | ``False``   | Store the refresh token in the session                        |
|                                  |             | (``oidc_refresh_token``). Required by ``RefreshOIDCToken``.   |
+----------------------------------+-------------+---------------------------------------------------------------+
| ``OIDC_USE_TOKEN_EXPIRATION``    | ``False``   | Refresh based on the token endpoint's real ``expires_in``     |
|                                  |             | instead of ``OIDC_RENEW_ID_TOKEN_EXPIRY_SECONDS``.            |
+----------------------------------+-------------+---------------------------------------------------------------+
| ``OIDC_DISCOVERY_CACHE_TIMEOUT`` | ``86400``   | How long discovered provider metadata is cached (seconds).    |
+----------------------------------+-------------+---------------------------------------------------------------+
| ``OIDC_DISCOVERY_CACHE_ALIAS``   | ``default`` | Django cache alias used for the discovery metadata.           |
+----------------------------------+-------------+---------------------------------------------------------------+

.. warning::

    Refresh tokens are long-lived credentials. Use a server-side session
    backend (database or cache) — do not combine ``OIDC_STORE_REFRESH_TOKEN``
    with the ``signed_cookies`` session engine, or the refresh token ends up
    in the browser's cookie store.

See ``docs/installation.rst`` and ``docs/settings.rst`` for details.


Documentation
-------------

The full documentation is at `<https://mozilla-django-oidc.readthedocs.io>`_.


Design principles
-----------------

* Keep it as minimal/lightweight as possible
* Store as few authn/authz artifacts as possible
* Allow custom functionality by overriding the authentication backend
* Mainly support OIDC authorization code flow
* Allow shipping Mozilla-centric authn/authz features
* Test against all supported Python/Django version
* E2E tested and audited by `Mozilla InfoSec <https://infosec.mozilla.org/>`_


Running Unit Tests
-------------------

Use ``tox`` to run as many different versions of Python you have. If you
don't have ``tox`` installed (and executable) already you can either
install it in your system Python or use `pipx <https://pipx.pypa.io/>`_.
Once installed, simply execute in the project root directory.

.. code-block:: shell

    $ tox

``tox`` will do the equivalent of installing virtual environments for every
combination mentioned in the ``tox.ini`` file. If your system, for example,
doesn't have ``python3.10`` those ``tox`` tests will be skipped.

For a faster test-rinse-repeat cycle you can run tests in a specific
environment with a specific version of Python and specific version of
Django of your choice. Here is such an example:


.. code-block:: shell

    $ python -m venv venv
    $ source ./venv/bin/activate
    (venv) $ pip install '.[dev]'
    (venv) $ make test

Measuring code coverage, continuing the steps above:

.. code-block:: shell

    (venv) $ make coverage

Local development
-----------------

The local development setup is based on Docker so you need the following installed in your system:

* `docker`
* `docker compose`

You will also need to edit your ``hosts`` file to resolve ``testrp`` and ``testprovider`` hostnames to ``127.0.0.1``.

Running test services
=====================

To run the `testrp` and `testprovider` instances run the following:

.. code-block:: shell

   (venv) $ docker compose up -d testprovider testrp

Then visit the testing django app on: ``http://testrp:8081``.

The library source code is mounted as a docker volume and source code changes are reflected directly in.
In order to test a change you need to restart the ``testrp`` service.

.. code-block:: shell

   (venv) $ docker compose stop testrp
   (venv) $ docker compose up -d testrp

Running integration tests
=========================

Integration tests are mounted as a volume to the docker containers. Tests can be run using the following command:

.. code-block:: shell

   (venv) $ docker compose run --service-ports testrunner

Linting
-------

All code is checked with `flake8 <https://pypi.org/project/flake8/>`_ in
continuous integration. To make sure your code still passes all style guides
install ``flake8`` and check:

.. code-block:: shell

    $ flake8 mozilla_django_oidc tests

.. note::

    When you run ``tox`` it also does a ``flake8`` run on the main package
    files and the tests.

You can also run linting with ``tox``:

.. code-block:: shell

    $ tox -e lint

Finally you can use pre-commit hooks to run linting and formatting before you commit your code:

.. code-block:: shell

  (venv)  $ pre-commit install


Releasing a new version
------------------------

``mozilla-django-oidc`` releases are hosted in `PyPI <https://pypi.org/project/mozilla-django-oidc/>`_.
Here are the steps you need to follow in order to push a new release:

* Make sure that ``HISTORY.rst`` is up-to-date focusing mostly on backwards incompatible changes.

  Security vulnerabilities should be clearly marked in a "Security issues" section along with
  a level indicator of:

  * High: vulnerability facilitates data loss, data access, impersonation of admin, or allows access
    to other sites or components

    Users should upgrade immediately.

  * Medium: vulnerability endangers users by sending them to malicious sites or stealing browser
    data.

    Users should upgrade immediately.

  * Low: vulnerability is a nuissance to site staff and/or users

    Users should upgrade.

* Bump the project version and create a commit for the new version.

  * You can use ``bumpversion`` for that. It is a tool to automate this procedure following the `semantic versioning scheme <http://semver.org/>`_.

    * For a patch version update (eg 0.1.1 to 0.1.2) you can run ``bumpversion patch``.
    * For a minor version update (eg 0.1.0 to 0.2.0) you can run ``bumpversion minor``.
    * For a major version update (eg 0.1.0 to 1.0.0) you can run ``bumpversion major``.

* Create a `signed tag <https://git-scm.com/book/tr/v2/Git-Tools-Signing-Your-Work>`_ for that version

  Example::

      git tag -s 0.1.1 -m "Bump version: 0.1.0 to 0.1.1"

* Push the signed tag to Github

  Example::

      git push origin 0.1.1

The release is published automatically to PyPI using GitHub Actions on every new tag.


License
-------

This software is licensed under the MPL 2.0 license. For more info check the LICENSE file.


Credits
-------

Tools used in rendering this package:

*  Cookiecutter_
*  `cookiecutter-djangopackage`_

.. _Cookiecutter: https://github.com/cookiecutter/cookiecutter
.. _`cookiecutter-djangopackage`: https://github.com/pydanny/cookiecutter-djangopackage
