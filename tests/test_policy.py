"""Bearer tokens are accepted only when the Keycloak realm issued and signed them."""

import datetime

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator
from pyramid.exceptions import ConfigurationError
from pyramid.interfaces import IAuthenticationPolicy
from webob import Request

from vcorp.sso import set_keycloak_authentication_policy
from vcorp.sso.policy import JWTAuthenticationPolicy, KeycloakAuthenticationPolicy

ISSUER = "https://sso.example.com/realms/master"
REALM_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


class RealmKeys:
    """Stands in for the realm's published keys (PyJWKClient)."""

    def __init__(self, error=None):
        self.error = error

    def get_signing_key_from_jwt(self, token):
        if self.error:
            raise self.error
        return type("SigningKey", (), {"key": REALM_KEY.public_key()})()


def token(key=REALM_KEY, algorithm="RS256", **claims):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "iss": ISSUER,
        "exp": now + datetime.timedelta(minutes=5),
        "preferred_username": "alice",
        **claims,
    }
    return jwt.encode(payload, key, algorithm=algorithm)


def claims(policy, bearer):
    request = Request.blank("/", headers={"Authorization": f"Bearer {bearer}"})
    return policy.get_claims(request)


@pytest.fixture
def policy():
    return KeycloakAuthenticationPolicy(ISSUER, jwks_client=RealmKeys())


def test_a_token_the_realm_signed_is_accepted(policy):
    assert claims(policy, token())["preferred_username"] == "alice"


def test_an_unsigned_token_is_refused(policy):
    assert claims(policy, token(key=None, algorithm="none")) == {}


def test_a_token_signed_by_another_key_is_refused(policy):
    assert claims(policy, token(key=OTHER_KEY)) == {}


def test_an_expired_token_is_refused(policy):
    now = datetime.datetime.now(datetime.timezone.utc)
    expired = now - datetime.timedelta(minutes=1)
    assert claims(policy, token(exp=expired)) == {}


def test_a_token_from_another_issuer_is_refused(policy):
    assert claims(policy, token(iss="https://evil.example.com/realms/master")) == {}


def test_a_token_for_another_audience_is_refused():
    policy = KeycloakAuthenticationPolicy(
        ISSUER, audience="formfiller", jwks_client=RealmKeys()
    )
    assert claims(policy, token(aud="formfiller"))["preferred_username"] == "alice"
    assert claims(policy, token(aud="someone-else")) == {}


def test_no_token_is_accepted_when_the_keys_cannot_be_fetched():
    policy = KeycloakAuthenticationPolicy(
        ISSUER, jwks_client=RealmKeys(error=jwt.PyJWKClientError("unreachable"))
    )
    assert claims(policy, token()) == {}


def test_garbage_is_refused(policy):
    assert claims(policy, "forged") == {}


def test_the_realm_must_be_configured():
    config = Configurator(settings={})
    config.include("vcorp.sso")
    with pytest.raises(ConfigurationError, match="keycloak.issuer"):
        set_keycloak_authentication_policy(config)


def test_the_issuer_is_read_from_the_settings():
    config = Configurator(settings={"multiauth.policy.keycloak.issuer": ISSUER + "/"})
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.include("vcorp.sso")
    config.set_keycloak_authentication_policy()
    config.commit()
    policy = config.registry.getUtility(IAuthenticationPolicy)
    assert isinstance(policy, KeycloakAuthenticationPolicy)
    assert policy.issuer == ISSUER


def test_the_shared_secret_policy_verifies_signatures():
    policy = JWTAuthenticationPolicy("secret", algorithm="HS256", auth_type="Bearer")
    good = jwt.encode({"sub": "alice"}, "secret", algorithm="HS256")
    forged = jwt.encode({"sub": "alice"}, "guess", algorithm="HS256")
    assert claims(policy, good) == {"sub": "alice"}
    assert claims(policy, forged) == {}
