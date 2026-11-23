"""Bearer tokens are accepted only when the Keycloak realm issued and signed them."""

import datetime
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.config import Configurator
from pyramid.exceptions import ConfigurationError
from pyramid.interfaces import IAuthenticationPolicy
from webob import Request

from vcorp.sso import (
    create_jwt_authentication_policy,
    set_keycloak_authentication_policy,
)
from vcorp.sso.policy import JWTAuthenticationPolicy, KeycloakAuthenticationPolicy

ISSUER = "https://sso.example.com/realms/master"
REALM_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


NEW_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk(key, kid):
    return {
        **json.loads(RSAAlgorithm.to_jwk(key.public_key())),
        "kid": kid,
        "use": "sig",
    }


class RealmKeys(jwt.PyJWKClient):
    """Serves the realm's published keys (its JWKS endpoint) without the network."""

    def __init__(self, keys=None, error=None, **kwargs):
        super().__init__(f"{ISSUER}/protocol/openid-connect/certs", **kwargs)
        self.keys = {"realm": REALM_KEY} if keys is None else keys
        self.error = error
        self.fetches = 0

    def fetch_data(self):
        self.fetches += 1
        if self.error:
            raise self.error
        data = {"keys": [jwk(key, kid) for kid, key in self.keys.items()]}
        if self.jwk_set_cache is not None:
            self.jwk_set_cache.put(data)  # pyright: ignore[reportArgumentType]
        return data


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    clock = Clock()
    monkeypatch.setattr(time, "monotonic", clock)
    return clock


def token(key=REALM_KEY, algorithm="RS256", kid="realm", **claims):
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "iss": ISSUER,
        "exp": now + datetime.timedelta(minutes=5),
        "preferred_username": "alice",
        **claims,
    }
    return jwt.encode(payload, key, algorithm=algorithm, headers={"kid": kid})


def claims(policy, bearer, auth_type="Bearer"):
    request = Request.blank("/", headers={"Authorization": f"{auth_type} {bearer}"})
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
        ISSUER,
        jwks_client=RealmKeys(error=jwt.PyJWKClientConnectionError("unreachable")),
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


def test_tokens_are_signed_with_rs256_unless_configured_otherwise(policy):
    assert claims(policy, token(algorithm="RS512")) == {}
    policy = KeycloakAuthenticationPolicy(
        ISSUER, algorithms=["RS256", "RS512"], jwks_client=RealmKeys()
    )
    assert claims(policy, token(algorithm="RS512"))["preferred_username"] == "alice"
    assert claims(policy, token())["preferred_username"] == "alice"


def test_the_algorithms_are_read_from_the_settings():
    config = Configurator(
        settings={"keycloak.issuer": ISSUER, "keycloak.algorithms": "RS256 RS512"}
    )
    config.set_authorization_policy(ACLAuthorizationPolicy())
    config.include("vcorp.sso")
    config.set_keycloak_authentication_policy()
    config.commit()
    policy = config.registry.getUtility(IAuthenticationPolicy)
    assert policy.algorithms == ["RS256", "RS512"]


@pytest.mark.parametrize("algorithm", ["HS256", "none"])
def test_shared_secret_and_unsigned_algorithms_cannot_be_configured(algorithm):
    config = Configurator(
        settings={"keycloak.issuer": ISSUER, "keycloak.algorithms": algorithm}
    )
    config.include("vcorp.sso")
    with pytest.raises(ConfigurationError, match="keycloak.algorithms"):
        set_keycloak_authentication_policy(config)


def test_a_key_the_realm_removes_stops_being_trusted(clock):
    realm = RealmKeys(lifespan=300)
    policy = KeycloakAuthenticationPolicy(ISSUER, jwks_client=realm)
    assert claims(policy, token())["preferred_username"] == "alice"
    realm.keys = {"new": NEW_KEY}
    clock.now += 301
    assert claims(policy, token()) == {}
    assert (
        claims(policy, token(key=NEW_KEY, kid="new"))["preferred_username"] == "alice"
    )


def test_a_new_realm_key_is_fetched_when_a_token_names_it(clock):
    realm = RealmKeys()
    policy = KeycloakAuthenticationPolicy(ISSUER, jwks_client=realm)
    assert claims(policy, token())["preferred_username"] == "alice"
    realm.keys = {"realm": REALM_KEY, "new": NEW_KEY}
    assert (
        claims(policy, token(key=NEW_KEY, kid="new"))["preferred_username"] == "alice"
    )
    assert realm.fetches == 2


def test_unknown_keys_trigger_at_most_one_fetch_per_interval(clock):
    realm = RealmKeys()
    policy = KeycloakAuthenticationPolicy(
        ISSUER, jwks_client=realm, min_refresh_interval=60
    )
    for _ in range(10):
        assert claims(policy, token(key=OTHER_KEY, kid="unknown")) == {}
    assert realm.fetches == 2
    clock.now += 61
    assert claims(policy, token(key=OTHER_KEY, kid="unknown")) == {}
    assert realm.fetches == 3


def test_an_rsa_signing_key_alone_verifies_its_tokens():
    pem = REALM_KEY.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    config = Configurator(settings={"jwt.private_key": pem})
    policy = create_jwt_authentication_policy(config)
    assert (
        claims(policy, policy.create_token("alice"), auth_type="JWT")["sub"] == "alice"
    )
    forged = jwt.encode({"sub": "alice"}, OTHER_KEY, algorithm="RS256")
    assert claims(policy, forged, auth_type="JWT") == {}
