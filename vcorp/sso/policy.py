import datetime
import logging
import threading
import time
import warnings
import jwt
from jwt import PyJWKClient
from jwt.algorithms import get_default_algorithms
from zope.interface import implementer
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.interfaces import IAuthenticationPolicy


log = logging.getLogger("pyramid_jwt")
marker = []


def verification_key(private_key, algorithm):
    """Return the key that verifies tokens signed with ``private_key``.

    A shared secret verifies its own tokens; an asymmetric private key is verified by
    its public half.
    """
    if private_key is None or algorithm.startswith("HS"):
        return private_key
    key = get_default_algorithms()[algorithm].prepare_key(private_key)
    return key.public_key() if hasattr(key, "public_key") else key


@implementer(IAuthenticationPolicy)
class JWTAuthenticationPolicy(CallbackAuthenticationPolicy):
    def __init__(
        self,
        private_key,
        public_key=None,
        algorithm="HS512",
        leeway=0,
        expiration=None,
        default_claims=None,
        http_header="Authorization",
        auth_type="JWT",
        callback=None,
        json_encoder=None,
        audience=None,
    ):
        self.private_key = private_key
        self.public_key = (
            public_key
            if public_key is not None
            else verification_key(private_key, algorithm)
        )
        self.algorithm = algorithm
        self.leeway = leeway
        self.default_claims = default_claims if default_claims else {}
        self.http_header = http_header
        self.auth_type = auth_type
        if expiration:
            if not isinstance(expiration, datetime.timedelta):
                expiration = datetime.timedelta(seconds=expiration)
            self.expiration = expiration
        else:
            self.expiration = None
        if audience:
            self.audience = audience
        else:
            self.audience = None
        self.callback = callback
        self.json_encoder = json_encoder

    def create_token(self, principal, expiration=None, audience=None, **claims):
        payload = self.default_claims.copy()
        payload.update(claims)
        payload["sub"] = principal
        payload["iat"] = iat = datetime.datetime.utcnow()
        expiration = expiration or self.expiration
        audience = audience or self.audience
        if expiration:
            if not isinstance(expiration, datetime.timedelta):
                expiration = datetime.timedelta(seconds=expiration)
            payload["exp"] = iat + expiration
        if audience:
            payload["aud"] = audience
        token = jwt.encode(
            payload,
            self.private_key,
            algorithm=self.algorithm,
            json_encoder=self.json_encoder,
        )
        if not isinstance(token, str):  # Python3 unicode madness
            token = token.decode("ascii")
        return token

    def get_claims(self, request):
        if self.http_header == "Authorization":
            try:
                if request.authorization is None:
                    return {}
            except ValueError:  # Invalid Authorization header
                return {}
            (auth_type, token) = request.authorization
            if auth_type != self.auth_type:
                return {}
        else:
            token = request.headers.get(self.http_header)

        if not token:
            return {}
        if token.startswith("Bearer ") or token.startswith("bearer "):
            token = token[len("bearer ") :]
        try:
            return self.decode(token)
        except jwt.PyJWTError as e:
            log.warning("Invalid JWT token from %s: %s", request.remote_addr, e)
            return {}

    def decode(self, token):
        """Return a token's claims after verifying its signature, expiry and audience.

        Raises:
            jwt.PyJWTError: If the token is not valid.
        """
        return jwt.decode(
            token,
            self.public_key,
            algorithms=[self.algorithm],
            leeway=self.leeway,
            audience=self.audience,
            options={"verify_aud": self.audience is not None},
        )

    def unauthenticated_userid(self, request):
        return request.jwt_claims.get("preferred_username")

    def remember(self, request, principal, **kw):
        warnings.warn(
            "JWT tokens need to be returned by an API. Using remember() "
            "has no effect.",
            stacklevel=3,
        )
        return []

    def forget(self, request):
        warnings.warn(
            "JWT tokens are managed by API (users) manually. Using forget() "
            "has no effect.",
            stacklevel=3,
        )
        return []


class KeycloakAuthenticationPolicy(JWTAuthenticationPolicy):
    """Accepts bearer tokens issued and signed by a Keycloak realm.

    A token is verified against the keys the realm publishes, and must be signed with
    one of ``algorithms``, not be expired and name the realm as its issuer (and
    ``audience``, when one is set). A token that can't be verified, including when the
    keys can't be fetched, authenticates nobody.

    The realm's keys are re-fetched every ``keys_lifespan`` seconds, so a key the realm
    removes stops being trusted. A token naming an unknown key triggers a re-fetch at
    most once every ``min_refresh_interval`` seconds.
    """

    ALGORITHMS = ["RS256"]

    def __init__(
        self,
        issuer,
        audience=None,
        leeway=0,
        callback=None,
        jwks_client=None,
        algorithms=None,
        keys_lifespan=300,
        min_refresh_interval=60,
    ):
        algorithms = list(algorithms or self.ALGORITHMS)
        for algorithm in algorithms:
            if algorithm == "none" or algorithm.startswith("HS"):
                raise ValueError(f"{algorithm} is not an asymmetric signing algorithm")
        super().__init__(
            None,
            algorithm=algorithms[0],
            leeway=leeway,
            http_header="Authorization",
            auth_type="Bearer",
            callback=callback,
            audience=audience,
        )
        self.algorithms = algorithms
        self.issuer = issuer.rstrip("/")
        self.jwks_client = jwks_client or PyJWKClient(
            f"{self.issuer}/protocol/openid-connect/certs",
            cache_jwk_set=True,
            lifespan=keys_lifespan,
            timeout=5,  # seconds; a stalled Keycloak mustn't hold a request for long
        )
        self.min_refresh_interval = min_refresh_interval
        self._last_refresh = None
        self._refresh_lock = threading.Lock()

    def create_token(self, principal, expiration=None, audience=None, **claims):
        raise NotImplementedError("Keycloak issues the tokens this policy accepts")

    def signing_key(self, token):
        """Return the realm's public key that signed ``token``.

        Raises:
            jwt.PyJWTError: If the realm publishes no such key.
        """
        kid = jwt.get_unverified_header(token).get("kid")
        key = self._find_key(self.jwks_client.get_signing_keys(), kid)
        if key is None and self._may_refresh():
            key = self._find_key(self.jwks_client.get_signing_keys(refresh=True), kid)
        if key is None:
            raise jwt.PyJWKClientError(
                f'Unable to find a signing key that matches: "{kid}"'
            )
        return key.key

    @staticmethod
    def _find_key(keys, kid):
        return next((key for key in keys if key.key_id == kid), None)

    def _may_refresh(self):
        with self._refresh_lock:
            now = time.monotonic()
            if (
                self._last_refresh is not None
                and now - self._last_refresh < self.min_refresh_interval
            ):
                return False
            self._last_refresh = now
            return True

    def decode(self, token):
        return jwt.decode(
            token,
            self.signing_key(token),
            algorithms=self.algorithms,
            issuer=self.issuer,
            leeway=self.leeway,
            audience=self.audience,
            options={
                "require": ["exp", "iss"],
                "verify_aud": self.audience is not None,
            },
        )
