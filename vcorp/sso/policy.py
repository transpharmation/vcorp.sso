import datetime
import logging
import warnings
import jwt
from jwt import PyJWKClient
from zope.interface import implementer
from pyramid.authentication import CallbackAuthenticationPolicy
from pyramid.interfaces import IAuthenticationPolicy


log = logging.getLogger("pyramid_jwt")
marker = []


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
        self.public_key = public_key if public_key is not None else private_key
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

    A token is verified against the keys the realm publishes, and must not be expired
    and must name the realm as its issuer (and ``audience``, when one is set). A token
    that can't be verified, including when the keys can't be fetched, authenticates
    nobody.
    """

    ALGORITHMS = ["RS256"]

    def __init__(
        self, issuer, audience=None, leeway=0, callback=None, jwks_client=None
    ):
        super().__init__(
            None,
            algorithm="RS256",
            leeway=leeway,
            http_header="Authorization",
            auth_type="Bearer",
            callback=callback,
            audience=audience,
        )
        self.issuer = issuer.rstrip("/")
        self.jwks_client = jwks_client or PyJWKClient(
            f"{self.issuer}/protocol/openid-connect/certs", cache_keys=True
        )

    def create_token(self, principal, expiration=None, audience=None, **claims):
        raise NotImplementedError("Keycloak issues the tokens this policy accepts")

    def decode(self, token):
        key = self.jwks_client.get_signing_key_from_jwt(token).key
        return jwt.decode(
            token,
            key,
            algorithms=self.ALGORITHMS,
            issuer=self.issuer,
            leeway=self.leeway,
            audience=self.audience,
            options={
                "require": ["exp", "iss"],
                "verify_aud": self.audience is not None,
            },
        )
