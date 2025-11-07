from pyramid.view import view_config
from .policy import JWTAuthenticationPolicy


def includeme(config):
    config.add_directive(
        'set_jwt_authentication_policy',
        set_jwt_authentication_policy,
        action_wrap=True)
    config.add_directive(
        'set_keycloak_authentication_policy',
        set_keycloak_authentication_policy,
        action_wrap=True)


def add_role_principals(userid, request):
    settings = request.registry.settings
    claims = request.jwt_claims
    client = settings.get('keycloak.client', None)
    # Initialize with an "Owner" role
    result = [userid]
    if client is not None and client in claims['resource_access']:
        return result + ['%s' % role for role in
                claims['resource_access'][client]['roles']]
    else:
        return result


def create_jwt_authentication_policy(config, private_key=None, public_key=None,
                                     algorithm=None, expiration=None, leeway=None,
                                     http_header=None, auth_type=None, callback=None, json_encoder=None,
                                     audience=None,):
    settings = config.get_settings()
    private_key = private_key or settings.get('jwt.private_key')
    algorithm = settings.get('jwt.algorithm') or algorithm or 'RS256'
    if not algorithm.startswith('HS'):
        public_key = public_key or settings.get('jwt.public_key')
    else:
        public_key = None
    if expiration is None and 'jwt.expiration' in settings:
        expiration = int(settings.get('jwt.expiration'))
    leeway = int(settings.get('jwt.leeway', 0)) if leeway is None else leeway
    http_header = settings.get('jwt.http_header') or http_header or 'Authorization'
    if http_header.lower() == 'authorization':
        auth_type = settings.get('jwt.auth_type') or auth_type or 'JWT'
    else:
        auth_type = auth_type
    return JWTAuthenticationPolicy(
        private_key=private_key,
        public_key=public_key,
        algorithm=algorithm,
        leeway=leeway,
        expiration=expiration,
        http_header=http_header,
        auth_type=auth_type,
        callback=callback,
        json_encoder=json_encoder,
        audience=audience)


def set_jwt_authentication_policy(config, private_key=None, public_key=None,
                                  algorithm=None, expiration=None, leeway=None,
                                  http_header=None, auth_type=None, callback=None, json_encoder=None,
                                  audience=None,):
    policy = create_jwt_authentication_policy(
        config, private_key, public_key,
        algorithm, expiration, leeway,
        http_header, auth_type, callback, json_encoder, audience)

    def request_create_token(request, principal, expiration=None, audience=None, **claims):
        return policy.create_token(principal, expiration, audience, **claims)

    def request_claims(request):
        return policy.get_claims(request)

    config.set_authentication_policy(policy)
    config.add_request_method(request_create_token, 'create_jwt_token')
    config.add_request_method(request_claims, 'jwt_claims', reify=True)


def set_keycloak_authentication_policy(config):
    settings = config.get_settings()
    realm = settings.get('keycloak.realm', 'master')
    auth_server = settings.get('keycloak.auth_server') or ''
    resource = settings.get('keycloak.resource', '')

    def keycloak_conf(request):
        return {
            "realm": realm,
            "auth-server-url": auth_server,
            "ssl-required": "external",
            "resource": resource,
            "public-client": True,
            "enable-cors": True
        }
    config.add_view(keycloak_conf,
                    route_name="keycloak.json",
                    renderer='json')

    config.add_route('keycloak.json', '/keycloak.json')

    # Enable JWT authentication.
    config.set_jwt_authentication_policy(
        'secret',
        algorithm='HS256',
        auth_type='Bearer',
        http_header="Authorization",
        callback=add_role_principals,
        audience=resource
    )
