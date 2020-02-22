import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'keingsw.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffee-shop'

# AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# Auth Header

def get_token_auth_header():
    """Validate authorization header in the request, and returns JWT token in request header.

    Returns:
        string: JWT token in request header
    """

    auth_header = request.headers.get('Authorization', None)

    if not auth_header:
        raise AuthError({
            'status': 'authorization_header_missing',
            'message': 'Authorization header is expected.'
        }, 401)

    auth_header_parts = auth_header.split(' ')

    if auth_header_parts[0].lower() != 'bearer':
        raise AuthError({
            'status': 'invalid_header',
            'message': 'Authorization header must start with "Bearer".'
        }, 401)

    elif len(auth_header_parts) == 1:
        raise AuthError({
            'status': 'invalid_header',
            'message': 'No token found.".'
        }, 401)

    elif len(auth_header_parts) > 2:
        raise AuthError({
            'status': 'invalid_header',
            'message': 'Authorization header must be bearer token.".'
        }, 401)

    token = auth_header_parts[1]
    return token


def check_permissions(permission, payload):
    """Check the user has apermission to the given action

    Args:
        string: permission
        dictionary: decoded jwt payload

    Returns:
        boolean: returns true when the user has a permission otherwise error is raised
    """

    if 'permissions' not in payload:
        raise AuthError({
            'status': 'no_permissions_included',
            'message': 'JWT is expected to have `permissions` parameter.".'
        }, 401)

    if permission not in payload['permissions']:
        raise AuthError({
            'status': 'permission_not_allowed',
            'message': 'Permission is not allowed".'
        }, 403)

    return True


def verify_decode_jwt(token):
    """Verify a json web token and decode the payload from it

    Args:
        string: a json web token

    Returns:
        the decoded payload
    """
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())

    unverified_header = jwt.get_unverified_header(token)
    if 'kid' not in unverified_header:
        raise AuthError({
            'status': 'invalid_header',
            'message': 'Authorization malformed.'
        }, 401)

    rsa_key = {}
    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e'],
            }

    if not rsa_key:
        raise AuthError({
            'status': 'invalid_header',
            'message': 'Unabble to find the appropriate key.'
        }, 401)

    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f'https://{AUTH0_DOMAIN}/'
        )
        return payload

    except jwt.ExpiredSignatureError:
        raise AuthError({
            'status': 'token_expired',
            'message': 'Token expired.'
        }, 401)

    except jwt.JWTClaimsError:
        raise AuthError({
            'status': 'invalid_claims',
            'message': 'Incorrect claims. Please, check the audience and issuer.'
        }, 401)

    except Exception:
        raise AuthError({
            'status': 'invalid_header',
            'message': 'Unable to parse authentication token.'
        }, 401)


def requires_auth(permission=''):
    """Gets a auth token from request header, verify the token, and check if the user has the requested permission

    Args:
        string: permission(i.e. 'post:drink')

    Returns:
        the decorator which passes the decoded payload to the decorated method
    """
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)
        return wrapper
    return requires_auth_decorator
