from jwt import encode, decode, exceptions, PyJWKClient
from os import getenv
from datetime import datetime, timedelta


class Token:

    @classmethod
    def write_token(self, data: dict) -> bytes | None:
        try:
            token = encode(payload={**data, "exp": self.expire_date(days=3)},
                       key=getenv('SECRET_JWT'), algorithm='HS256')
            return token.encode("UTF-8")
        except Exception as e:
            print(str(e))
            return None

    def validate_token(token) -> dict:
        try:
            token_data = decode(token, key=getenv('SECRET_JWT'), algorithms=['HS256'])
            return {'is_valid': True, "token_data": token_data}
        except exceptions.DecodeError:
            return {'is_valid': False, 'error': 'DecodeError'}
        except exceptions.ExpiredSignatureError:
            return {'is_valid': False, 'error': 'ExpiredSignatureError'}

    def validate_aws_token(token) -> dict:
        try:
            jwks_client = PyJWKClient(getenv('JWKS_URL'))
            signing_key = jwks_client.get_signing_key_from_jwt(token)
            token_data = decode(token, key=signing_key, algorithms=["RS256"])
            return {'is_valid': True, "token_data": token_data}
        except exceptions.DecodeError:
            return {'is_valid': False, 'error': 'DecodeError'}
        except exceptions.ExpiredSignatureError:
            return {'is_valid': False, 'error': 'ExpiredSignatureError'}

    @classmethod
    def expire_date(self, days: int) -> datetime:
        now = datetime.now()
        return now + timedelta(days)

