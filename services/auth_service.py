from logging import exception
import boto3
import botocore
from os import getenv
import hmac, hashlib, base64
from urllib.parse import urlencode
import base64
import requests


class AuthService():

    @classmethod
    def login(self, email: str, password: str):
        try:
            cognito_client = boto3.client('cognito-idp', region_name= getenv('COGNITO_REGION'))
            secret_hash = self.get_secret_hash(email, getenv('COGNITO_CLIENT_ID'), getenv('COGNITO_CLIENT_SECRET'))
            response = cognito_client.initiate_auth (
            AuthFlow='USER_PASSWORD_AUTH',
            ClientId= getenv('COGNITO_CLIENT_ID'),
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': secret_hash
            }
            )
            return response
        except botocore.exceptions.ClientError as error:
            return {"exception": error.response['Error']['Code']}

    @classmethod
    def signup(self, email: str, password: str, name: str, last_name: str):
        cognito_client = boto3.client('cognito-idp', region_name= getenv('COGNITO_REGION'))
        secret_hash = self.get_secret_hash(email, getenv('COGNITO_CLIENT_ID'), getenv('COGNITO_CLIENT_SECRET'))
        response = cognito_client.sign_up(
        ClientId= getenv('COGNITO_CLIENT_ID'),
        SecretHash= secret_hash,
        Username=email,
        Password=password,
        UserAttributes=[
            {
                'Name': 'email',
                'Value': email
            },
                        {
                'Name': 'given_name',
                'Value': name
            },
            {
                'Name': 'family_name',
                'Value': last_name
            },
        ])
        return response

    @classmethod
    def verify_account(self, email, code):
        cognito_client = boto3.client('cognito-idp', region_name= getenv('COGNITO_REGION'))
        secret_hash = self.get_secret_hash(email, getenv('COGNITO_CLIENT_ID'), getenv('COGNITO_CLIENT_SECRET'))
        response = cognito_client.confirm_sign_up(
            ClientId= getenv('COGNITO_CLIENT_ID'),
            SecretHash= secret_hash,
            Username= email,
            ConfirmationCode= code,
        )
        return response

    @classmethod
    def logout(self, token):
        cognito_client = boto3.client('cognito-idp', region_name= getenv('COGNITO_REGION'))
        response = cognito_client.global_sign_out(
        AccessToken= token
        )
        return response

    @classmethod
    def exchange_code(self, code):
        params = {
            "code": code, 
            "grant_type": "authorization_code",
            "client_id": getenv('COGNITO_CLIENT_ID'), 
            "redirect_uri": getenv('REDIRECT_URI')
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded", 
            "Authorization": self.getBase64EncodedCredential()
        }
        data = urlencode(params)
        response = requests.post(getenv('COGNITO_HOST') + "/oauth2/token", data=data, headers=headers)
        return response.json()
    

    @classmethod
    def get_secret_hash(self, username, app_client_id, app_client_Secret) -> str:
        username = username
        app_client_id = app_client_id
        key = app_client_Secret
        message = bytes(username+app_client_id,'utf-8')
        key = bytes(app_client_Secret,'utf-8')
        secret_hash = base64.b64encode(hmac.new(key, message, digestmod=hashlib.sha256).digest()).decode()

        return secret_hash

    @classmethod
    def getBase64EncodedCredential(self) -> str:
        return "Basic " + base64.b64encode((getenv('COGNITO_CLIENT_ID') + ":" + getenv('COGNITO_CLIENT_SECRET')).encode("ascii")).decode("ascii")