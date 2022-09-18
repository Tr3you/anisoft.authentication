from flask import Blueprint, jsonify, request
from services.auth_service import AuthService
from shared.token import Token


routes_auth = Blueprint('routes_auth', __name__)


@routes_auth.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = AuthService.login(data['email'], data['password'])
    
    if user.get('AuthenticationResult') != None:
        login_data = {
            "email": data['email'],
            "access_token": user['AuthenticationResult']['AccessToken'],
            "id_token": user['AuthenticationResult']['IdToken'],
            "refresh_token": user['AuthenticationResult']['RefreshToken'],
            "expires_in": user['AuthenticationResult']['ExpiresIn'],
        }
        response = jsonify(login_data)
        response.status_code = 200
        return response
    else:
        response  = jsonify({"message": user})
        response.status_code = 200
        return response

@routes_auth.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    result = AuthService.signup(data['email'], data['password'], data['name'], data['lastName'])
    if result.get('UserSub') != None:
        response  = jsonify({"result": "OK"})
        response.status_code = 200
        return response
    else:
        response  = jsonify({"result": "NOK"})
        response.status_code = 500
        return response

@routes_auth.route('/confirmSignup', methods=['POST'])
def confirm_sign_up():
    data = request.get_json()
    result = AuthService().verify_account(data['email'], data['code'])

    if result.get('ResponseMetadata') != None:
        response  = jsonify({"result": "OK"})
        response.status_code = 200
        return response
    else:
        response  = jsonify({"result": "NOK"})
        response.status_code = 500
        return response

@routes_auth.route('/logout', methods=['POST'])
def logout():
    data = request.get_json()
    logout = AuthService.logout(data['access_token'], )

    if logout == {}:
        response  = jsonify({"result": "OK"})
        response.status_code = 200
        return response
    else:
        response  = jsonify({"result": "NOK"})
        response.status_code = 500
        return response

@routes_auth.route('/exchange', methods=['POST'])
def exchange_code():
    data = request.get_json()
    response = AuthService.exchange_code(data["code"])

    if response.get('access_token'):
        response  = jsonify(response)
        response.status_code = 200
        return response
    else:
        response  = jsonify({"result": "NOK"})
        response.status_code = 500
        return response


@routes_auth.route('/recoverPassword', methods=['POST'])
def recover_password():
    pass

@routes_auth.route('/refreshTokens', methods=['POST'])
def refresh_tokens():
    pass


