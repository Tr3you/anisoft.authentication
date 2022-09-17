from flask import Blueprint, request, jsonify
from shared.token import Token
from services.auth_service import AuthService
from shared.utils import Utils

routes_authorization = Blueprint('routes_authorization', __name__)

@routes_authorization.route('/validateToken', methods=['POST'])
def validate_token():
    data = request.get_json()
    validation_result = Token.validate_aws_token(data['token'])
    response  = jsonify(validation_result)
    response.status_code = 200
    return response