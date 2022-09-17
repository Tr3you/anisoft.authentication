from flask import Flask
from routes.authentication import routes_auth
from routes.authorization import routes_authorization
from dotenv import load_dotenv


app = Flask(__name__)
app.register_blueprint(routes_auth, url_prefix='/auth')
app.register_blueprint(routes_authorization, url_prefix='/authorization')


if __name__ == '__main__':
    load_dotenv()
    app.run(debug=False, port='4000', host='0.0.0.0')