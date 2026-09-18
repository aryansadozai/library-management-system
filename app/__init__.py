from flask import Flask

from app.routes.user_routes import user_bp
from app.routes.auth_routes import auth_bp
from app.routes.chat_routes import chat_bp


def create_app():
    app = Flask(__name__)

    app.register_blueprint(user_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)

    return app