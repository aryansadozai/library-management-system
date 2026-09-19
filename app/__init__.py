from flask import Flask
from flask_socketio import SocketIO

from app.routes.user_routes import user_bp
from app.routes.auth_routes import auth_bp
from app.routes.chat_routes import chat_bp


socketio = SocketIO(
    cors_allowed_origins="*"
)


def create_app():

    app = Flask(__name__)

    app.register_blueprint(user_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(chat_bp)

    socketio.init_app(app)

    return app


from app.sockets import chat_socket
