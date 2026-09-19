import jwt

from flask import request
from flask_socketio import emit, join_room

from app import socketio
from app.config import Config
from app.services.chat_services import (
    is_conversation_member,
    send_message,
    update_message_status
)
from app.models.database import get_db_connection


connected_users = {}
user_connections = {}


def set_user_online(user_id):

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE users
            SET is_online = 1
            WHERE id = %s
            """,
            (user_id,)
        )

        connection.commit()

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


def set_user_offline(user_id):

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            UPDATE users
            SET is_online = 0
            WHERE id = %s
            """,
            (user_id,)
        )

        connection.commit()

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


def add_user_connection(user_id, sid):

    connected_users[sid] = user_id

    if user_id not in user_connections:
        user_connections[user_id] = set()

    user_connections[user_id].add(sid)

    set_user_online(user_id)


def remove_user_connection(user_id, sid):

    if user_id in user_connections:
        user_connections[user_id].discard(sid)

        if not user_connections[user_id]:
            del user_connections[user_id]

            set_user_offline(user_id)


def emit_to_user(user_id, event, data):

    sids = user_connections.get(user_id, set())

    for sid in sids:
        emit(
            event,
            data,
            to=sid
        )


@socketio.on("connect")
def handle_connect(auth):

    if not auth or "token" not in auth:
        return False

    token = auth["token"]

    try:
        payload = jwt.decode(
            token,
            Config.JWT_SECRET,
            algorithms=["HS256"]
        )

        user_id = payload["user_id"]

    except jwt.ExpiredSignatureError:
        return False

    except jwt.InvalidTokenError:
        return False

    add_user_connection(
        user_id,
        request.sid
    )

    print(
        f"User {user_id} connected "
        f"with SID {request.sid}"
    )

    emit("connection_response", {
        "message": "Connected successfully"
    })


@socketio.on("join_conversation")
def handle_join_conversation(data):

    user_id = connected_users.get(request.sid)

    if user_id is None:
        emit("error", {
            "message": "Authentication required"
        })
        return

    if not data or "conversation_id" not in data:
        emit("error", {
            "message": "conversation_id is required"
        })
        return

    try:
        conversation_id = int(data["conversation_id"])
    except (TypeError, ValueError):
        emit("error", {
            "message": "conversation_id must be an integer"
        })
        return

    if not is_conversation_member(
        user_id,
        conversation_id
    ):
        emit("error", {
            "message": "You are not a member of this conversation"
        })
        return

    room = f"conversation_{conversation_id}"

    join_room(room)

    emit("conversation_joined", {
        "conversation_id": conversation_id
    })


@socketio.on("send_message")
def handle_send_message(data):

    user_id = connected_users.get(request.sid)

    if user_id is None:
        emit("error", {
            "message": "Authentication required"
        })
        return

    if not data:
        emit("error", {
            "message": "Request data is required"
        })
        return

    if "conversation_id" not in data:
        emit("error", {
            "message": "conversation_id is required"
        })
        return

    if "content" not in data:
        emit("error", {
            "message": "content is required"
        })
        return

    try:
        conversation_id = int(data["conversation_id"])
    except (TypeError, ValueError):
        emit("error", {
            "message": "conversation_id must be an integer"
        })
        return

    if not is_conversation_member(
        user_id,
        conversation_id
    ):
        emit("error", {
            "message": "You are not a member of this conversation"
        })
        return

    result = send_message(
        user_id,
        conversation_id,
        data["content"]
    )

    if not result["success"]:
        emit("error", {
            "message": result["message"]
        })
        return

    room = f"conversation_{conversation_id}"

    emit(
        "new_message",
        {
            "message": result["data"]
        },
        to=room
    )


@socketio.on("message_delivered")
def handle_message_delivered(data):

    user_id = connected_users.get(request.sid)

    if user_id is None:
        emit("error", {
            "message": "Authentication required"
        })
        return

    if not data or "conversation_id" not in data:
        emit("error", {
            "message": "conversation_id is required"
        })
        return

    if "message_id" not in data:
        emit("error", {
            "message": "message_id is required"
        })
        return

    try:
        conversation_id = int(data["conversation_id"])
        message_id = int(data["message_id"])
    except (TypeError, ValueError):
        emit("error", {
            "message": "conversation_id and message_id must be integers"
        })
        return

    if not is_conversation_member(
        user_id,
        conversation_id
    ):
        emit("error", {
            "message": "You are not a member of this conversation"
        })
        return

    result = update_message_status(
        user_id,
        conversation_id,
        message_id,
        "delivered"
    )

    if not result["success"]:
        emit("error", {
            "message": result["message"]
        })
        return

    emit_to_user(
        result["sender_id"],
        "message_status",
        {
            "message_id": message_id,
            "conversation_id": conversation_id,
            "status": "delivered"
        }
    )


@socketio.on("message_read")
def handle_message_read(data):

    user_id = connected_users.get(request.sid)

    if user_id is None:
        emit("error", {
            "message": "Authentication required"
        })
        return

    if not data or "conversation_id" not in data:
        emit("error", {
            "message": "conversation_id is required"
        })
        return

    if "message_id" not in data:
        emit("error", {
            "message": "message_id is required"
        })
        return

    try:
        conversation_id = int(data["conversation_id"])
        message_id = int(data["message_id"])
    except (TypeError, ValueError):
        emit("error", {
            "message": "conversation_id and message_id must be integers"
        })
        return

    if not is_conversation_member(
        user_id,
        conversation_id
    ):
        emit("error", {
            "message": "You are not a member of this conversation"
        })
        return

    result = update_message_status(
        user_id,
        conversation_id,
        message_id,
        "read"
    )

    if not result["success"]:
        emit("error", {
            "message": result["message"]
        })
        return

    emit_to_user(
        result["sender_id"],
        "message_status",
        {
            "message_id": message_id,
            "conversation_id": conversation_id,
            "status": "read"
        }
    )


@socketio.on("disconnect")
def handle_disconnect():

    sid = request.sid

    user_id = connected_users.pop(
        sid,
        None
    )

    if user_id is None:
        return

    remove_user_connection(
        user_id,
        sid
    )

    print(
        f"User {user_id} disconnected "
        f"with SID {sid}"
    )