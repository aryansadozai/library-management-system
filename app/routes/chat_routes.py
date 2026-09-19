from flask import Blueprint, request, jsonify

from app.services.chat_services import (
    create_direct_conversation,
    send_message,
    get_messages,
    update_message_status
)

from app.utils.security import token_required


chat_bp = Blueprint("chat", __name__)


@chat_bp.route("/conversations/direct", methods=["POST"])
@token_required
def create_direct_chat(payload):

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body must be JSON"
        }), 400

    if set(data.keys()) != {"username"}:
        return jsonify({
            "error": "Request must contain username only"
        }), 400

    result = create_direct_conversation(
        payload["user_id"],
        data["username"]
    )

    if not result["success"]:
        return jsonify({
            "error": result["message"]
        }), result["status"]

    return jsonify({
        "message": result["message"],
        "conversation_id": result["conversation_id"]
    }), result["status"]


@chat_bp.route(
    "/conversations/<int:conversation_id>/messages",
    methods=["POST"]
)
@token_required
def send_chat_message(payload, conversation_id):

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body must be JSON"
        }), 400

    if set(data.keys()) != {"content"}:
        return jsonify({
            "error": "Request must contain content only"
        }), 400

    result = send_message(
        payload["user_id"],
        conversation_id,
        data["content"]
    )

    if not result["success"]:
        return jsonify({
            "error": result["message"]
        }), result["status"]

    return jsonify({
        "message": result["message"],
        "data": result["data"]
    }), result["status"]


@chat_bp.route(
    "/conversations/<int:conversation_id>/messages",
    methods=["GET"]
)
@token_required
def get_chat_messages(payload, conversation_id):

    result = get_messages(
        payload["user_id"],
        conversation_id
    )

    if not result["success"]:
        return jsonify({
            "error": result["message"]
        }), result["status"]

    return jsonify({
        "messages": result["messages"]
    }), 200


@chat_bp.route(
    "/conversations/<int:conversation_id>/messages/<int:message_id>/status",
    methods=["PATCH"]
)
@token_required
def update_chat_message_status(
    payload,
    conversation_id,
    message_id
):

    data = request.get_json()

    if not data:
        return jsonify({
            "error": "Request body must be JSON"
        }), 400

    if set(data.keys()) != {"status"}:
        return jsonify({
            "error": "Request must contain status only"
        }), 400

    result = update_message_status(
        payload["user_id"],
        conversation_id,
        message_id,
        data["status"]
    )

    if not result["success"]:
        return jsonify({
            "error": result["message"]
        }), result["status"]

    return jsonify({
        "message": result["message"],
        "message_id": result["message_id"],
        "status": result["new_status"]
    }), result["status"]