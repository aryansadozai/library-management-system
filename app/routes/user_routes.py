from flask import Blueprint, jsonify , request
from app.services.user_services import get_all_users
from app.utils.auth import token_required
from app.services.user_services import get_current_user

user_bp = Blueprint("users", __name__)


@user_bp.route("/users", methods=["GET"])
def users():
    return jsonify(get_all_users())


@user_bp.route("/me", methods=["GET"])
@token_required
def current_user():
    user_id = request.user["user_id"]

    result = get_current_user(user_id)

    if not result["success"]:
        return jsonify({
            "success": False,
            "message": result["message"]
        }), result["status"]

    return jsonify({
        "success": True,
        "user": result["user"]
    }), 200