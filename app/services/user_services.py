from app.models.database import get_db_connection


def get_all_users():
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()

    cursor.close()
    connection.close()

    return users


def get_current_user(user_id):
    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, username, email
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        if not user:
            return {
                "success": False,
                "status": 404,
                "message": "User not found"
            }

        return {
            "success": True,
            "status": 200,
            "user": user
        }

    except Exception:
        return {
            "success": False,
            "status": 500,
            "message": "Failed to retrieve user"
        }

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()