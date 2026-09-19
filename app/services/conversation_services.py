from app.models.database import get_db_connection


def get_or_create_direct_conversation(user_id, other_user_id):
    if user_id == other_user_id:
        return {
            "success": False,
            "status": 400,
            "message": "You cannot chat with yourself"
        }

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id
            FROM users
            WHERE id IN (%s, %s)
            AND status = 'active'
            """,
            (user_id, other_user_id)
        )

        users = cursor.fetchall()

        if len(users) != 2:
            return {
                "success": False,
                "status": 404,
                "message": "One or both users do not exist or are blocked"
            }

        cursor.execute(
            """
            SELECT c.id
            FROM conversations c
            JOIN conversation_members cm
                ON c.id = cm.conversation_id
            WHERE c.type = 'direct'
            AND cm.user_id IN (%s, %s)
            GROUP BY c.id
            HAVING COUNT(DISTINCT cm.user_id) = 2
            """,
            (user_id, other_user_id)
        )

        conversation = cursor.fetchone()

        if conversation:
            return {
                "success": True,
                "status": 200,
                "message": "Conversation found",
                "conversation_id": conversation["id"]
            }

        cursor.execute(
            """
            INSERT INTO conversations (type)
            VALUES ('direct')
            """
        )

        conversation_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO conversation_members
                (conversation_id, user_id)
            VALUES
                (%s, %s),
                (%s, %s)
            """,
            (
                conversation_id,
                user_id,
                conversation_id,
                other_user_id
            )
        )

        connection.commit()

        return {
            "success": True,
            "status": 201,
            "message": "Conversation created",
            "conversation_id": conversation_id
        }

    except Exception:
        if connection:
            connection.rollback()

        return {
            "success": False,
            "status": 500,
            "message": "Failed to create conversation"
        }

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()
