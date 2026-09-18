from app.models.database import get_db_connection


def create_direct_conversation(user_id, target_username):

    target_username = target_username.strip().lower()

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, status
            FROM users
            WHERE username = %s
            """,
            (target_username,)
        )

        target_user = cursor.fetchone()

        if not target_user:
            return {
                "success": False,
                "status": 404,
                "message": "User not found"
            }

        target_user_id = target_user["id"]

        if user_id == target_user_id:
            return {
                "success": False,
                "status": 400,
                "message": "You cannot create a conversation with yourself"
            }

        if target_user["status"] == "blocked":
            return {
                "success": False,
                "status": 403,
                "message": "User is blocked"
            }

        cursor.execute(
            """
            SELECT c.id
            FROM conversations c
            JOIN conversation_members cm1
                ON c.id = cm1.conversation_id
            JOIN conversation_members cm2
                ON c.id = cm2.conversation_id
            WHERE c.type = 'direct'
              AND cm1.user_id = %s
              AND cm2.user_id = %s
            LIMIT 1
            """,
            (user_id, target_user_id)
        )

        existing_conversation = cursor.fetchone()

        if existing_conversation:
            return {
                "success": True,
                "status": 200,
                "message": "Conversation already exists",
                "conversation_id": existing_conversation["id"]
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
                target_user_id
            )
        )

        connection.commit()

        return {
            "success": True,
            "status": 201,
            "message": "Direct conversation created",
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


def send_message(user_id, conversation_id, content):

    if not isinstance(content, str):
        return {
            "success": False,
            "status": 400,
            "message": "Message content must be text"
        }

    content = content.strip()

    if not content:
        return {
            "success": False,
            "status": 400,
            "message": "Message cannot be empty"
        }

    if len(content) > 4096:
        return {
            "success": False,
            "status": 400,
            "message": "Message is too long"
        }

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id, status
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        )

        user = cursor.fetchone()

        if not user:
            return {
                "success": False,
                "status": 401,
                "message": "User not found"
            }

        if user["status"] == "blocked":
            return {
                "success": False,
                "status": 403,
                "message": "Account is blocked"
            }

        cursor.execute(
            """
            SELECT id
            FROM conversations
            WHERE id = %s
            """,
            (conversation_id,)
        )

        conversation = cursor.fetchone()

        if not conversation:
            return {
                "success": False,
                "status": 404,
                "message": "Conversation not found"
            }

        cursor.execute(
            """
            SELECT id
            FROM conversation_members
            WHERE conversation_id = %s
              AND user_id = %s
            """,
            (conversation_id, user_id)
        )

        membership = cursor.fetchone()

        if not membership:
            return {
                "success": False,
                "status": 403,
                "message": "You are not a member of this conversation"
            }

        cursor.execute(
            """
            INSERT INTO messages
                (conversation_id, sender_id, content)
            VALUES
                (%s, %s, %s)
            """,
            (conversation_id, user_id, content)
        )

        message_id = cursor.lastrowid

        connection.commit()

        cursor.execute(
            """
            SELECT
                id,
                conversation_id,
                sender_id,
                content,
                created_at
            FROM messages
            WHERE id = %s
            """,
            (message_id,)
        )

        message = cursor.fetchone()

        return {
            "success": True,
            "status": 201,
            "message": "Message sent",
            "data": message
        }

    except Exception:
        if connection:
            connection.rollback()

        return {
            "success": False,
            "status": 500,
            "message": "Failed to send message"
        }

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()


def get_messages(user_id, conversation_id):

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT id
            FROM conversations
            WHERE id = %s
            """,
            (conversation_id,)
        )

        conversation = cursor.fetchone()

        if not conversation:
            return {
                "success": False,
                "status": 404,
                "message": "Conversation not found"
            }

        cursor.execute(
            """
            SELECT id
            FROM conversation_members
            WHERE conversation_id = %s
              AND user_id = %s
            """,
            (conversation_id, user_id)
        )

        membership = cursor.fetchone()

        if not membership:
            return {
                "success": False,
                "status": 403,
                "message": "You are not a member of this conversation"
            }

        cursor.execute(
            """
            SELECT
                id,
                sender_id,
                content,
                created_at
            FROM messages
            WHERE conversation_id = %s
            ORDER BY created_at ASC, id ASC
            """,
            (conversation_id,)
        )

        messages = cursor.fetchall()

        return {
            "success": True,
            "status": 200,
            "messages": messages
        }

    except Exception:
        return {
            "success": False,
            "status": 500,
            "message": "Failed to retrieve messages"
        }

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()