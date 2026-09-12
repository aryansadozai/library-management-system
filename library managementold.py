from flask import Flask, jsonify, request
import mysql.connector
import hashlib
import secrets
import jwt
from datetime import datetime, timedelta, timezone, date


app = Flask(__name__)

JWT_SECRET = "change-this-to-a-long-random-secret"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_db_connection():
    db = mysql.connector.connect(
        host="127.0.0.1",
        port=3306,
        user="root",
        password="freefire0000",
        database="library_management",
        use_pure=True
    )
    return db


# =========================================================
# PASSWORD HASHING
# =========================================================

def hash_password(password, salt):
    password_with_salt = password + salt

    password_hash = hashlib.sha256(
        password_with_salt.encode()
    ).hexdigest()

    return password_hash


# =========================================================
# JWT VERIFICATION
# =========================================================

def verify_token():

    auth_header = request.headers.get("Authorization")

    print("AUTH HEADER:", auth_header)

    if not auth_header:
        print("No Authorization header")
        return None

    if not auth_header.startswith("Bearer "):
        print("Wrong Authorization format")
        return None

    token = auth_header.split(" ", 1)[1]

    print("TOKEN RECEIVED")

    try:

        decoded_token = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )

        print("TOKEN VALID:", decoded_token)

        return decoded_token

    except jwt.ExpiredSignatureError:

        print("TOKEN EXPIRED")

        return None

    except jwt.InvalidTokenError as e:

        print("INVALID TOKEN:", e)

        return None


# =========================================================
# ROLE HELPERS
# =========================================================

def is_staff(user):

    return user and user.get("role") in ["librarian", "admin"]


def is_admin(user):

    return user and user.get("role") == "admin"


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return jsonify({
        "message": "Library Management API is running"
    })


# =========================================================
# REGISTER USER
# =========================================================

@app.route("/register", methods=["POST"])
def register():

    data = request.get_json()

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON"
        }), 400

    required_fields = [
        "first_name",
        "last_name",
        "email",
        "phone",
        "age",
        "password"
    ]

    for field in required_fields:

        if field not in data:

            return jsonify({
                "error": f"{field} is required"
            }), 400

    if not isinstance(data["age"], int):

        return jsonify({
            "error": "Age must be an integer"
        }), 400

    if data["age"] < 18:

        return jsonify({
            "error": "User must be 18 or older"
        }), 400

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT user_id
            FROM users
            WHERE email = %s OR phone = %s
        """, (
            data["email"],
            data["phone"]
        ))

        existing_user = cursor.fetchone()

        if existing_user:

            return jsonify({
                "error": "Email or phone already exists"
            }), 409

        salt = secrets.token_hex(16)

        password_hash = hash_password(
            data["password"],
            salt
        )

        cursor.execute("""
            INSERT INTO users
            (
                first_name,
                last_name,
                email,
                phone,
                age,
                password_hash,
                salt,
                role
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,'user')
        """, (
            data["first_name"],
            data["last_name"],
            data["email"],
            data["phone"],
            data["age"],
            password_hash,
            salt
        ))

        db.commit()

        return jsonify({
            "message": "User registered successfully",
            "user_id": cursor.lastrowid
        }), 201

    finally:

        cursor.close()
        db.close()


# =========================================================
# LOGIN
# =========================================================

@app.route("/login", methods=["POST"])
def login():

    data = request.get_json()

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON"
        }), 400

    if "email" not in data or "password" not in data:

        return jsonify({
            "error": "Email and password are required"
        }), 400

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                user_id,
                email,
                password_hash,
                salt,
                role,
                account_status
            FROM users
            WHERE email = %s
        """, (data["email"],))

        user = cursor.fetchone()

        if not user:

            return jsonify({
                "error": "Invalid email or password"
            }), 401

        if user["account_status"] == "blocked":

            return jsonify({
                "error": "Account is blocked"
            }), 403

        password_hash = hash_password(
            data["password"],
            user["salt"]
        )

        if password_hash != user["password_hash"]:

            return jsonify({
                "error": "Invalid email or password"
            }), 401

        payload = {

            "user_id": user["user_id"],

            "role": user["role"],

            "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
        }

        token = jwt.encode(
            payload,
            JWT_SECRET,
            algorithm="HS256"
        )

        return jsonify({
            "message": "Login successful",
            "token": token,
            "user_id": user["user_id"],
            "role": user["role"]
        })

    finally:

        cursor.close()
        db.close()


# =========================================================
# PROFILE
# =========================================================

@app.route("/profile", methods=["GET"])
def profile():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                user_id,
                first_name,
                last_name,
                email,
                phone,
                age,
                role,
                account_status
            FROM users
            WHERE user_id = %s
        """, (user["user_id"],))

        result = cursor.fetchone()

        if not result:

            return jsonify({
                "error": "User not found"
            }), 404

        return jsonify(result)

    finally:

        cursor.close()
        db.close()


# =========================================================
# USERS
# STAFF ONLY
# =========================================================

@app.route("/users", methods=["GET"])
def users():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_staff(user):

        return jsonify({
            "error": "Staff access required"
        }), 403

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                user_id,
                first_name,
                last_name,
                email,
                phone,
                age,
                role,
                account_status
            FROM users
            ORDER BY user_id
        """)

        return jsonify(cursor.fetchall())

    finally:

        cursor.close()
        db.close()


# =========================================================
# STAFF CREATE USER
# =========================================================

@app.route("/librarian/users", methods=["POST"])
def librarian_create_user():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_staff(user):

        return jsonify({
            "error": "Librarian or admin access required"
        }), 403

    data = request.get_json()

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON"
        }), 400

    required_fields = [
        "first_name",
        "last_name",
        "email",
        "phone",
        "age",
        "password"
    ]

    for field in required_fields:

        if field not in data:

            return jsonify({
                "error": f"{field} is required"
            }), 400

    if not isinstance(data["age"], int) or data["age"] < 18:

        return jsonify({
            "error": "User must be 18 or older"
        }), 400

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT user_id
            FROM users
            WHERE email = %s OR phone = %s
        """, (
            data["email"],
            data["phone"]
        ))

        if cursor.fetchone():

            return jsonify({
                "error": "Email or phone already exists"
            }), 409

        salt = secrets.token_hex(16)

        password_hash = hash_password(
            data["password"],
            salt
        )

        cursor.execute("""
            INSERT INTO users
            (
                first_name,
                last_name,
                email,
                phone,
                age,
                password_hash,
                salt,
                role
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,'user')
        """, (
            data["first_name"],
            data["last_name"],
            data["email"],
            data["phone"],
            data["age"],
            password_hash,
            salt
        ))

        db.commit()

        return jsonify({
            "message": "User created successfully",
            "user_id": cursor.lastrowid
        }), 201

    finally:

        cursor.close()
        db.close()


# =========================================================
# BLOCK / UNBLOCK USER
# =========================================================

@app.route("/librarian/users/<int:user_id>/block", methods=["PATCH"])
def block_user(user_id):

    staff = verify_token()

    if not staff:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_staff(staff):

        return jsonify({
            "error": "Staff access required"
        }), 403

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT user_id, role, account_status
            FROM users
            WHERE user_id = %s
        """, (user_id,))

        target = cursor.fetchone()

        if not target:

            return jsonify({
                "error": "User not found"
            }), 404

        # Librarian cannot block another librarian/admin
        if staff["role"] == "librarian" and target["role"] != "user":

            return jsonify({
                "error": "Librarian can only block normal users"
            }), 403

        if target["user_id"] == staff["user_id"]:

            return jsonify({
                "error": "You cannot block yourself"
            }), 400

        new_status = (
            "blocked"
            if target["account_status"] == "active"
            else "active"
        )

        cursor.execute("""
            UPDATE users
            SET account_status = %s
            WHERE user_id = %s
        """, (
            new_status,
            user_id
        ))

        db.commit()

        return jsonify({
            "message": f"User is now {new_status}",
            "user_id": user_id,
            "account_status": new_status
        })

    finally:

        cursor.close()
        db.close()


# =========================================================
# DELETE USER
# =========================================================

@app.route("/librarian/users/<int:user_id>", methods=["DELETE"])
def delete_user(user_id):

    staff = verify_token()

    if not staff:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_staff(staff):

        return jsonify({
            "error": "Staff access required"
        }), 403

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT user_id, role
            FROM users
            WHERE user_id = %s
        """, (user_id,))

        target = cursor.fetchone()

        if not target:

            return jsonify({
                "error": "User not found"
            }), 404

        if target["user_id"] == staff["user_id"]:

            return jsonify({
                "error": "You cannot delete yourself"
            }), 400

        if staff["role"] == "librarian" and target["role"] != "user":

            return jsonify({
                "error": "Librarian can only delete normal users"
            }), 403

        cursor.execute("""
            DELETE FROM users
            WHERE user_id = %s
        """, (user_id,))

        db.commit()

        return jsonify({
            "message": "User deleted successfully",
            "user_id": user_id
        })

    except mysql.connector.Error as e:

        db.rollback()

        return jsonify({
            "error": "User cannot be deleted because related records exist",
            "details": str(e)
        }), 409

    finally:

        cursor.close()
        db.close()


# =========================================================
# ADMIN CREATE LIBRARIAN
# =========================================================

@app.route("/admin/librarians", methods=["POST"])
def create_librarian():

    admin = verify_token()

    if not admin:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_admin(admin):

        return jsonify({
            "error": "Admin access required"
        }), 403

    data = request.get_json()

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON"
        }), 400

    required_fields = [
        "first_name",
        "last_name",
        "email",
        "phone",
        "age",
        "password"
    ]

    for field in required_fields:

        if field not in data:

            return jsonify({
                "error": f"{field} is required"
            }), 400

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT user_id
            FROM users
            WHERE email = %s OR phone = %s
        """, (
            data["email"],
            data["phone"]
        ))

        if cursor.fetchone():

            return jsonify({
                "error": "Email or phone already exists"
            }), 409

        salt = secrets.token_hex(16)

        password_hash = hash_password(
            data["password"],
            salt
        )

        cursor.execute("""
            INSERT INTO users
            (
                first_name,
                last_name,
                email,
                phone,
                age,
                password_hash,
                salt,
                role
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,'librarian')
        """, (
            data["first_name"],
            data["last_name"],
            data["email"],
            data["phone"],
            data["age"],
            password_hash,
            salt
        ))

        db.commit()

        return jsonify({
            "message": "Librarian created successfully",
            "librarian_id": cursor.lastrowid
        }), 201

    finally:

        cursor.close()
        db.close()


# =========================================================
# ADMIN LIST LIBRARIANS
# =========================================================

@app.route("/admin/librarians", methods=["GET"])
def list_librarians():

    admin = verify_token()

    if not admin:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_admin(admin):

        return jsonify({
            "error": "Admin access required"
        }), 403

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                user_id,
                first_name,
                last_name,
                email,
                phone,
                age,
                role,
                account_status
            FROM users
            WHERE role = 'librarian'
            ORDER BY user_id
        """)

        return jsonify(cursor.fetchall())

    finally:

        cursor.close()
        db.close()


# =========================================================
# ADMIN BLOCK / UNBLOCK LIBRARIAN
# =========================================================

@app.route("/admin/librarians/<int:user_id>/block", methods=["PATCH"])
def block_librarian(user_id):

    admin = verify_token()

    if not admin:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_admin(admin):

        return jsonify({
            "error": "Admin access required"
        }), 403

    if user_id == admin["user_id"]:

        return jsonify({
            "error": "You cannot block yourself"
        }), 400

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT user_id, role, account_status
            FROM users
            WHERE user_id = %s
        """, (user_id,))

        target = cursor.fetchone()

        if not target:

            return jsonify({
                "error": "User not found"
            }), 404

        if target["role"] != "librarian":

            return jsonify({
                "error": "Target is not a librarian"
            }), 400

        new_status = (
            "blocked"
            if target["account_status"] == "active"
            else "active"
        )

        cursor.execute("""
            UPDATE users
            SET account_status = %s
            WHERE user_id = %s
        """, (
            new_status,
            user_id
        ))

        db.commit()

        return jsonify({
            "message": f"Librarian is now {new_status}",
            "user_id": user_id,
            "account_status": new_status
        })

    finally:

        cursor.close()
        db.close()


# =========================================================
# ADMIN DELETE LIBRARIAN
# =========================================================

@app.route("/admin/librarians/<int:user_id>", methods=["DELETE"])
def delete_librarian(user_id):

    admin = verify_token()

    if not admin:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_admin(admin):

        return jsonify({
            "error": "Admin access required"
        }), 403

    if user_id == admin["user_id"]:

        return jsonify({
            "error": "You cannot delete yourself"
        }), 400

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT user_id, role
            FROM users
            WHERE user_id = %s
        """, (user_id,))

        target = cursor.fetchone()

        if not target:

            return jsonify({
                "error": "Librarian not found"
            }), 404

        if target["role"] != "librarian":

            return jsonify({
                "error": "Target is not a librarian"
            }), 400

        cursor.execute("""
            DELETE FROM users
            WHERE user_id = %s
        """, (user_id,))

        db.commit()

        return jsonify({
            "message": "Librarian deleted successfully",
            "user_id": user_id
        })

    except mysql.connector.Error as e:

        db.rollback()

        return jsonify({
            "error": "Librarian cannot be deleted because related records exist",
            "details": str(e)
        }), 409

    finally:

        cursor.close()
        db.close()


# =========================================================
# BOOK SEARCH
# =========================================================

@app.route("/books", methods=["GET"])
def books():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    title = request.args.get("title")

    author = request.args.get("author")

    category = request.args.get("category")

    available = request.args.get("available")

    page = request.args.get("page", 1, type=int)

    limit = request.args.get("limit", 10, type=int)

    sort = request.args.get("sort", "book_id")

    allowed_sort = {
        "book_id": "b.book_id",
        "title": "b.title",
        "author": "a.author_name",
        "category": "c.category_name",
        "total_copies": "total_copies",
        "available_copies": "available_copies"
    }

    if sort not in allowed_sort:

        return jsonify({
            "error": "Invalid sort field"
        }), 400

    if page < 1 or limit < 1:

        return jsonify({
            "error": "Invalid pagination"
        }), 400

    offset = (page - 1) * limit

    conditions = []

    params = []

    if title:

        conditions.append(
            "b.title LIKE %s"
        )

        params.append(f"%{title}%")

    if author:

        conditions.append(
            "a.author_name LIKE %s"
        )

        params.append(f"%{author}%")

    if category:

        conditions.append(
            "c.category_name LIKE %s"
        )

        params.append(f"%{category}%")

    where_clause = ""

    if conditions:

        where_clause = "WHERE " + " AND ".join(conditions)

    having_clause = ""

    if available == "true":

        having_clause = "HAVING available_copies > 0"

    elif available == "false":

        having_clause = "HAVING available_copies = 0"

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        query = f"""
            SELECT
                b.book_id,
                b.title,
                a.author_name AS author,
                c.category_name AS category,
                COUNT(bc.copy_id) AS total_copies,
                COALESCE(
                    SUM(
                        CASE
                            WHEN bc.status = 'available'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS available_copies
            FROM books b

            JOIN authors a
                ON b.author_id = a.author_id

            JOIN categories c
                ON b.category_id = c.category_id

            LEFT JOIN book_copies bc
                ON b.book_id = bc.book_id

            {where_clause}

            GROUP BY
                b.book_id,
                b.title,
                a.author_name,
                c.category_name

            {having_clause}

            ORDER BY {allowed_sort[sort]}

            LIMIT %s OFFSET %s
        """

        query_params = params + [limit, offset]

        cursor.execute(query, query_params)

        results = cursor.fetchall()

        count_query = f"""
            SELECT COUNT(*)
            FROM
            (
                SELECT
                    b.book_id

                FROM books b

                JOIN authors a
                    ON b.author_id = a.author_id

                JOIN categories c
                    ON b.category_id = c.category_id

                LEFT JOIN book_copies bc
                    ON b.book_id = bc.book_id

                {where_clause}

                GROUP BY
                    b.book_id

                {having_clause}
            ) AS filtered_books
        """

        cursor.execute(count_query, params)

        total = cursor.fetchone()["COUNT(*)"]

        return jsonify({
            "page": page,
            "limit": limit,
            "total": total,
            "books": results
        })

    finally:

        cursor.close()
        db.close()


# =========================================================
# CREATE AUTHOR
# =========================================================

@app.route("/authors", methods=["POST"])
def create_author():

    staff = verify_token()

    if not staff:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_staff(staff):

        return jsonify({
            "error": "Staff access required"
        }), 403

    data = request.get_json()

    if not isinstance(data, dict) or "author_name" not in data:

        return jsonify({
            "error": "author_name is required"
        }), 400

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            INSERT INTO authors (author_name)
            VALUES (%s)
        """, (data["author_name"],))

        db.commit()

        return jsonify({
            "message": "Author created successfully",
            "author_id": cursor.lastrowid
        }), 201

    finally:

        cursor.close()
        db.close()


# =========================================================
# CREATE CATEGORY
# =========================================================

@app.route("/categories", methods=["POST"])
def create_category():

    staff = verify_token()

    if not staff:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_staff(staff):

        return jsonify({
            "error": "Staff access required"
        }), 403

    data = request.get_json()

    if not isinstance(data, dict) or "category_name" not in data:

        return jsonify({
            "error": "category_name is required"
        }), 400

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            INSERT INTO categories (category_name)
            VALUES (%s)
        """, (data["category_name"],))

        db.commit()

        return jsonify({
            "message": "Category created successfully",
            "category_id": cursor.lastrowid
        }), 201

    finally:

        cursor.close()
        db.close()


# =========================================================
# CREATE BOOK
# =========================================================

@app.route("/books", methods=["POST"])
def create_book():

    staff = verify_token()

    if not staff:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_staff(staff):

        return jsonify({
            "error": "Staff access required"
        }), 403

    data = request.get_json()

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON"
        }), 400

    required_fields = [
        "title",
        "author_id",
        "category_id",
        "borrowing_price",
        "loan_price",
        "fine_per_day"
    ]

    for field in required_fields:

        if field not in data:

            return jsonify({
                "error": f"{field} is required"
            }), 400

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            INSERT INTO books
            (
                title,
                author_id,
                category_id,
                borrowing_price,
                loan_price,
                fine_per_day
            )
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (
            data["title"],
            data["author_id"],
            data["category_id"],
            data["borrowing_price"],
            data["loan_price"],
            data["fine_per_day"]
        ))

        db.commit()

        return jsonify({
            "message": "Book created successfully",
            "book_id": cursor.lastrowid
        }), 201

    except mysql.connector.Error as e:

        db.rollback()

        return jsonify({
            "error": str(e)
        }), 400

    finally:

        cursor.close()
        db.close()


# =========================================================
# UPDATE BOOK
# =========================================================

@app.route("/books/<int:book_id>", methods=["PATCH"])
def update_book(book_id):

    staff = verify_token()

    if not staff:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_staff(staff):

        return jsonify({
            "error": "Staff access required"
        }), 403

    data = request.get_json()

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON"
        }), 400

    allowed_fields = [
        "title",
        "author_id",
        "category_id",
        "borrowing_price",
        "loan_price",
        "fine_per_day"
    ]

    updates = []

    values = []

    for field in allowed_fields:

        if field in data:

            updates.append(
                f"{field} = %s"
            )

            values.append(data[field])

    if not updates:

        return jsonify({
            "error": "No valid fields supplied"
        }), 400

    values.append(book_id)

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT book_id
            FROM books
            WHERE book_id = %s
        """, (book_id,))

        if not cursor.fetchone():

            return jsonify({
                "error": "Book not found"
            }), 404

        query = f"""
            UPDATE books
            SET {", ".join(updates)}
            WHERE book_id = %s
        """

        cursor.execute(query, values)

        db.commit()

        return jsonify({
            "message": "Book updated successfully",
            "book_id": book_id
        })

    finally:

        cursor.close()
        db.close()


# =========================================================
# ADD BOOK COPY
# =========================================================

@app.route("/books/<int:book_id>/copies", methods=["POST"])
def add_copy(book_id):

    staff = verify_token()

    if not staff:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_staff(staff):

        return jsonify({
            "error": "Staff access required"
        }), 403

    data = request.get_json()

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON"
        }), 400

    book_condition = data.get(
        "book_condition",
        "good"
    )

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT book_id
            FROM books
            WHERE book_id = %s
        """, (book_id,))

        if not cursor.fetchone():

            return jsonify({
                "error": "Book not found"
            }), 404

        cursor.execute("""
            INSERT INTO book_copies
            (
                book_id,
                book_condition,
                status
            )
            VALUES (%s,%s,'available')
        """, (
            book_id,
            book_condition
        ))

        db.commit()

        return jsonify({
            "message": "Book copy added successfully",
            "copy_id": cursor.lastrowid,
            "book_id": book_id,
            "condition": book_condition,
            "status": "available"
        }), 201

    finally:

        cursor.close()
        db.close()


# =========================================================
# VIEW BOOK COPIES
# =========================================================

@app.route("/books/<int:book_id>/copies", methods=["GET"])
def view_copies(book_id):

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                copy_id,
                book_id,
                book_condition,
                status
            FROM book_copies
            WHERE book_id = %s
            ORDER BY copy_id
        """, (book_id,))

        return jsonify(cursor.fetchall())

    finally:

        cursor.close()
        db.close()


# =========================================================
# MANAGE COPY
# =========================================================

@app.route("/copies/<int:copy_id>", methods=["PATCH"])
def manage_copy(copy_id):

    staff = verify_token()

    if not staff:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_staff(staff):

        return jsonify({
            "error": "Staff access required"
        }), 403

    data = request.get_json()

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON"
        }), 400

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                copy_id,
                status,
                book_condition
            FROM book_copies
            WHERE copy_id = %s
        """, (copy_id,))

        copy = cursor.fetchone()

        if not copy:

            return jsonify({
                "error": "Copy not found"
            }), 404

        updates = []

        values = []

        if "book_condition" in data:

            updates.append(
                "book_condition = %s"
            )

            values.append(data["book_condition"])

        if "status" in data:

            allowed_statuses = [
                "available",
                "borrowed",
                "lost",
                "damaged",
                "maintenance"
            ]

            if data["status"] not in allowed_statuses:

                return jsonify({
                    "error": "Invalid copy status"
                }), 400

            updates.append(
                "status = %s"
            )

            values.append(data["status"])

        if not updates:

            return jsonify({
                "error": "No valid fields supplied"
            }), 400

        values.append(copy_id)

        query = f"""
            UPDATE book_copies
            SET {", ".join(updates)}
            WHERE copy_id = %s
        """

        cursor.execute(query, values)

        db.commit()

        return jsonify({
            "message": "Copy updated successfully",
            "copy_id": copy_id
        })

    finally:

        cursor.close()
        db.close()


# =========================================================
# RESERVATION
# =========================================================

@app.route("/reservations", methods=["POST"])
def create_reservation():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if user["role"] != "user":

        return jsonify({
            "error": "Only users can make reservations"
        }), 403

    data = request.get_json()

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON"
        }), 400

    if "book_id" not in data:

        return jsonify({
            "error": "book_id is required"
        }), 400

    book_id = data["book_id"]

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT book_id
            FROM books
            WHERE book_id = %s
        """, (book_id,))

        if not cursor.fetchone():

            return jsonify({
                "error": "Book not found"
            }), 404

        cursor.execute("""
            SELECT reservation_id
            FROM reservations
            WHERE user_id = %s
              AND book_id = %s
              AND status = 'waiting'
        """, (
            user["user_id"],
            book_id
        ))

        if cursor.fetchone():

            return jsonify({
                "error": "You already have a waiting reservation"
            }), 409

        cursor.execute("""
            INSERT INTO reservations
            (
                user_id,
                book_id,
                status
            )
            VALUES (%s,%s,'waiting')
        """, (
            user["user_id"],
            book_id
        ))

        db.commit()

        return jsonify({
            "message": "Reservation created successfully",
            "reservation_id": cursor.lastrowid,
            "user_id": user["user_id"],
            "book_id": book_id,
            "status": "waiting"
        }), 201

    finally:

        cursor.close()
        db.close()


# =========================================================
# MY RESERVATIONS
# =========================================================

@app.route("/my-reservations", methods=["GET"])
def my_reservations():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                r.reservation_id,
                r.user_id,
                r.book_id,
                b.title,
                r.reservation_time,
                r.status
            FROM reservations r
            JOIN books b
                ON r.book_id = b.book_id
            WHERE r.user_id = %s
            ORDER BY r.reservation_time DESC
        """, (user["user_id"],))

        return jsonify(cursor.fetchall())

    finally:

        cursor.close()
        db.close()


# =========================================================
# CANCEL RESERVATION
# =========================================================

@app.route("/reservations/<int:reservation_id>", methods=["DELETE"])
def cancel_reservation(reservation_id):

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                reservation_id,
                user_id,
                status
            FROM reservations
            WHERE reservation_id = %s
        """, (reservation_id,))

        reservation = cursor.fetchone()

        if not reservation:

            return jsonify({
                "error": "Reservation not found"
            }), 404

        if reservation["user_id"] != user["user_id"]:

            return jsonify({
                "error": "You do not own this reservation"
            }), 403

        if reservation["status"] != "waiting":

            return jsonify({
                "error": "Only waiting reservations can be cancelled"
            }), 400

        cursor.execute("""
            DELETE FROM reservations
            WHERE reservation_id = %s
        """, (reservation_id,))

        db.commit()

        return jsonify({
            "message": "Reservation cancelled successfully",
            "reservation_id": reservation_id
        })

    finally:

        cursor.close()
        db.close()


# =========================================================
# BORROW BOOK
# =========================================================

@app.route("/borrowings", methods=["POST"])
def create_borrowing():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if user["role"] != "user":

        return jsonify({
            "error": "Only users can borrow books"
        }), 403

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                COUNT(*) AS total
            FROM borrowings
            WHERE user_id = %s
              AND status IN ('active','overdue')
        """, (user["user_id"],))

        active_count = cursor.fetchone()["total"]

        if active_count >= 3:

            return jsonify({
                "error": "Maximum 3 active borrowings allowed"
            }), 400

        data = request.get_json()

        if not isinstance(data, dict) or "book_id" not in data:

            return jsonify({
                "error": "book_id is required"
            }), 400

        book_id = data["book_id"]

        cursor.execute("""
            SELECT
                reservation_id
            FROM reservations
            WHERE user_id = %s
              AND book_id = %s
              AND status = 'waiting'
            ORDER BY reservation_time
            LIMIT 1
        """, (
            user["user_id"],
            book_id
        ))

        reservation = cursor.fetchone()

        if not reservation:

            return jsonify({
                "error": "You must reserve this book first"
            }), 400

        cursor.execute("""
            SELECT
                bc.copy_id
            FROM book_copies bc
            WHERE bc.book_id = %s
              AND bc.status = 'available'
            LIMIT 1
        """, (book_id,))

        copy = cursor.fetchone()

        if not copy:

            return jsonify({
                "error": "No available copy"
            }), 409

        cursor.execute("""
            SELECT
                book_id,
                borrowing_price
            FROM books
            WHERE book_id = %s
        """, (book_id,))

        book = cursor.fetchone()

        due_date = date.today() + timedelta(days=10)

        cursor.execute("""
            INSERT INTO borrowings
            (
                user_id,
                copy_id,
                due_date,
                price,
                status
            )
            VALUES (%s,%s,%s,%s,'active')
        """, (
            user["user_id"],
            copy["copy_id"],
            due_date,
            book["borrowing_price"]
        ))

        borrowing_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO payments
            (
                user_id,
                borrowing_id,
                amount,
                payment_type
            )
            VALUES (%s,%s,%s,'borrowing')
        """, (
            user["user_id"],
            borrowing_id,
            book["borrowing_price"]
        ))

        payment_id = cursor.lastrowid

        cursor.execute("""
            UPDATE book_copies
            SET status = 'borrowed'
            WHERE copy_id = %s
        """, (copy["copy_id"],))

        cursor.execute("""
            UPDATE reservations
            SET status = 'fulfilled'
            WHERE reservation_id = %s
        """, (reservation["reservation_id"],))

        db.commit()

        return jsonify({
            "message": "Book borrowed successfully",
            "borrowing_id": borrowing_id,
            "payment_id": payment_id,
            "user_id": user["user_id"],
            "book_id": book_id,
            "copy_id": copy["copy_id"],
            "price": float(book["borrowing_price"]),
            "borrow_date": date.today().isoformat(),
            "due_date": due_date.isoformat(),
            "status": "active"
        }), 201

    except Exception as e:

        db.rollback()

        return jsonify({
            "error": str(e)
        }), 500

    finally:

        cursor.close()
        db.close()


# =========================================================
# LOAN BOOK
# =========================================================

@app.route("/loans", methods=["POST"])
def create_loan():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if user["role"] != "user":

        return jsonify({
            "error": "Only users can take loans"
        }), 403

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                COUNT(*) AS total
            FROM loans
            WHERE user_id = %s
              AND status IN ('active','overdue')
        """, (user["user_id"],))

        active_count = cursor.fetchone()["total"]

        if active_count >= 3:

            return jsonify({
                "error": "Maximum 3 active loans allowed"
            }), 400

        data = request.get_json()

        if not isinstance(data, dict) or "book_id" not in data:

            return jsonify({
                "error": "book_id is required"
            }), 400

        book_id = data["book_id"]

        cursor.execute("""
            SELECT
                reservation_id
            FROM reservations
            WHERE user_id = %s
              AND book_id = %s
              AND status = 'waiting'
            ORDER BY reservation_time
            LIMIT 1
        """, (
            user["user_id"],
            book_id
        ))

        reservation = cursor.fetchone()

        if not reservation:

            return jsonify({
                "error": "You must reserve this book first"
            }), 400

        cursor.execute("""
            SELECT
                bc.copy_id
            FROM book_copies bc
            WHERE bc.book_id = %s
              AND bc.status = 'available'
            LIMIT 1
        """, (book_id,))

        copy = cursor.fetchone()

        if not copy:

            return jsonify({
                "error": "No available copy"
            }), 409

        cursor.execute("""
            SELECT
                book_id,
                loan_price
            FROM books
            WHERE book_id = %s
        """, (book_id,))

        book = cursor.fetchone()

        due_date = date.today() + timedelta(days=10)

        cursor.execute("""
            INSERT INTO loans
            (
                user_id,
                copy_id,
                due_date,
                status,
                price
            )
            VALUES (%s,%s,%s,'active',%s)
        """, (
            user["user_id"],
            copy["copy_id"],
            due_date,
            book["loan_price"]
        ))

        loan_id = cursor.lastrowid

        cursor.execute("""
            UPDATE book_copies
            SET status = 'borrowed'
            WHERE copy_id = %s
        """, (copy["copy_id"],))

        cursor.execute("""
            UPDATE reservations
            SET status = 'fulfilled'
            WHERE reservation_id = %s
        """, (reservation["reservation_id"],))

        db.commit()

        return jsonify({
            "message": "Book loan created successfully",
            "loan_id": loan_id,
            "user_id": user["user_id"],
            "book_id": book_id,
            "copy_id": copy["copy_id"],
            "price": float(book["loan_price"]),
            "borrow_date": date.today().isoformat(),
            "due_date": due_date.isoformat(),
            "status": "active"
        }), 201

    except Exception as e:

        db.rollback()

        return jsonify({
            "error": str(e)
        }), 500

    finally:

        cursor.close()
        db.close()


# =========================================================
# RETURN LOAN
# =========================================================

@app.route("/loans/<int:loan_id>/return", methods=["POST"])
def return_loan(loan_id):

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                l.loan_id,
                l.user_id,
                l.copy_id,
                l.due_date,
                l.status,
                l.price,
                b.book_id,
                b.fine_per_day
            FROM loans l
            JOIN book_copies bc
                ON l.copy_id = bc.copy_id
            JOIN books b
                ON bc.book_id = b.book_id
            WHERE l.loan_id = %s
        """, (loan_id,))

        loan = cursor.fetchone()

        if not loan:

            return jsonify({
                "error": "Loan not found"
            }), 404

        if loan["user_id"] != user["user_id"]:

            return jsonify({
                "error": "You do not own this loan"
            }), 403

        if loan["status"] == "returned":

            return jsonify({
                "error": "Loan already returned"
            }), 400

        overdue_days = 0

        if date.today() > loan["due_date"]:

            overdue_days = (
                date.today() - loan["due_date"]
            ).days

        late_fine = (
            overdue_days * loan["fine_per_day"]
        )

        cursor.execute("""
            UPDATE loans
            SET
                return_time = NOW(),
                status = 'returned',
                fine_amount = %s
            WHERE loan_id = %s
        """, (
            late_fine,
            loan_id
        ))

        cursor.execute("""
            UPDATE book_copies
            SET
                status = 'maintenance',
                book_condition = 'pending_inspection'
            WHERE copy_id = %s
        """, (loan["copy_id"],))

        fine_id = None

        if late_fine > 0:

            cursor.execute("""
                INSERT INTO fines
                (
                    user_id,
                    loan_id,
                    fine_amount,
                    reason,
                    status
                )
                VALUES (%s,%s,%s,%s,'unpaid')
            """, (
                user["user_id"],
                loan_id,
                late_fine,
                f"Late return ({overdue_days} overdue days)"
            ))

            fine_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO payments
            (
                user_id,
                loan_id,
                amount,
                payment_type
            )
            VALUES (%s,%s,%s,'loan')
        """, (
            user["user_id"],
            loan_id,
            loan["price"]
        ))

        payment_id = cursor.lastrowid

        db.commit()

        return jsonify({
            "message": "Loan returned successfully and sent for inspection",
            "loan_id": loan_id,
            "payment_id": payment_id,
            "fine_id": fine_id,
            "fine_amount": float(late_fine),
            "copy_status": "maintenance",
            "copy_condition": "pending_inspection"
        })

    except Exception as e:

        db.rollback()

        return jsonify({
            "error": str(e)
        }), 500

    finally:

        cursor.close()
        db.close()


# =========================================================
# RETURN BORROWING
# =========================================================

@app.route("/borrowings/<int:borrowing_id>/return", methods=["POST"])
def return_borrowing(borrowing_id):

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                br.borrowing_id,
                br.user_id,
                br.copy_id,
                br.due_date,
                br.status,
                b.book_id,
                b.fine_per_day
            FROM borrowings br
            JOIN book_copies bc
                ON br.copy_id = bc.copy_id
            JOIN books b
                ON bc.book_id = b.book_id
            WHERE br.borrowing_id = %s
        """, (borrowing_id,))

        borrowing = cursor.fetchone()

        if not borrowing:

            return jsonify({
                "error": "Borrowing not found"
            }), 404

        if borrowing["user_id"] != user["user_id"]:

            return jsonify({
                "error": "You do not own this borrowing"
            }), 403

        if borrowing["status"] == "returned":

            return jsonify({
                "error": "Borrowing already returned"
            }), 400

        overdue_days = 0

        if date.today() > borrowing["due_date"]:

            overdue_days = (
                date.today() - borrowing["due_date"]
            ).days

        late_fine = (
            overdue_days * borrowing["fine_per_day"]
        )

        cursor.execute("""
            UPDATE borrowings
            SET
                return_time = NOW(),
                status = 'returned',
                fine_amount = %s
            WHERE borrowing_id = %s
        """, (
            late_fine,
            borrowing_id
        ))

        cursor.execute("""
            UPDATE book_copies
            SET
                status = 'maintenance',
                book_condition = 'pending_inspection'
            WHERE copy_id = %s
        """, (borrowing["copy_id"],))

        fine_id = None

        if late_fine > 0:

            cursor.execute("""
                INSERT INTO fines
                (
                    user_id,
                    borrowing_id,
                    fine_amount,
                    reason,
                    status
                )
                VALUES (%s,%s,%s,%s,'unpaid')
            """, (
                user["user_id"],
                borrowing_id,
                late_fine,
                f"Late return ({overdue_days} overdue days)"
            ))

            fine_id = cursor.lastrowid

        db.commit()

        return jsonify({
            "message": "Borrowing returned successfully and sent for inspection",
            "borrowing_id": borrowing_id,
            "fine_id": fine_id,
            "fine_amount": float(late_fine),
            "copy_status": "maintenance",
            "copy_condition": "pending_inspection"
        })

    except Exception as e:

        db.rollback()

        return jsonify({
            "error": str(e)
        }), 500

    finally:

        cursor.close()
        db.close()


# =========================================================
# MY BORROWINGS
# =========================================================

@app.route("/my-borrowings", methods=["GET"])
def my_borrowings():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                br.borrowing_id,
                br.user_id,
                br.copy_id,
                bc.book_id,
                b.title,
                br.borrow_time,
                br.due_date,
                br.return_time,
                br.price,
                br.fine_amount,
                br.status
            FROM borrowings br

            JOIN book_copies bc
                ON br.copy_id = bc.copy_id

            JOIN books b
                ON bc.book_id = b.book_id

            WHERE br.user_id = %s

            ORDER BY br.borrow_time DESC
        """, (user["user_id"],))

        return jsonify(cursor.fetchall())

    finally:

        cursor.close()
        db.close()


# =========================================================
# MY LOANS
# =========================================================

@app.route("/my-loans", methods=["GET"])
def my_loans():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                l.loan_id,
                l.user_id,
                l.copy_id,
                bc.book_id,
                b.title,
                l.borrow_time,
                l.due_date,
                l.return_time,
                l.price,
                l.fine_amount,
                l.status
            FROM loans l

            JOIN book_copies bc
                ON l.copy_id = bc.copy_id

            JOIN books b
                ON bc.book_id = b.book_id

            WHERE l.user_id = %s

            ORDER BY l.borrow_time DESC
        """, (user["user_id"],))

        return jsonify(cursor.fetchall())

    finally:

        cursor.close()
        db.close()


# =========================================================
# MY PAYMENTS
# =========================================================

@app.route("/my-payments", methods=["GET"])
def my_payments():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                payment_id,
                user_id,
                borrowing_id,
                loan_id,
                fine_id,
                amount,
                payment_type,
                payment_time
            FROM payments
            WHERE user_id = %s
            ORDER BY payment_time DESC
        """, (user["user_id"],))

        return jsonify(cursor.fetchall())

    finally:

        cursor.close()
        db.close()


# =========================================================
# MY FINES
# =========================================================

@app.route("/my-fines", methods=["GET"])
def my_fines():

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                fine_id,
                borrowing_id,
                loan_id,
                fine_amount,
                reason,
                created_at,
                paid_at,
                status
            FROM fines
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (user["user_id"],))

        return jsonify(cursor.fetchall())

    finally:

        cursor.close()
        db.close()


# =========================================================
# PAY FINE
# =========================================================

@app.route("/fines/<int:fine_id>/pay", methods=["POST"])
def pay_fine(fine_id):

    user = verify_token()

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                fine_id,
                user_id,
                borrowing_id,
                loan_id,
                fine_amount,
                reason,
                status,
                paid_at
            FROM fines
            WHERE fine_id = %s
            FOR UPDATE
        """, (fine_id,))

        fine = cursor.fetchone()

        if not fine:

            return jsonify({
                "error": "Fine not found"
            }), 404

        if fine["user_id"] != user["user_id"]:

            return jsonify({
                "error": "You do not own this fine"
            }), 403

        if fine["status"] == "paid":

            return jsonify({
                "error": "Fine already paid"
            }), 400

        cursor.execute("""
            INSERT INTO payments
            (
                user_id,
                borrowing_id,
                loan_id,
                fine_id,
                amount,
                payment_type
            )
            VALUES (%s,%s,%s,%s,%s,'fine')
        """, (
            user["user_id"],
            fine["borrowing_id"],
            fine["loan_id"],
            fine_id,
            fine["fine_amount"]
        ))

        payment_id = cursor.lastrowid

        cursor.execute("""
            UPDATE fines
            SET
                status = 'paid',
                paid_at = NOW()
            WHERE fine_id = %s
              AND status = 'unpaid'
        """, (fine_id,))

        if cursor.rowcount != 1:

            db.rollback()

            return jsonify({
                "error": "Fine payment failed"
            }), 409

        db.commit()

        return jsonify({
            "message": "Fine paid successfully",
            "fine_id": fine_id,
            "payment_id": payment_id,
            "amount": float(fine["fine_amount"]),
            "reason": fine["reason"],
            "payment_type": "fine",
            "status": "paid"
        })

    except Exception as e:

        db.rollback()

        return jsonify({
            "error": str(e)
        }), 500

    finally:

        cursor.close()
        db.close()


# =========================================================
# LIBRARIAN / ADMIN INSPECT RETURNED COPY
# =========================================================

@app.route("/librarian/copies/<int:copy_id>/inspect", methods=["POST"])
def inspect_copy(copy_id):

    inspector = verify_token()

    if not inspector:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if inspector["role"] not in ["librarian", "admin"]:

        return jsonify({
            "error": "Librarian or admin access required"
        }), 403

    data = request.get_json()

    if not isinstance(data, dict):

        return jsonify({
            "error": "Invalid JSON"
        }), 400

    condition = data.get("condition")

    if condition not in ["good", "damaged", "lost"]:

        return jsonify({
            "error": "Condition must be good, damaged, or lost"
        }), 400

    fine_amount = data.get("fine_amount", 0)

    if condition in ["damaged", "lost"]:

        try:

            fine_amount = float(fine_amount)

        except (TypeError, ValueError):

            return jsonify({
                "error": "fine_amount must be a number"
            }), 400

        if fine_amount <= 0:

            return jsonify({
                "error": "Fine amount must be greater than 0"
            }), 400

    else:

        fine_amount = 0

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        cursor.execute("""
            SELECT
                copy_id,
                book_id,
                status,
                book_condition
            FROM book_copies
            WHERE copy_id = %s
        """, (copy_id,))

        copy = cursor.fetchone()

        if not copy:

            return jsonify({
                "error": "Copy not found"
            }), 404

        if copy["status"] != "maintenance":

            return jsonify({
                "error": "Copy is not waiting for inspection"
            }), 400

        if copy["book_condition"] != "pending_inspection":

            return jsonify({
                "error": "Copy is not pending inspection"
            }), 400

        # Find most recent returned transaction
        cursor.execute("""
            SELECT
                transaction_type,
                transaction_id,
                user_id
            FROM
            (
                SELECT
                    'borrowing' AS transaction_type,
                    borrowing_id AS transaction_id,
                    user_id,
                    return_time
                FROM borrowings
                WHERE copy_id = %s
                  AND status = 'returned'

                UNION ALL

                SELECT
                    'loan' AS transaction_type,
                    loan_id AS transaction_id,
                    user_id,
                    return_time
                FROM loans
                WHERE copy_id = %s
                  AND status = 'returned'
            ) AS transactions

            ORDER BY return_time DESC

            LIMIT 1
        """, (
            copy_id,
            copy_id
        ))

        transaction = cursor.fetchone()

        if not transaction:

            return jsonify({
                "error": "No returned transaction found"
            }), 400

        # Check existing damage/loss fine BEFORE changing copy
        cursor.execute("""
            SELECT fine_id
            FROM fines
            WHERE
                (
                    borrowing_id = %s
                    AND %s = 'borrowing'
                )
                OR
                (
                    loan_id = %s
                    AND %s = 'loan'
                )
            LIMIT 1
        """, (
            transaction["transaction_id"],
            transaction["transaction_type"],
            transaction["transaction_id"],
            transaction["transaction_type"]
        ))

        existing_fine = cursor.fetchone()

        if existing_fine:

            return jsonify({
                "error": "A fine already exists for this returned transaction",
                "fine_id": existing_fine["fine_id"]
            }), 409

        # GOOD
        if condition == "good":

            cursor.execute("""
                UPDATE book_copies
                SET
                    status = 'available',
                    book_condition = 'good'
                WHERE copy_id = %s
            """, (copy_id,))

            db.commit()

            return jsonify({
                "message": "Book inspection completed",
                "copy_id": copy_id,
                "book_id": copy["book_id"],
                "condition": "good",
                "status": "available",
                "fine_id": None,
                "fine_amount": 0,
                "inspected_by": inspector["user_id"],
                "inspector_role": inspector["role"]
            })

        # DAMAGED / LOST
        if condition == "damaged":

            new_status = "damaged"

            reason = "Book damaged"

        else:

            new_status = "lost"

            reason = "Book lost"

        cursor.execute("""
            UPDATE book_copies
            SET
                status = %s,
                book_condition = %s
            WHERE copy_id = %s
        """, (
            new_status,
            condition,
            copy_id
        ))

        if transaction["transaction_type"] == "borrowing":

            cursor.execute("""
                INSERT INTO fines
                (
                    user_id,
                    borrowing_id,
                    fine_amount,
                    reason,
                    status
                )
                VALUES (%s,%s,%s,%s,'unpaid')
            """, (
                transaction["user_id"],
                transaction["transaction_id"],
                fine_amount,
                reason
            ))

        else:

            cursor.execute("""
                INSERT INTO fines
                (
                    user_id,
                    loan_id,
                    fine_amount,
                    reason,
                    status
                )
                VALUES (%s,%s,%s,%s,'unpaid')
            """, (
                transaction["user_id"],
                transaction["transaction_id"],
                fine_amount,
                reason
            ))

        fine_id = cursor.lastrowid

        db.commit()

        return jsonify({
            "message": "Book inspection completed",
            "copy_id": copy_id,
            "book_id": copy["book_id"],
            "condition": condition,
            "status": new_status,
            "fine_id": fine_id,
            "fine_amount": fine_amount,
            "fine_status": "unpaid",
            "inspected_by": inspector["user_id"],
            "inspector_role": inspector["role"]
        })

    except Exception as e:

        db.rollback()

        return jsonify({
            "error": str(e)
        }), 500

    finally:

        cursor.close()
        db.close()


# =========================================================
# CHECK OVERDUE BORROWINGS + LOANS
# =========================================================

@app.route("/staff/overdue/check", methods=["POST"])
def check_overdue():

    staff = verify_token()

    if not staff:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if not is_staff(staff):

        return jsonify({
            "error": "Librarian or admin access required"
        }), 403

    db = get_db_connection()

    cursor = db.cursor(dictionary=True, buffered=True)

    try:

        # Borrowings
        cursor.execute("""
            UPDATE borrowings
            SET status = 'overdue'
            WHERE status = 'active'
              AND due_date < CURDATE()
        """)

        borrowing_count = cursor.rowcount

        # Loans
        cursor.execute("""
            UPDATE loans
            SET status = 'overdue'
            WHERE status = 'active'
              AND due_date < CURDATE()
        """)

        loan_count = cursor.rowcount

        db.commit()

        return jsonify({
            "message": "Overdue check completed",
            "borrowings_marked_overdue": borrowing_count,
            "loans_marked_overdue": loan_count
        })

    finally:

        cursor.close()
        db.close()


# =========================================================
# RUN APP
# =========================================================

if __name__ == "__main__":

    app.run(debug=True)