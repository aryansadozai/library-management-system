import os
import re
import math
import hmac
import logging
import secrets as secrets_module
import time
import uuid
from decimal import Decimal, InvalidOperation
from functools import wraps
from datetime import datetime, timedelta, timezone, date

from flask import Flask, jsonify, request, g
from flask.json.provider import DefaultJSONProvider
import mysql.connector
from mysql.connector import pooling
import hashlib
import jwt


# =========================================================
# CONFIG
# =========================================================

app = Flask(__name__)


class _DecimalAwareJSONProvider(DefaultJSONProvider):
    @staticmethod
    def default(obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return DefaultJSONProvider.default(obj)


app.json = _DecimalAwareJSONProvider(app)


JWT_SECRET = os.environ.get("JWT_SECRET")

if not JWT_SECRET:
    raise RuntimeError(
        "JWT_SECRET environment variable must be set "
        "(no hardcoded fallback on purpose)."
    )


DB_CONFIG = {
    "host": os.environ.get("DB_HOST", "127.0.0.1"),
    "port": int(os.environ.get("DB_PORT", "3306")),
    "user": os.environ.get("DB_USER", "root"),
    "password": os.environ.get("DB_PASSWORD"),
    "database": os.environ.get("DB_NAME", "library_management"),
    "use_pure": True,
    "autocommit": False,
}


if not DB_CONFIG["password"]:
    raise RuntimeError(
        "DB_PASSWORD environment variable must be set "
        "(no hardcoded fallback on purpose)."
    )


MAX_ACTIVE_HOLDS = 3
RESERVATION_EXPIRY_DAYS = 3
JWT_LIFETIME_MINUTES = 30

ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", "").split(",")
    if o.strip()
]


MONEY_MAX = Decimal("99999999.99")


# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(message)s",
)


class _RequestIdFilter(logging.Filter):
    def filter(self, record):
        try:
            record.request_id = g.get("request_id", "-")
        except RuntimeError:
            record.request_id = "-"
        return True


logger = logging.getLogger("library_api")
logger.addFilter(_RequestIdFilter())


@app.before_request
def _assign_request_id():
    g.request_id = uuid.uuid4().hex[:12]
    g.request_start = time.time()


@app.after_request
def _log_and_secure(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    origin = request.headers.get("Origin")

    if origin and (
        origin in ALLOWED_ORIGINS or "*" in ALLOWED_ORIGINS
    ):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = (
            "Authorization, Content-Type"
        )
        response.headers["Access-Control-Allow-Methods"] = (
            "GET, POST, PATCH, DELETE, OPTIONS"
        )

    duration_ms = int(
        (time.time() - getattr(g, "request_start", time.time())) * 1000
    )

    logger.info(
        "%s %s -> %s (%dms)",
        request.method,
        request.path,
        response.status_code,
        duration_ms,
    )

    return response


# =========================================================
# RATE LIMITING
# =========================================================

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address

    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["300 per hour"],
    )

    logger.info("Using Flask-Limiter for rate limiting.")

except ImportError:

    logger.warning(
        "flask_limiter not installed; using simple in-memory "
        "rate limiter. Use Flask-Limiter + Redis in production."
    )

    def get_remote_address_fallback():
        trust_proxy = (
            os.environ.get("TRUST_PROXY", "false").lower() == "true"
        )

        if trust_proxy:
            forwarded = request.headers.get("X-Forwarded-For")

            if forwarded:
                return forwarded.split(",")[0].strip()

        return request.remote_addr or "unknown"


    class _SimpleRateLimiter:

        def __init__(self):
            self._hits = {}

        def limit(self, spec):
            count, _, period = spec.partition(" per ")

            count = int(count)

            window = {
                "second": 1,
                "minute": 60,
                "hour": 3600,
                "day": 86400,
            }[period.strip()]

            def decorator(f):

                @wraps(f)
                def wrapped(*args, **kwargs):
                    key = (
                        f.__name__,
                        get_remote_address_fallback(),
                    )

                    now = time.time()

                    hits = [
                        t
                        for t in self._hits.get(key, [])
                        if now - t < window
                    ]

                    if len(hits) >= count:
                        return jsonify({
                            "error": "Too many requests, slow down"
                        }), 429

                    hits.append(now)
                    self._hits[key] = hits

                    return f(*args, **kwargs)

                return wrapped

            return decorator


    limiter = _SimpleRateLimiter()


# =========================================================
# DATABASE CONNECTION POOL
# =========================================================

_connection_pool = None


def _init_pool():
    global _connection_pool

    try:
        _connection_pool = pooling.MySQLConnectionPool(
            pool_name="library_pool",
            pool_size=int(
                os.environ.get("DB_POOL_SIZE", "10")
            ),
            pool_reset_session=True,
            **DB_CONFIG,
        )

        logger.info("Database connection pool initialized.")

    except mysql.connector.Error as e:
        logger.error(
            "Could not initialize DB connection pool: %s",
            e,
        )

        _connection_pool = None


_init_pool()


def get_db_connection():
    if _connection_pool is not None:

        try:
            return _connection_pool.get_connection()

        except mysql.connector.Error as e:
            logger.warning(
                "Pool unavailable, opening direct connection: %s",
                e,
            )

    return mysql.connector.connect(
        **DB_CONFIG
    )


# =========================================================
# ENSURE SMALL REQUIRED SCHEMA
# =========================================================

def ensure_schema():

    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti VARCHAR(64) PRIMARY KEY,
                user_id INT NOT NULL,
                revoked_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL
            )
        """)

        db.commit()

        cursor.close()
        db.close()

    except mysql.connector.Error as e:
        logger.warning(
            "Could not ensure schema: %s",
            e,
        )


ensure_schema()


# =========================================================
# PASSWORD HASHING
# =========================================================

def hash_password(password, salt):
    return hashlib.sha256(
        (password + salt).encode()
    ).hexdigest()


# =========================================================
# VALIDATION
# =========================================================

EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
)

PHONE_RE = re.compile(
    r"^\+?[0-9][0-9\-\s()]{6,29}$"
)


def err(message, code):
    return jsonify({
        "error": message
    }), code


def clean_string(value, field_name, max_length=255):

    if not isinstance(value, str):
        return None, f"{field_name} must be a string"

    value = value.strip()

    if not value:
        return None, f"{field_name} cannot be empty"

    if len(value) > max_length:
        return None, f"{field_name} is too long"

    return value, None


def clean_email(value):

    value, error = clean_string(
        value,
        "email",
        255
    )

    if error:
        return None, error

    if not EMAIL_RE.match(value):
        return None, "email is not a valid email address"

    return value.lower(), None


def clean_phone(value):

    value, error = clean_string(
        value,
        "phone",
        30
    )

    if error:
        return None, error

    if not PHONE_RE.match(value):
        return None, "phone is not a valid phone number"

    return value, None


def validate_money(
    value,
    field_name,
    allow_zero=True
):

    if isinstance(value, bool):
        return None, f"{field_name} must be a number"

    try:
        amount = Decimal(str(value))

    except (InvalidOperation, ValueError, TypeError):
        return None, f"{field_name} must be a number"

    if not amount.is_finite():
        return None, f"{field_name} must be a finite number"

    if allow_zero:

        if amount < 0:
            return None, f"{field_name} cannot be negative"

    else:

        if amount <= 0:
            return None, (
                f"{field_name} must be greater than 0"
            )

    if amount > MONEY_MAX:
        return None, f"{field_name} is too large"

    if amount.as_tuple().exponent < -2:
        return None, (
            f"{field_name} can have at most 2 decimal places"
        )

    return amount.quantize(
        Decimal("0.01")
    ), None


def validate_positive_integer(value, field_name):

    if isinstance(value, bool):
        return None, f"{field_name} must be an integer"

    if isinstance(value, float):

        if not value.is_integer():
            return None, (
                f"{field_name} must be an integer"
            )

        value = int(value)

    if not isinstance(value, int):
        return None, (
            f"{field_name} must be an integer"
        )

    if value <= 0:
        return None, (
            f"{field_name} must be greater than 0"
        )

    return value, None


def validate_age(value):

    if isinstance(value, bool):
        return None, "Age must be an integer"

    if isinstance(value, float):

        if not value.is_integer():
            return None, "Age must be an integer"

        value = int(value)

    if not isinstance(value, int):
        return None, "Age must be an integer"

    if value < 18:
        return None, "User must be 18 or older"

    if value > 120:
        return None, "Invalid age"

    return value, None


def validate_user_data(data):

    if not isinstance(data, dict):
        return None, {
            "error": "Invalid JSON"
        }, 400

    required_fields = [
        "first_name",
        "last_name",
        "email",
        "phone",
        "age",
        "password",
    ]

    for field in required_fields:

        if field not in data:
            return None, {
                "error": f"{field} is required"
            }, 400

    first_name, error = clean_string(
        data["first_name"],
        "first_name",
        100
    )

    if error:
        return None, {
            "error": error
        }, 400

    last_name, error = clean_string(
        data["last_name"],
        "last_name",
        100
    )

    if error:
        return None, {
            "error": error
        }, 400

    email, error = clean_email(
        data["email"]
    )

    if error:
        return None, {
            "error": error
        }, 400

    phone, error = clean_phone(
        data["phone"]
    )

    if error:
        return None, {
            "error": error
        }, 400

    password, error = clean_string(
        data["password"],
        "password",
        255
    )

    if error:
        return None, {
            "error": error
        }, 400

    if len(password) < 6:
        return None, {
            "error": "Password must be at least 6 characters"
        }, 400

    age, error = validate_age(
        data["age"]
    )

    if error:
        return None, {
            "error": error
        }, 400

    return {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "phone": phone,
        "age": age,
        "password": password,
    }, None, None


def parse_pagination(
    default_limit=20,
    max_limit=100
):

    page_raw = request.args.get(
        "page",
        "1"
    )

    limit_raw = request.args.get(
        "limit",
        str(default_limit)
    )

    try:
        page = int(page_raw)

    except (TypeError, ValueError):
        raise ValueError(
            "page must be a positive integer"
        )

    try:
        limit = int(limit_raw)

    except (TypeError, ValueError):
        raise ValueError(
            "limit must be a positive integer"
        )

    if page <= 0:
        raise ValueError(
            "page must be greater than 0"
        )

    if limit <= 0:
        raise ValueError(
            "limit must be greater than 0"
        )

    if limit > max_limit:
        raise ValueError(
            f"limit cannot be greater than {max_limit}"
        )

    offset = (
        page - 1
    ) * limit

    return page, limit, offset


# =========================================================
# JWT
# =========================================================

def _is_token_revoked(cursor, jti):

    if not jti:
        return False

    try:

        cursor.execute(
            """
            SELECT jti
            FROM revoked_tokens
            WHERE jti = %s
            """,
            (jti,)
        )

        return cursor.fetchone() is not None

    except mysql.connector.Error as e:

        logger.error(
            "Could not check token revocation: %s",
            e
        )

        # Fail closed.
        raise


def verify_token():

    auth_header = request.headers.get(
        "Authorization"
    )

    if not auth_header:
        return None

    if not auth_header.startswith(
        "Bearer "
    ):
        return None

    token = auth_header.split(
        " ",
        1
    )[1].strip()

    if not token:
        return None

    try:

        decoded_token = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
        )

    except jwt.ExpiredSignatureError:
        return None

    except jwt.InvalidTokenError:
        return None

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        if _is_token_revoked(
            cursor,
            decoded_token.get("jti")
        ):
            return None

        cursor.execute(
            """
            SELECT
                user_id,
                role,
                account_status
            FROM users
            WHERE user_id = %s
            """,
            (
                decoded_token.get("user_id"),
            )
        )

        user = cursor.fetchone()

        if not user:
            return None

        if user["account_status"] != "active":
            return None

        # Always trust the database role.
        decoded_token["role"] = user["role"]

        return decoded_token

    except mysql.connector.Error as e:

        logger.error(
            "verify_token DB error: %s",
            e
        )

        return None

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


def require_auth(f):

    @wraps(f)
    def wrapped(*args, **kwargs):

        user = verify_token()

        if not user:
            return err(
                "Unauthorized",
                401
            )

        g.current_user = user

        return f(
            user,
            *args,
            **kwargs
        )

    return wrapped


def require_staff(f):

    @wraps(f)
    def wrapped(*args, **kwargs):

        user = verify_token()

        if not user:
            return err(
                "Unauthorized",
                401
            )

        if not is_staff(user):
            return err(
                "Staff access required",
                403
            )

        g.current_user = user

        return f(
            user,
            *args,
            **kwargs
        )

    return wrapped


def require_admin(f):

    @wraps(f)
    def wrapped(*args, **kwargs):

        user = verify_token()

        if not user:
            return err(
                "Unauthorized",
                401
            )

        if not is_admin(user):
            return err(
                "Admin access required",
                403
            )

        g.current_user = user

        return f(
            user,
            *args,
            **kwargs
        )

    return wrapped


# =========================================================
# ROLE HELPERS
# =========================================================

def is_staff(user):

    return bool(user) and user.get(
        "role"
    ) in [
        "librarian",
        "admin"
    ]


def is_admin(user):

    return bool(user) and user.get(
        "role"
    ) == "admin"


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(404)
def _not_found(e):
    return err(
        "Not found",
        404
    )


@app.errorhandler(405)
def _method_not_allowed(e):
    return err(
        "Method not allowed",
        405
    )


@app.errorhandler(500)
def _internal_error(e):

    logger.exception(
        "Unhandled exception"
    )

    return err(
        "Internal server error",
        500
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return jsonify({
        "message":
            "Library Management API is running"
    })


# =========================================================
# HEALTH
# =========================================================

@app.route("/health")
def health():

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor()

        cursor.execute(
            "SELECT 1"
        )

        cursor.fetchone()

        return jsonify({
            "status": "ok"
        }), 200

    except mysql.connector.Error as e:

        logger.error(
            "Health check failed: %s",
            e
        )

        return jsonify({
            "status": "error"
        }), 503

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# REGISTER
# =========================================================

@app.route(
    "/register",
    methods=["POST"]
)
@limiter.limit("10 per minute")
def register():

    data = request.get_json(
        silent=True
    )

    user_data, error_response, error_code = (
        validate_user_data(data)
    )

    if error_response:
        return jsonify(
            error_response
        ), error_code

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT user_id
            FROM users
            WHERE email = %s
               OR phone = %s
            """,
            (
                user_data["email"],
                user_data["phone"],
            )
        )

        if cursor.fetchone():
            return err(
                "Email or phone already exists",
                409
            )

        salt = secrets_module.token_hex(
            16
        )

        password_hash = hash_password(
            user_data["password"],
            salt
        )

        cursor.execute(
            """
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
            VALUES
                (
                    %s,%s,%s,%s,%s,%s,%s,'user'
                )
            """,
            (
                user_data["first_name"],
                user_data["last_name"],
                user_data["email"],
                user_data["phone"],
                user_data["age"],
                password_hash,
                salt,
            )
        )

        db.commit()

        return jsonify({
            "message":
                "User registered successfully",
            "user_id":
                cursor.lastrowid,
        }), 201

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Email or phone already exists",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "register DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# LOGIN HELPER
# =========================================================

def _perform_login(data, expected_role=None):

    if not isinstance(data, dict):
        return err("Invalid JSON", 400)

    if "email" not in data or "password" not in data:
        return err("Email and password are required", 400)

    email, error = clean_email(data["email"])
    if error:
        return err(error, 400)

    password, error = clean_string(data["password"], "password", 255)
    if error:
        return err(error, 400)

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True, buffered=True)

        cursor.execute(
            """
            SELECT
                user_id,
                email,
                password_hash,
                salt,
                role,
                account_status
            FROM users
            WHERE email = %s
            """,
            (email,)
        )

        user = cursor.fetchone()

        if not user:
            return err("Invalid email or password", 401)

        if user["account_status"] == "blocked":
            return err("Account is blocked", 403)

        if expected_role is not None and user["role"] != expected_role:
            return err(
                f"This login is only for {expected_role} accounts",
                403
            )

        password_hash = hash_password(password, user["salt"])

        if not hmac.compare_digest(password_hash, user["password_hash"]):
            return err("Invalid email or password", 401)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=JWT_LIFETIME_MINUTES)
        jti = secrets_module.token_hex(16)

        payload = {
            "user_id": user["user_id"],
            "role": user["role"],
            "jti": jti,
            "iat": now,
            "exp": expires_at,
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
            "role": user["role"],
            "expires_at": expires_at.isoformat(),
        })

    except mysql.connector.Error as e:
        logger.error("login DB error: %s", e)
        return err("Database error", 500)

    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


# =========================================================
# USER LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["POST"]
)
@limiter.limit("5 per minute")
def login():
    return _perform_login(
        request.get_json(silent=True),
        expected_role="user"
    )


# =========================================================
# LIBRARIAN LOGIN
# =========================================================

@app.route(
    "/librarian/login",
    methods=["POST"]
)
@limiter.limit("5 per minute")
def librarian_login():
    return _perform_login(
        request.get_json(silent=True),
        expected_role="librarian"
    )


# =========================================================
# ADMIN LOGIN
# =========================================================

@app.route(
    "/admin/login",
    methods=["POST"]
)
@limiter.limit("5 per minute")
def admin_login():
    return _perform_login(
        request.get_json(silent=True),
        expected_role="admin"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route(
    "/logout",
    methods=["POST"]
)
def logout():

    auth_header = request.headers.get(
        "Authorization"
    )

    if (
        not auth_header
        or not auth_header.startswith("Bearer ")
    ):
        return err(
            "Unauthorized",
            401
        )

    token = auth_header.split(
        " ",
        1
    )[1].strip()

    try:

        decoded = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
            options={
                "verify_exp": False
            }
        )

    except jwt.InvalidTokenError:
        return err(
            "Invalid token",
            401
        )

    jti = decoded.get("jti")
    user_id = decoded.get("user_id")
    exp = decoded.get("exp")

    if not jti or not user_id or not exp:
        return err(
            "Token does not support revocation",
            400
        )

    expires_at = datetime.fromtimestamp(
        exp,
        tz=timezone.utc
    )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor()

        cursor.execute(
            """
            INSERT INTO revoked_tokens
                (
                    jti,
                    user_id,
                    revoked_at,
                    expires_at
                )
            VALUES
                (%s,%s,NOW(),%s)
            ON DUPLICATE KEY UPDATE
                revoked_at = NOW()
            """,
            (
                jti,
                user_id,
                expires_at,
            )
        )

        db.commit()

        return jsonify({
            "message":
                "Logged out successfully"
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "logout DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# PROFILE
# =========================================================

@app.route(
    "/profile",
    methods=["GET"]
)
@require_auth
def profile(user):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
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
            """,
            (user["user_id"],)
        )

        result = cursor.fetchone()

        if not result:
            return err(
                "User not found",
                404
            )

        return jsonify(result)

    except mysql.connector.Error as e:

        logger.error(
            "profile DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# USERS
# =========================================================

@app.route(
    "/users",
    methods=["GET"]
)
@require_staff
def users(staff):

    try:
        page, limit, offset = parse_pagination()

    except ValueError as e:
        return err(
            str(e),
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        if staff["role"] == "librarian":

            count_query = """
                SELECT COUNT(*) AS total
                FROM users
                WHERE role = 'user'
            """

            list_query = """
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
                WHERE role = 'user'
                ORDER BY user_id
                LIMIT %s OFFSET %s
            """

            cursor.execute(count_query)

            total = cursor.fetchone()["total"]

            cursor.execute(
                list_query,
                (limit, offset)
            )

        else:

            cursor.execute(
                "SELECT COUNT(*) AS total FROM users"
            )

            total = cursor.fetchone()["total"]

            cursor.execute(
                """
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
                LIMIT %s OFFSET %s
                """,
                (limit, offset)
            )

        return jsonify({
            "page": page,
            "limit": limit,
            "total": total,
            "users": cursor.fetchall(),
        })

    except mysql.connector.Error as e:

        logger.error(
            "users DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# STAFF CREATE USER
# =========================================================

@app.route(
    "/librarian/users",
    methods=["POST"]
)
@require_staff
def librarian_create_user(staff):

    data = request.get_json(
        silent=True
    )

    user_data, error_response, error_code = (
        validate_user_data(data)
    )

    if error_response:
        return jsonify(
            error_response
        ), error_code

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT user_id
            FROM users
            WHERE email = %s
               OR phone = %s
            """,
            (
                user_data["email"],
                user_data["phone"],
            )
        )

        if cursor.fetchone():
            return err(
                "Email or phone already exists",
                409
            )

        salt = secrets_module.token_hex(
            16
        )

        password_hash = hash_password(
            user_data["password"],
            salt
        )

        cursor.execute(
            """
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
            VALUES
                (
                    %s,%s,%s,%s,%s,%s,%s,'user'
                )
            """,
            (
                user_data["first_name"],
                user_data["last_name"],
                user_data["email"],
                user_data["phone"],
                user_data["age"],
                password_hash,
                salt,
            )
        )

        db.commit()

        return jsonify({
            "message":
                "User created successfully",
            "user_id":
                cursor.lastrowid,
        }), 201

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Email or phone already exists",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "librarian_create_user DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# BLOCK / UNBLOCK USER
# =========================================================

@app.route(
    "/librarian/users/<int:user_id>/block",
    methods=["PATCH"]
)
@require_staff
def block_user(staff, user_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                user_id,
                role,
                account_status
            FROM users
            WHERE user_id = %s
            FOR UPDATE
            """,
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            return err(
                "User not found",
                404
            )

        if target["user_id"] == staff["user_id"]:
            return err(
                "You cannot block yourself",
                400
            )

        if (
            staff["role"] == "librarian"
            and target["role"] != "user"
        ):
            return err(
                "Librarian can only block normal users",
                403
            )

        if target["role"] == "admin":
            return err(
                "Admins cannot be blocked through this endpoint",
                403
            )

        new_status = (
            "blocked"
            if target["account_status"] == "active"
            else "active"
        )

        cursor.execute(
            """
            UPDATE users
            SET account_status = %s
            WHERE user_id = %s
            """,
            (
                new_status,
                user_id,
            )
        )

        db.commit()

        return jsonify({
            "message":
                f"User is now {new_status}",
            "user_id":
                user_id,
            "account_status":
                new_status,
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "block_user DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# DELETE USER
# =========================================================

@app.route(
    "/librarian/users/<int:user_id>",
    methods=["DELETE"]
)
@require_staff
def delete_user(staff, user_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT user_id, role
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            return err(
                "User not found",
                404
            )

        if target["user_id"] == staff["user_id"]:
            return err(
                "You cannot delete yourself",
                400
            )

        if (
            staff["role"] == "librarian"
            and target["role"] != "user"
        ):
            return err(
                "Librarian can only delete normal users",
                403
            )

        if target["role"] == "admin":
            return err(
                "Admins cannot be deleted through this endpoint",
                403
            )

        cursor.execute(
            """
            DELETE FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )

        db.commit()

        return jsonify({
            "message":
                "User deleted successfully",
            "user_id":
                user_id,
        })

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "User cannot be deleted because related records exist",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "delete_user DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# ADMIN - CREATE LIBRARIAN
# =========================================================

@app.route(
    "/admin/librarians",
    methods=["POST"]
)
@require_admin
def create_librarian(admin):

    data = request.get_json(
        silent=True
    )

    user_data, error_response, error_code = (
        validate_user_data(data)
    )

    if error_response:
        return jsonify(
            error_response
        ), error_code

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT user_id
            FROM users
            WHERE email = %s
               OR phone = %s
            """,
            (
                user_data["email"],
                user_data["phone"],
            )
        )

        if cursor.fetchone():
            return err(
                "Email or phone already exists",
                409
            )

        salt = secrets_module.token_hex(
            16
        )

        password_hash = hash_password(
            user_data["password"],
            salt
        )

        cursor.execute(
            """
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
            VALUES
                (
                    %s,%s,%s,%s,%s,%s,%s,'librarian'
                )
            """,
            (
                user_data["first_name"],
                user_data["last_name"],
                user_data["email"],
                user_data["phone"],
                user_data["age"],
                password_hash,
                salt,
            )
        )

        db.commit()

        return jsonify({
            "message":
                "Librarian created successfully",
            "librarian_id":
                cursor.lastrowid,
        }), 201

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Email or phone already exists",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "create_librarian DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# ADMIN - LIST LIBRARIANS
# =========================================================

@app.route(
    "/admin/librarians",
    methods=["GET"]
)
@require_admin
def list_librarians(admin):

    try:
        page, limit, offset = parse_pagination()

    except ValueError as e:
        return err(
            str(e),
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM users
            WHERE role = 'librarian'
            """
        )

        total = cursor.fetchone()["total"]

        cursor.execute(
            """
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
            LIMIT %s OFFSET %s
            """,
            (limit, offset)
        )

        return jsonify({
            "page": page,
            "limit": limit,
            "total": total,
            "librarians": cursor.fetchall(),
        })

    except mysql.connector.Error as e:

        logger.error(
            "list_librarians DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# ADMIN - BLOCK LIBRARIAN
# =========================================================

@app.route(
    "/admin/librarians/<int:user_id>/block",
    methods=["PATCH"]
)
@require_admin
def block_librarian(admin, user_id):

    if user_id == admin["user_id"]:
        return err(
            "You cannot block yourself",
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                user_id,
                role,
                account_status
            FROM users
            WHERE user_id = %s
            FOR UPDATE
            """,
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            return err(
                "User not found",
                404
            )

        if target["role"] != "librarian":
            return err(
                "Target is not a librarian",
                400
            )

        new_status = (
            "blocked"
            if target["account_status"] == "active"
            else "active"
        )

        cursor.execute(
            """
            UPDATE users
            SET account_status = %s
            WHERE user_id = %s
            """,
            (
                new_status,
                user_id,
            )
        )

        db.commit()

        return jsonify({
            "message":
                f"Librarian is now {new_status}",
            "user_id":
                user_id,
            "account_status":
                new_status,
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "block_librarian DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# ADMIN - DELETE LIBRARIAN
# =========================================================

@app.route(
    "/admin/librarians/<int:user_id>",
    methods=["DELETE"]
)
@require_admin
def delete_librarian(admin, user_id):

    if user_id == admin["user_id"]:
        return err(
            "You cannot delete yourself",
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT user_id, role
            FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )

        target = cursor.fetchone()

        if not target:
            return err(
                "Librarian not found",
                404
            )

        if target["role"] != "librarian":
            return err(
                "Target is not a librarian",
                400
            )

        cursor.execute(
            """
            DELETE FROM users
            WHERE user_id = %s
            """,
            (user_id,)
        )

        db.commit()

        return jsonify({
            "message":
                "Librarian deleted successfully",
            "user_id":
                user_id,
        })

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Librarian cannot be deleted because related records exist",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "delete_librarian DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# ADMIN - USER TRANSACTION HISTORY
# =========================================================

@app.route(
    "/admin/users/<int:user_id>/transactions",
    methods=["GET"]
)
@require_admin
def admin_user_transactions(admin, user_id):

    try:
        page, limit, offset = parse_pagination()
    except ValueError as e:
        return err(str(e), 400)

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True, buffered=True)

        cursor.execute(
            "SELECT user_id, first_name, last_name, email, role, account_status "
            "FROM users WHERE user_id = %s",
            (user_id,)
        )
        target = cursor.fetchone()

        if not target:
            return err("User not found", 404)

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM (
                SELECT borrowing_id AS transaction_id
                FROM borrowings
                WHERE user_id = %s
                UNION ALL
                SELECT loan_id AS transaction_id
                FROM loans
                WHERE user_id = %s
            ) AS t
            """,
            (user_id, user_id)
        )
        total = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT *
            FROM (
                SELECT
                    'borrowing' AS transaction_type,
                    br.borrowing_id AS transaction_id,
                    br.user_id,
                    br.copy_id,
                    bc.book_id,
                    b.title,
                    br.borrow_time,
                    br.due_date,
                    br.return_time,
                    br.status
                FROM borrowings br
                JOIN book_copies bc ON br.copy_id = bc.copy_id
                JOIN books b ON bc.book_id = b.book_id
                WHERE br.user_id = %s

                UNION ALL

                SELECT
                    'loan' AS transaction_type,
                    l.loan_id AS transaction_id,
                    l.user_id,
                    l.copy_id,
                    bc.book_id,
                    b.title,
                    l.borrow_time,
                    l.due_date,
                    l.return_time,
                    l.status
                FROM loans l
                JOIN book_copies bc ON l.copy_id = bc.copy_id
                JOIN books b ON bc.book_id = b.book_id
                WHERE l.user_id = %s
            ) AS transactions
            ORDER BY borrow_time DESC, transaction_id DESC
            LIMIT %s OFFSET %s
            """,
            (user_id, user_id, limit, offset)
        )

        return jsonify({
            "user": target,
            "page": page,
            "limit": limit,
            "total": total,
            "transactions": cursor.fetchall(),
        })

    except mysql.connector.Error as e:
        logger.error("admin_user_transactions DB error: %s", e)
        return err("Database error", 500)
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


# =========================================================
# ADMIN - USER LOAN HISTORY
# =========================================================

@app.route(
    "/admin/users/<int:user_id>/loans",
    methods=["GET"]
)
@require_admin
def admin_user_loans(admin, user_id):

    try:
        page, limit, offset = parse_pagination()
    except ValueError as e:
        return err(str(e), 400)

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True, buffered=True)

        cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        if not cursor.fetchone():
            return err("User not found", 404)

        cursor.execute("SELECT COUNT(*) AS total FROM loans WHERE user_id = %s", (user_id,))
        total = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT
                l.loan_id,
                l.user_id,
                l.copy_id,
                bc.book_id,
                b.title,
                l.borrow_time,
                l.due_date,
                l.return_time,
                l.status
            FROM loans l
            JOIN book_copies bc ON l.copy_id = bc.copy_id
            JOIN books b ON bc.book_id = b.book_id
            WHERE l.user_id = %s
            ORDER BY l.borrow_time DESC, l.loan_id DESC
            LIMIT %s OFFSET %s
            """,
            (user_id, limit, offset)
        )

        return jsonify({
            "page": page,
            "limit": limit,
            "total": total,
            "loans": cursor.fetchall(),
        })

    except mysql.connector.Error as e:
        logger.error("admin_user_loans DB error: %s", e)
        return err("Database error", 500)
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


# =========================================================
# ADMIN - USER RESERVATIONS
# =========================================================

@app.route(
    "/admin/users/<int:user_id>/reservations",
    methods=["GET"]
)
@require_admin
def admin_user_reservations(admin, user_id):

    try:
        page, limit, offset = parse_pagination()
    except ValueError as e:
        return err(str(e), 400)

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True, buffered=True)

        cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        if not cursor.fetchone():
            return err("User not found", 404)

        cursor.execute("SELECT COUNT(*) AS total FROM reservations WHERE user_id = %s", (user_id,))
        total = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT
                r.reservation_id,
                r.user_id,
                r.book_id,
                b.title,
                r.reservation_time,
                r.status
            FROM reservations r
            JOIN books b ON r.book_id = b.book_id
            WHERE r.user_id = %s
            ORDER BY r.reservation_time DESC, r.reservation_id DESC
            LIMIT %s OFFSET %s
            """,
            (user_id, limit, offset)
        )

        return jsonify({
            "page": page,
            "limit": limit,
            "total": total,
            "reservations": cursor.fetchall(),
        })

    except mysql.connector.Error as e:
        logger.error("admin_user_reservations DB error: %s", e)
        return err("Database error", 500)
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


# =========================================================
# ADMIN - USER FINES
# =========================================================

@app.route(
    "/admin/users/<int:user_id>/fines",
    methods=["GET"]
)
@require_admin
def admin_user_fines(admin, user_id):

    try:
        page, limit, offset = parse_pagination()
    except ValueError as e:
        return err(str(e), 400)

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True, buffered=True)

        cursor.execute("SELECT user_id FROM users WHERE user_id = %s", (user_id,))
        if not cursor.fetchone():
            return err("User not found", 404)

        cursor.execute("SELECT COUNT(*) AS total FROM fines WHERE user_id = %s", (user_id,))
        total = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT
                fine_id,
                user_id,
                borrowing_id,
                loan_id,
                fine_amount,
                reason,
                created_at,
                paid_at,
                status
            FROM fines
            WHERE user_id = %s
            ORDER BY created_at DESC, fine_id DESC
            LIMIT %s OFFSET %s
            """,
            (user_id, limit, offset)
        )

        return jsonify({
            "page": page,
            "limit": limit,
            "total": total,
            "fines": cursor.fetchall(),
        })

    except mysql.connector.Error as e:
        logger.error("admin_user_fines DB error: %s", e)
        return err("Database error", 500)
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


# =========================================================
# ADMIN - ALL LOANS
# =========================================================

@app.route(
    "/admin/loans",
    methods=["GET"]
)
@require_admin
def admin_all_loans(admin):

    try:
        page, limit, offset = parse_pagination()
    except ValueError as e:
        return err(str(e), 400)

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True, buffered=True)

        cursor.execute("SELECT COUNT(*) AS total FROM loans")
        total = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT
                l.loan_id,
                l.user_id,
                CONCAT(u.first_name, ' ', u.last_name) AS user_name,
                l.copy_id,
                bc.book_id,
                b.title,
                l.borrow_time,
                l.due_date,
                l.return_time,
                l.status
            FROM loans l
            JOIN users u ON l.user_id = u.user_id
            JOIN book_copies bc ON l.copy_id = bc.copy_id
            JOIN books b ON bc.book_id = b.book_id
            ORDER BY l.borrow_time DESC, l.loan_id DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset)
        )

        return jsonify({
            "page": page,
            "limit": limit,
            "total": total,
            "loans": cursor.fetchall(),
        })

    except mysql.connector.Error as e:
        logger.error("admin_all_loans DB error: %s", e)
        return err("Database error", 500)
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


# =========================================================
# ADMIN - ALL TRANSACTIONS
# =========================================================

@app.route(
    "/admin/transactions",
    methods=["GET"]
)
@require_admin
def admin_all_transactions(admin):

    try:
        page, limit, offset = parse_pagination()
    except ValueError as e:
        return err(str(e), 400)

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True, buffered=True)

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM (
                SELECT borrowing_id AS transaction_id FROM borrowings
                UNION ALL
                SELECT loan_id AS transaction_id FROM loans
            ) AS t
            """
        )
        total = cursor.fetchone()["total"]

        cursor.execute(
            """
            SELECT *
            FROM (
                SELECT
                    'borrowing' AS transaction_type,
                    br.borrowing_id AS transaction_id,
                    br.user_id,
                    CONCAT(u.first_name, ' ', u.last_name) AS user_name,
                    br.copy_id,
                    bc.book_id,
                    b.title,
                    br.borrow_time,
                    br.due_date,
                    br.return_time,
                    br.status
                FROM borrowings br
                JOIN users u ON br.user_id = u.user_id
                JOIN book_copies bc ON br.copy_id = bc.copy_id
                JOIN books b ON bc.book_id = b.book_id

                UNION ALL

                SELECT
                    'loan' AS transaction_type,
                    l.loan_id AS transaction_id,
                    l.user_id,
                    CONCAT(u.first_name, ' ', u.last_name) AS user_name,
                    l.copy_id,
                    bc.book_id,
                    b.title,
                    l.borrow_time,
                    l.due_date,
                    l.return_time,
                    l.status
                FROM loans l
                JOIN users u ON l.user_id = u.user_id
                JOIN book_copies bc ON l.copy_id = bc.copy_id
                JOIN books b ON bc.book_id = b.book_id
            ) AS transactions
            ORDER BY borrow_time DESC, transaction_id DESC
            LIMIT %s OFFSET %s
            """,
            (limit, offset)
        )

        return jsonify({
            "page": page,
            "limit": limit,
            "total": total,
            "transactions": cursor.fetchall(),
        })

    except mysql.connector.Error as e:
        logger.error("admin_all_transactions DB error: %s", e)
        return err("Database error", 500)
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


# =========================================================
# ADMIN - DASHBOARD SUMMARY
# =========================================================

@app.route(
    "/admin/dashboard",
    methods=["GET"]
)
@require_admin
def admin_dashboard(admin):

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True, buffered=True)

        queries = {
            "users": "SELECT COUNT(*) AS total FROM users WHERE role = 'user'",
            "librarians": "SELECT COUNT(*) AS total FROM users WHERE role = 'librarian'",
            "admins": "SELECT COUNT(*) AS total FROM users WHERE role = 'admin'",
            "books": "SELECT COUNT(*) AS total FROM books",
            "copies": "SELECT COUNT(*) AS total FROM book_copies",
            "available_copies": "SELECT COUNT(*) AS total FROM book_copies WHERE status = 'available'",
            "borrowed_copies": "SELECT COUNT(*) AS total FROM book_copies WHERE status = 'borrowed'",
            "maintenance_copies": "SELECT COUNT(*) AS total FROM book_copies WHERE status = 'maintenance'",
            "damaged_copies": "SELECT COUNT(*) AS total FROM book_copies WHERE status = 'damaged'",
            "lost_copies": "SELECT COUNT(*) AS total FROM book_copies WHERE status = 'lost'",
            "active_borrowings": "SELECT COUNT(*) AS total FROM borrowings WHERE status IN ('active','overdue')",
            "active_loans": "SELECT COUNT(*) AS total FROM loans WHERE status IN ('active','overdue')",
            "reservations": "SELECT COUNT(*) AS total FROM reservations",
            "waiting_reservations": "SELECT COUNT(*) AS total FROM reservations WHERE status = 'waiting'",
            "unpaid_fines": "SELECT COUNT(*) AS total FROM fines WHERE status = 'unpaid'",
            "total_fine_amount": "SELECT COALESCE(SUM(fine_amount), 0) AS total FROM fines",
        }

        summary = {}
        for key, query in queries.items():
            cursor.execute(query)
            summary[key] = cursor.fetchone()["total"]

        return jsonify({
            "message": "Admin dashboard",
            "admin_id": admin["user_id"],
            "summary": summary,
        })

    except mysql.connector.Error as e:
        logger.error("admin_dashboard DB error: %s", e)
        return err("Database error", 500)
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()


# =========================================================
# BOOK SEARCH
# =========================================================

@app.route(
    "/books",
    methods=["GET"]
)
@require_auth
def books(user):

    title = request.args.get(
        "title"
    )

    author = request.args.get(
        "author"
    )

    category = request.args.get(
        "category"
    )

    available = request.args.get(
        "available"
    )

    try:
        page, limit, offset = parse_pagination(
            default_limit=10
        )

    except ValueError as e:
        return err(
            str(e),
            400
        )

    sort = request.args.get(
        "sort",
        "book_id"
    )

    allowed_sort = {
        "book_id": "b.book_id",
        "title": "b.title",
        "author": "a.author_name",
        "category": "c.category_name",
        "total_copies": "total_copies",
        "available_copies": "available_copies",
    }

    if sort not in allowed_sort:
        return err(
            "Invalid sort field",
            400
        )

    conditions = []
    params = []

    title = title.strip() if title else None
    author = author.strip() if author else None
    category = category.strip() if category else None

    if title:

        if len(title) > 200:
            return err(
                "title search is too long",
                400
            )

        conditions.append(
            "b.title LIKE %s"
        )

        params.append(
            f"%{title}%"
        )

    if author:

        if len(author) > 200:
            return err(
                "author search is too long",
                400
            )

        conditions.append(
            "a.author_name LIKE %s"
        )

        params.append(
            f"%{author}%"
        )

    if category:

        if len(category) > 200:
            return err(
                "category search is too long",
                400
            )

        conditions.append(
            "c.category_name LIKE %s"
        )

        params.append(
            f"%{category}%"
        )

    where_clause = (
        "WHERE "
        + " AND ".join(conditions)
        if conditions
        else ""
    )

    if available == "true":
        having_clause = (
            "HAVING available_copies > 0"
        )

    elif available == "false":
        having_clause = (
            "HAVING available_copies = 0"
        )

    elif available is not None:
        return err(
            "available must be true or false",
            400
        )

    else:
        having_clause = ""

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        query = f"""
            SELECT
                b.book_id,
                b.title,
                a.author_name AS author,
                c.category_name AS category,

                COUNT(bc.copy_id)
                    AS total_copies,

                COALESCE(
                    SUM(
                        CASE
                            WHEN bc.status = 'available'
                             AND bc.book_condition = 'good'
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS available_copies,

                COUNT(*) OVER()
                    AS grand_total

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

            ORDER BY
                {allowed_sort[sort]},
                b.book_id

            LIMIT %s OFFSET %s
        """

        cursor.execute(
            query,
            params + [limit, offset]
        )

        rows = cursor.fetchall()

        total = (
            rows[0]["grand_total"]
            if rows
            else 0
        )

        for row in rows:
            row.pop(
                "grand_total",
                None
            )

        return jsonify({
            "page": page,
            "limit": limit,
            "total": total,
            "books": rows,
        })

    except mysql.connector.Error as e:

        logger.error(
            "books search DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# GET SINGLE BOOK
# =========================================================

@app.route(
    "/books/<int:book_id>",
    methods=["GET"]
)
@require_auth
def get_book(user, book_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                b.book_id,
                b.title,
                a.author_name AS author,
                c.category_name AS category,
                b.borrowing_price,
                b.loan_price,
                b.fine_per_day,

                COUNT(bc.copy_id)
                    AS total_copies,

                COALESCE(
                    SUM(
                        CASE
                            WHEN bc.status = 'available'
                             AND bc.book_condition = 'good'
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

            WHERE b.book_id = %s

            GROUP BY
                b.book_id,
                b.title,
                a.author_name,
                c.category_name,
                b.borrowing_price,
                b.loan_price,
                b.fine_per_day
            """,
            (book_id,)
        )

        result = cursor.fetchone()

        if not result:
            return err(
                "Book not found",
                404
            )

        return jsonify(result)

    except mysql.connector.Error as e:

        logger.error(
            "get_book DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()
@app.route("/books", methods=["GET"])
def get_books():

    conn = None
    cursor = None

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        # -----------------------------
        # GET FILTER VALUES
        # -----------------------------

        book_id = request.args.get("id")
        title = request.args.get("title")
        author = request.args.get("author")
        category = request.args.get("category")

        # -----------------------------
        # BASE QUERY
        # -----------------------------

        query = """
            SELECT
                b.book_id,
                b.title,
                b.author_id,
                a.author_name,
                b.category_id,
                c.category_name,
                b.borrowing_price,
                b.loan_price,
                b.fine_per_day
            FROM books b
            LEFT JOIN authors a
                ON b.author_id = a.author_id
            LEFT JOIN categories c
                ON b.category_id = c.category_id
            WHERE 1=1
        """

        params = []

        # -----------------------------
        # FILTER BY BOOK ID
        # -----------------------------

        if book_id:

            try:
                book_id = int(book_id)
            except ValueError:
                return err("id must be an integer", 400)

            query += " AND b.book_id = %s"
            params.append(book_id)

        # -----------------------------
        # FILTER BY TITLE
        # -----------------------------

        if title:

            query += " AND b.title LIKE %s"
            params.append(f"%{title}%")

        # -----------------------------
        # FILTER BY AUTHOR
        # -----------------------------

        if author:

            query += " AND a.author_name LIKE %s"
            params.append(f"%{author}%")

        # -----------------------------
        # FILTER BY CATEGORY
        # -----------------------------

        if category:

            query += " AND c.category_name LIKE %s"
            params.append(f"%{category}%")

        # -----------------------------
        # DEFAULT SORT
        # -----------------------------

        query += " ORDER BY b.book_id ASC"

        cursor.execute(query, tuple(params))

        books = cursor.fetchall()

        return jsonify({
            "books": books,
            "count": len(books)
        }), 200

    except Exception as e:

        return err(str(e), 500)

    finally:

        if cursor:
            cursor.close()

        if conn:
            conn.close()

# =========================================================
# AUTHOR CRUD
# =========================================================

@app.route(
    "/authors",
    methods=["POST"]
)
@require_staff
def create_author(staff):

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return err(
            "Invalid JSON",
            400
        )

    author_name, error = clean_string(
        data.get("author_name"),
        "author_name",
        200
    )

    if error:
        return err(
            error,
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            INSERT INTO authors
                (author_name)
            VALUES
                (%s)
            """,
            (author_name,)
        )

        db.commit()

        return jsonify({
            "message":
                "Author created successfully",
            "author_id":
                cursor.lastrowid,
        }), 201

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Author already exists",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "create_author DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


@app.route(
    "/authors",
    methods=["GET"]
)
@require_staff
def list_authors(staff):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                author_id,
                author_name
            FROM authors
            ORDER BY author_name ASC
            """
        )

        authors = cursor.fetchall()

        return jsonify({
            "authors": authors,
            "count": len(authors),
        }), 200

    except mysql.connector.Error as e:

        logger.error(
            "list_authors DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


@app.route(
    "/authors/<int:author_id>",
    methods=["GET"]
)
@require_staff
def get_author(staff, author_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                author_id,
                author_name
            FROM authors
            WHERE author_id = %s
            """,
            (author_id,)
        )

        author = cursor.fetchone()

        if not author:
            return err(
                "Author not found",
                404
            )

        return jsonify(author), 200

    except mysql.connector.Error as e:

        logger.error(
            "get_author DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


@app.route(
    "/authors/<int:author_id>",
    methods=["PATCH"]
)
@require_staff
def update_author(staff, author_id):

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return err(
            "Invalid JSON",
            400
        )

    if "author_name" not in data:
        return err(
            "author_name is required",
            400
        )

    author_name, error = clean_string(
        data["author_name"],
        "author_name",
        200
    )

    if error:
        return err(
            error,
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT author_id
            FROM authors
            WHERE author_id = %s
            FOR UPDATE
            """,
            (author_id,)
        )

        if not cursor.fetchone():
            return err(
                "Author not found",
                404
            )

        cursor.execute(
            """
            UPDATE authors
            SET author_name = %s
            WHERE author_id = %s
            """,
            (author_name, author_id)
        )

        db.commit()

        return jsonify({
            "message":
                "Author updated successfully",
            "author_id": author_id,
        }), 200

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Author already exists",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "update_author DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


@app.route(
    "/authors/<int:author_id>",
    methods=["DELETE"]
)
@require_staff
def delete_author(staff, author_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT author_id
            FROM authors
            WHERE author_id = %s
            FOR UPDATE
            """,
            (author_id,)
        )

        if not cursor.fetchone():
            return err(
                "Author not found",
                404
            )

        cursor.execute(
            """
            SELECT book_id
            FROM books
            WHERE author_id = %s
            LIMIT 1
            """,
            (author_id,)
        )

        if cursor.fetchone():
            return err(
                "Author is being used by existing books",
                409
            )

        cursor.execute(
            """
            DELETE FROM authors
            WHERE author_id = %s
            """,
            (author_id,)
        )

        db.commit()

        return jsonify({
            "message":
                "Author deleted successfully",
            "author_id": author_id,
        }), 200

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Author cannot be deleted because it is in use",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "delete_author DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# CATEGORY CRUD
# =========================================================

@app.route(
    "/categories",
    methods=["POST"]
)
@require_staff
def create_category(staff):

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return err(
            "Invalid JSON",
            400
        )

    category_name, error = clean_string(
        data.get("category_name"),
        "category_name",
        200
    )

    if error:
        return err(
            error,
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            INSERT INTO categories
                (category_name)
            VALUES
                (%s)
            """,
            (category_name,)
        )

        db.commit()

        return jsonify({
            "message":
                "Category created successfully",
            "category_id":
                cursor.lastrowid,
        }), 201

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Category already exists",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "create_category DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


@app.route(
    "/categories",
    methods=["GET"]
)
@require_staff
def list_categories(staff):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                category_id,
                category_name
            FROM categories
            ORDER BY category_name ASC
            """
        )

        categories = cursor.fetchall()

        return jsonify({
            "categories": categories,
            "count": len(categories),
        }), 200

    except mysql.connector.Error as e:

        logger.error(
            "list_categories DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


@app.route(
    "/categories/<int:category_id>",
    methods=["GET"]
)
@require_staff
def get_category(staff, category_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                category_id,
                category_name
            FROM categories
            WHERE category_id = %s
            """,
            (category_id,)
        )

        category = cursor.fetchone()

        if not category:
            return err(
                "Category not found",
                404
            )

        return jsonify(category), 200

    except mysql.connector.Error as e:

        logger.error(
            "get_category DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


@app.route(
    "/categories/<int:category_id>",
    methods=["PATCH"]
)
@require_staff
def update_category(staff, category_id):

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return err(
            "Invalid JSON",
            400
        )

    if "category_name" not in data:
        return err(
            "category_name is required",
            400
        )

    category_name, error = clean_string(
        data["category_name"],
        "category_name",
        200
    )

    if error:
        return err(
            error,
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT category_id
            FROM categories
            WHERE category_id = %s
            FOR UPDATE
            """,
            (category_id,)
        )

        if not cursor.fetchone():
            return err(
                "Category not found",
                404
            )

        cursor.execute(
            """
            UPDATE categories
            SET category_name = %s
            WHERE category_id = %s
            """,
            (category_name, category_id)
        )

        db.commit()

        return jsonify({
            "message":
                "Category updated successfully",
            "category_id": category_id,
        }), 200

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Category already exists",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "update_category DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


@app.route(
    "/categories/<int:category_id>",
    methods=["DELETE"]
)
@require_staff
def delete_category(staff, category_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT category_id
            FROM categories
            WHERE category_id = %s
            FOR UPDATE
            """,
            (category_id,)
        )

        if not cursor.fetchone():
            return err(
                "Category not found",
                404
            )

        cursor.execute(
            """
            SELECT book_id
            FROM books
            WHERE category_id = %s
            LIMIT 1
            """,
            (category_id,)
        )

        if cursor.fetchone():
            return err(
                "Category is being used by existing books",
                409
            )

        cursor.execute(
            """
            DELETE FROM categories
            WHERE category_id = %s
            """,
            (category_id,)
        )

        db.commit()

        return jsonify({
            "message":
                "Category deleted successfully",
            "category_id": category_id,
        }), 200

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Category cannot be deleted because it is in use",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "delete_category DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# CREATE BOOK
# =========================================================

@app.route(
    "/books",
    methods=["POST"]
)
@require_staff
def create_book(staff):

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return err(
            "Invalid JSON",
            400
        )

    required_fields = [
        "title",
        "author_id",
        "category_id",
        "borrowing_price",
        "loan_price",
        "fine_per_day",
    ]

    for field in required_fields:

        if field not in data:
            return err(
                f"{field} is required",
                400
            )

    title, error = clean_string(
        data["title"],
        "title",
        200
    )

    if error:
        return err(error, 400)

    author_id, error = validate_positive_integer(
        data["author_id"],
        "author_id"
    )

    if error:
        return err(error, 400)

    category_id, error = validate_positive_integer(
        data["category_id"],
        "category_id"
    )

    if error:
        return err(error, 400)

    borrowing_price, error = validate_money(
        data["borrowing_price"],
        "borrowing_price"
    )

    if error:
        return err(error, 400)

    loan_price, error = validate_money(
        data["loan_price"],
        "loan_price"
    )

    if error:
        return err(error, 400)

    fine_per_day, error = validate_money(
        data["fine_per_day"],
        "fine_per_day"
    )

    if error:
        return err(error, 400)

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT author_id
            FROM authors
            WHERE author_id = %s
            """,
            (author_id,)
        )

        if not cursor.fetchone():
            return err(
                "Author not found",
                404
            )

        cursor.execute(
            """
            SELECT category_id
            FROM categories
            WHERE category_id = %s
            """,
            (category_id,)
        )

        if not cursor.fetchone():
            return err(
                "Category not found",
                404
            )

        cursor.execute(
            """
            INSERT INTO books
                (
                    title,
                    author_id,
                    category_id,
                    borrowing_price,
                    loan_price,
                    fine_per_day
                )
            VALUES
                (%s,%s,%s,%s,%s,%s)
            """,
            (
                title,
                author_id,
                category_id,
                borrowing_price,
                loan_price,
                fine_per_day,
            )
        )

        db.commit()

        return jsonify({
            "message":
                "Book created successfully",
            "book_id":
                cursor.lastrowid,
        }), 201

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "create_book DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# UPDATE BOOK
# =========================================================

@app.route(
    "/books/<int:book_id>",
    methods=["PATCH"]
)
@require_staff
def update_book(staff, book_id):

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return err(
            "Invalid JSON",
            400
        )

    updates = []
    values = []

    author_id = None
    category_id = None

    if "title" in data:

        title, error = clean_string(
            data["title"],
            "title",
            200
        )

        if error:
            return err(error, 400)

        updates.append(
            "title = %s"
        )

        values.append(title)

    if "author_id" in data:

        author_id, error = validate_positive_integer(
            data["author_id"],
            "author_id"
        )

        if error:
            return err(error, 400)

        updates.append(
            "author_id = %s"
        )

        values.append(author_id)

    if "category_id" in data:

        category_id, error = validate_positive_integer(
            data["category_id"],
            "category_id"
        )

        if error:
            return err(error, 400)

        updates.append(
            "category_id = %s"
        )

        values.append(category_id)

    if "borrowing_price" in data:

        value, error = validate_money(
            data["borrowing_price"],
            "borrowing_price"
        )

        if error:
            return err(error, 400)

        updates.append(
            "borrowing_price = %s"
        )

        values.append(value)

    if "loan_price" in data:

        value, error = validate_money(
            data["loan_price"],
            "loan_price"
        )

        if error:
            return err(error, 400)

        updates.append(
            "loan_price = %s"
        )

        values.append(value)

    if "fine_per_day" in data:

        value, error = validate_money(
            data["fine_per_day"],
            "fine_per_day"
        )

        if error:
            return err(error, 400)

        updates.append(
            "fine_per_day = %s"
        )

        values.append(value)

    if not updates:
        return err(
            "No valid fields supplied",
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT book_id
            FROM books
            WHERE book_id = %s
            FOR UPDATE
            """,
            (book_id,)
        )

        if not cursor.fetchone():
            return err(
                "Book not found",
                404
            )

        if author_id is not None:

            cursor.execute(
                """
                SELECT author_id
                FROM authors
                WHERE author_id = %s
                """,
                (author_id,)
            )

            if not cursor.fetchone():
                return err(
                    "Author not found",
                    404
                )

        if category_id is not None:

            cursor.execute(
                """
                SELECT category_id
                FROM categories
                WHERE category_id = %s
                """,
                (category_id,)
            )

            if not cursor.fetchone():
                return err(
                    "Category not found",
                    404
                )

        values.append(book_id)

        cursor.execute(
            f"""
            UPDATE books
            SET {', '.join(updates)}
            WHERE book_id = %s
            """,
            values
        )

        db.commit()

        return jsonify({
            "message":
                "Book updated successfully",
            "book_id":
                book_id,
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "update_book DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# ADD BOOK COPY
# =========================================================

@app.route(
    "/books/<int:book_id>/copies",
    methods=["POST"]
)
@require_staff
def add_copy(staff, book_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT book_id
            FROM books
            WHERE book_id = %s
            """,
            (book_id,)
        )

        if not cursor.fetchone():
            return err(
                "Book not found",
                404
            )

        cursor.execute(
            """
            INSERT INTO book_copies
                (
                    book_id,
                    book_condition,
                    status
                )
            VALUES
                (%s,'good','available')
            """,
            (book_id,)
        )

        db.commit()

        return jsonify({
            "message":
                "Book copy added successfully",
            "copy_id":
                cursor.lastrowid,
            "book_id":
                book_id,
            "condition":
                "good",
            "status":
                "available",
        }), 201

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "add_copy DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# VIEW COPIES
# =========================================================

@app.route(
    "/books/<int:book_id>/copies",
    methods=["GET"]
)
@require_auth
def view_copies(user, book_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                copy_id,
                book_id,
                book_condition,
                status
            FROM book_copies
            WHERE book_id = %s
            ORDER BY copy_id
            """,
            (book_id,)
        )

        return jsonify(
            cursor.fetchall()
        )

    except mysql.connector.Error as e:

        logger.error(
            "view_copies DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# MANAGE COPY
# =========================================================

@app.route(
    "/copies/<int:copy_id>",
    methods=["PATCH"]
)
@require_staff
def manage_copy(staff, copy_id):

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return err(
            "Invalid JSON",
            400
        )

    if (
        "status" not in data
        and "book_condition" not in data
    ):
        return err(
            "No valid fields supplied",
            400
        )

    requested_status = data.get(
        "status"
    )

    requested_condition = data.get(
        "book_condition"
    )

    allowed_statuses = {
        "available",
        "maintenance",
    }

    allowed_conditions = {
        "good",
        "pending_inspection",
    }

    if (
        requested_status is not None
        and requested_status not in allowed_statuses
    ):
        return err(
            "Staff can only manually set status to available or maintenance",
            400
        )

    if (
        requested_condition is not None
        and requested_condition not in allowed_conditions
    ):
        return err(
            "Staff can only manually set condition to good or pending_inspection",
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                copy_id,
                book_id,
                status,
                book_condition
            FROM book_copies
            WHERE copy_id = %s
            FOR UPDATE
            """,
            (copy_id,)
        )

        copy = cursor.fetchone()

        if not copy:
            return err(
                "Copy not found",
                404
            )

        current_status = copy["status"]
        current_condition = copy["book_condition"]

        if current_status == "borrowed":
            return err(
                "A borrowed copy cannot be manually modified. Return it first.",
                409
            )

        if current_status in (
            "damaged",
            "lost"
        ):
            return err(
                "Damaged or lost copies require the inspection process",
                409
            )

        final_status = (
            requested_status
            if requested_status is not None
            else current_status
        )

        final_condition = (
            requested_condition
            if requested_condition is not None
            else current_condition
        )

        if final_status == "maintenance":
            final_condition = "pending_inspection"

        if final_status == "available":

            if final_condition != "good":
                return err(
                    "An available copy must have good condition",
                    400
                )

        if final_condition == "pending_inspection":

            if final_status != "maintenance":
                return err(
                    "A pending-inspection copy must have maintenance status",
                    400
                )

        if (
            final_status == "maintenance"
            and final_condition != "pending_inspection"
        ):
            return err(
                "A maintenance copy must be pending inspection",
                400
            )

        if current_status == "available":

            if final_status not in (
                "available",
                "maintenance"
            ):
                return err(
                    "Invalid copy state transition",
                    409
                )

        elif current_status == "maintenance":

            if final_status == "maintenance":
                pass

            elif final_status == "available":

                if final_condition != "good":
                    return err(
                        "A copy must be in good condition before becoming available",
                        400
                    )

            else:
                return err(
                    "Invalid copy state transition",
                    409
                )

        else:
            return err(
                "Invalid current copy state",
                409
            )

        cursor.execute(
            """
            UPDATE book_copies
            SET
                status = %s,
                book_condition = %s
            WHERE copy_id = %s
            """,
            (
                final_status,
                final_condition,
                copy_id,
            )
        )

        db.commit()

        return jsonify({
            "message":
                "Copy updated successfully",
            "copy_id":
                copy_id,
            "status":
                final_status,
            "book_condition":
                final_condition,
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "manage_copy DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# RESERVATION HELPER
# =========================================================

def _get_usable_reservation(
    cursor,
    user_id,
    book_id
):

    cursor.execute(
        """
        SELECT
            reservation_id,
            reservation_time
        FROM reservations
        WHERE user_id = %s
          AND book_id = %s
          AND status = 'waiting'
        ORDER BY reservation_time
        LIMIT 1
        FOR UPDATE
        """,
        (
            user_id,
            book_id,
        )
    )

    reservation = cursor.fetchone()

    if not reservation:
        return None, False

    cutoff = (
        datetime.now(timezone.utc)
        - timedelta(
            days=RESERVATION_EXPIRY_DAYS
        )
    )

    reservation_time = (
        reservation["reservation_time"]
    )

    if reservation_time.tzinfo is None:
        reservation_time = (
            reservation_time.replace(
                tzinfo=timezone.utc
            )
        )

    if reservation_time < cutoff:

        cursor.execute(
            """
            UPDATE reservations
            SET status = 'expired'
            WHERE reservation_id = %s
              AND status = 'waiting'
            """,
            (
                reservation["reservation_id"],
            )
        )

        return None, True

    return reservation, False


# =========================================================
# CREATE RESERVATION
# =========================================================

@app.route(
    "/reservations",
    methods=["POST"]
)
@require_auth
def create_reservation(user):

    if user["role"] not in ("user", "admin"):
        return err(
            "Only users or admins can make reservations",
            403
        )

    data = request.get_json(
        silent=True
    )

    if (
        not isinstance(data, dict)
        or "book_id" not in data
    ):
        return err(
            "book_id is required",
            400
        )

    book_id, error = validate_positive_integer(
        data["book_id"],
        "book_id"
    )

    if error:
        return err(
            error,
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT user_id
            FROM users
            WHERE user_id = %s
              AND account_status = 'active'
            FOR UPDATE
            """,
            (user["user_id"],)
        )

        if not cursor.fetchone():
            return err(
                "Account is no longer active",
                403
            )

        cursor.execute(
            """
            SELECT book_id
            FROM books
            WHERE book_id = %s
            FOR UPDATE
            """,
            (book_id,)
        )

        if not cursor.fetchone():
            return err(
                "Book not found",
                404
            )

        cursor.execute(
            """
            SELECT br.borrowing_id
            FROM borrowings br
            JOIN book_copies bc
                ON br.copy_id = bc.copy_id
            WHERE br.user_id = %s
              AND bc.book_id = %s
              AND br.status IN ('active','overdue')
            LIMIT 1
            """,
            (
                user["user_id"],
                book_id,
            )
        )

        if cursor.fetchone():
            return err(
                "You already have this book",
                409
            )

        cursor.execute(
            """
            SELECT l.loan_id
            FROM loans l
            JOIN book_copies bc
                ON l.copy_id = bc.copy_id
            WHERE l.user_id = %s
              AND bc.book_id = %s
              AND l.status IN ('active','overdue')
            LIMIT 1
            """,
            (
                user["user_id"],
                book_id,
            )
        )

        if cursor.fetchone():
            return err(
                "You already have this book",
                409
            )

        _, _ = _get_usable_reservation(
            cursor,
            user["user_id"],
            book_id
        )

        cursor.execute(
            """
            SELECT reservation_id
            FROM reservations
            WHERE user_id = %s
              AND book_id = %s
              AND status = 'waiting'
            LIMIT 1
            FOR UPDATE
            """,
            (
                user["user_id"],
                book_id,
            )
        )

        if cursor.fetchone():
            return err(
                "You already have a waiting reservation",
                409
            )

        cursor.execute(
            """
            INSERT INTO reservations
                (
                    user_id,
                    book_id,
                    status
                )
            VALUES
                (%s,%s,'waiting')
            """,
            (
                user["user_id"],
                book_id,
            )
        )

        reservation_id = cursor.lastrowid

        db.commit()

        return jsonify({
            "message":
                "Reservation created successfully",
            "reservation_id":
                reservation_id,
            "user_id":
                user["user_id"],
            "book_id":
                book_id,
            "status":
                "waiting",
        }), 201

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Reservation already exists",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "create_reservation DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# MY RESERVATIONS
# =========================================================

@app.route(
    "/my-reservations",
    methods=["GET"]
)
@require_auth
def my_reservations(user):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
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
            """,
            (user["user_id"],)
        )

        return jsonify(
            cursor.fetchall()
        )

    except mysql.connector.Error as e:

        logger.error(
            "my_reservations DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# CANCEL RESERVATION
# =========================================================

@app.route(
    "/reservations/<int:reservation_id>",
    methods=["DELETE"]
)
@require_auth
def cancel_reservation(
    user,
    reservation_id
):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                reservation_id,
                user_id,
                status
            FROM reservations
            WHERE reservation_id = %s
            FOR UPDATE
            """,
            (reservation_id,)
        )

        reservation = cursor.fetchone()

        if not reservation:
            return err(
                "Reservation not found",
                404
            )

        if reservation["user_id"] != user["user_id"]:
            return err(
                "You do not own this reservation",
                403
            )

        if reservation["status"] != "waiting":
            return err(
                "Only waiting reservations can be cancelled",
                400
            )

        cursor.execute(
            """
            DELETE FROM reservations
            WHERE reservation_id = %s
            """,
            (reservation_id,)
        )

        db.commit()

        return jsonify({
            "message":
                "Reservation cancelled successfully",
            "reservation_id":
                reservation_id,
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "cancel_reservation DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# STAFF EXPIRE RESERVATIONS
# =========================================================

@app.route(
    "/staff/reservations/expire",
    methods=["POST"]
)
@require_staff
def expire_reservations(staff):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor()

        cursor.execute(
            """
            UPDATE reservations
            SET status = 'expired'
            WHERE status = 'waiting'
              AND reservation_time <
                  (
                      NOW()
                      - INTERVAL %s DAY
                  )
            """,
            (
                RESERVATION_EXPIRY_DAYS,
            )
        )

        expired_count = cursor.rowcount

        db.commit()

        return jsonify({
            "message":
                "Reservation expiry check completed",
            "reservations_expired":
                expired_count,
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "expire_reservations DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# ACTIVE HOLDS
# =========================================================

def _count_active_holds(
    cursor,
    user_id
):

    cursor.execute(
        """
        SELECT
            (
                SELECT COUNT(*)
                FROM borrowings
                WHERE user_id = %s
                  AND status IN ('active','overdue')
            )
            +
            (
                SELECT COUNT(*)
                FROM loans
                WHERE user_id = %s
                  AND status IN ('active','overdue')
            )
            AS total
        """,
        (
            user_id,
            user_id,
        )
    )

    return cursor.fetchone()["total"]


# =========================================================
# CREATE BORROWING
# =========================================================

@app.route(
    "/borrowings",
    methods=["POST"]
)
@require_auth
def create_borrowing(user):

    if user["role"] not in ("user", "admin"):
        return err(
            "Only users or admins can borrow books",
            403
        )

    data = request.get_json(
        silent=True
    )

    if (
        not isinstance(data, dict)
        or "book_id" not in data
    ):
        return err(
            "book_id is required",
            400
        )

    book_id, error = validate_positive_integer(
        data["book_id"],
        "book_id"
    )

    if error:
        return err(
            error,
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        # Lock user first.
        cursor.execute(
            """
            SELECT
                user_id,
                account_status
            FROM users
            WHERE user_id = %s
            FOR UPDATE
            """,
            (user["user_id"],)
        )

        current_user = cursor.fetchone()

        if not current_user:
            return err(
                "User not found",
                404
            )

        if current_user["account_status"] != "active":
            return err(
                "Account is blocked",
                403
            )

        if (
            _count_active_holds(
                cursor,
                user["user_id"]
            )
            >= MAX_ACTIVE_HOLDS
        ):
            return err(
                f"Maximum {MAX_ACTIVE_HOLDS} "
                "active borrowings/loans allowed in total",
                400
            )

        # Lock the book before selecting its copy.
        cursor.execute(
            """
            SELECT
                book_id,
                borrowing_price,
                loan_price,
                fine_per_day
            FROM books
            WHERE book_id = %s
            FOR UPDATE
            """,
            (book_id,)
        )

        book = cursor.fetchone()

        if not book:
            return err(
                "Book not found",
                404
            )

        cursor.execute(
            """
            SELECT br.borrowing_id
            FROM borrowings br
            JOIN book_copies bc
                ON br.copy_id = bc.copy_id
            WHERE br.user_id = %s
              AND bc.book_id = %s
              AND br.status IN ('active','overdue')
            LIMIT 1
            """,
            (
                user["user_id"],
                book_id,
            )
        )

        if cursor.fetchone():
            return err(
                "You already have this book",
                409
            )

        cursor.execute(
            """
            SELECT l.loan_id
            FROM loans l
            JOIN book_copies bc
                ON l.copy_id = bc.copy_id
            WHERE l.user_id = %s
              AND bc.book_id = %s
              AND l.status IN ('active','overdue')
            LIMIT 1
            """,
            (
                user["user_id"],
                book_id,
            )
        )

        if cursor.fetchone():
            return err(
                "You already have this book as a loan",
                409
            )

        reservation, expired = _get_usable_reservation(
            cursor,
            user["user_id"],
            book_id
        )

        if not reservation:

            message = (
                "Your reservation expired, please reserve again"
                if expired
                else "You must reserve this book first"
            )

            db.rollback()

            return err(
                message,
                400
            )

        cursor.execute(
            """
            SELECT
                copy_id
            FROM book_copies
            WHERE book_id = %s
              AND status = 'available'
              AND book_condition = 'good'
            ORDER BY copy_id
            LIMIT 1
            FOR UPDATE
            """,
            (book_id,)
        )

        copy = cursor.fetchone()

        if not copy:

            db.rollback()

            return err(
                "No available copy",
                409
            )

        due_date = (
            date.today()
            + timedelta(days=10)
        )

        price = book["borrowing_price"]

        cursor.execute(
            """
            INSERT INTO borrowings
                (
                    user_id,
                    copy_id,
                    due_date,
                    price,
                    status
                )
            VALUES
                (%s,%s,%s,%s,'active')
            """,
            (
                user["user_id"],
                copy["copy_id"],
                due_date,
                price,
            )
        )

        borrowing_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO payments
                (
                    user_id,
                    borrowing_id,
                    amount,
                    payment_type
                )
            VALUES
                (%s,%s,%s,'borrowing')
            """,
            (
                user["user_id"],
                borrowing_id,
                price,
            )
        )

        payment_id = cursor.lastrowid

        cursor.execute(
            """
            UPDATE book_copies
            SET status = 'borrowed'
            WHERE copy_id = %s
              AND status = 'available'
              AND book_condition = 'good'
            """,
            (copy["copy_id"],)
        )

        if cursor.rowcount != 1:

            db.rollback()

            return err(
                "Copy is no longer available",
                409
            )

        cursor.execute(
            """
            UPDATE reservations
            SET status = 'fulfilled'
            WHERE reservation_id = %s
              AND status = 'waiting'
            """,
            (
                reservation["reservation_id"],
            )
        )

        if cursor.rowcount != 1:

            db.rollback()

            return err(
                "Reservation is no longer available",
                409
            )

        db.commit()

        return jsonify({
            "message":
                "Book borrowed successfully",
            "borrowing_id":
                borrowing_id,
            "payment_id":
                payment_id,
            "user_id":
                user["user_id"],
            "book_id":
                book_id,
            "copy_id":
                copy["copy_id"],
            "price":
                price,
            "borrow_date":
                date.today().isoformat(),
            "due_date":
                due_date.isoformat(),
            "status":
                "active",
        }), 201

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Borrowing could not be completed",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "create_borrowing DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    except Exception:

        if db:
            db.rollback()

        logger.exception(
            "create_borrowing unexpected error"
        )

        return err(
            "Borrowing could not be completed",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# CREATE LOAN
# =========================================================

@app.route(
    "/loans",
    methods=["POST"]
)
@require_auth
def create_loan(user):

    if user["role"] != "user":
        return err(
            "Only users can take loans",
            403
        )

    data = request.get_json(
        silent=True
    )

    if (
        not isinstance(data, dict)
        or "book_id" not in data
    ):
        return err(
            "book_id is required",
            400
        )

    book_id, error = validate_positive_integer(
        data["book_id"],
        "book_id"
    )

    if error:
        return err(
            error,
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                user_id,
                account_status
            FROM users
            WHERE user_id = %s
            FOR UPDATE
            """,
            (user["user_id"],)
        )

        current_user = cursor.fetchone()

        if not current_user:
            return err(
                "User not found",
                404
            )

        if current_user["account_status"] != "active":
            return err(
                "Account is blocked",
                403
            )

        if (
            _count_active_holds(
                cursor,
                user["user_id"]
            )
            >= MAX_ACTIVE_HOLDS
        ):
            return err(
                f"Maximum {MAX_ACTIVE_HOLDS} "
                "active borrowings/loans allowed in total",
                400
            )

        cursor.execute(
            """
            SELECT
                book_id,
                borrowing_price,
                loan_price,
                fine_per_day
            FROM books
            WHERE book_id = %s
            FOR UPDATE
            """,
            (book_id,)
        )

        book = cursor.fetchone()

        if not book:
            return err(
                "Book not found",
                404
            )

        cursor.execute(
            """
            SELECT br.borrowing_id
            FROM borrowings br
            JOIN book_copies bc
                ON br.copy_id = bc.copy_id
            WHERE br.user_id = %s
              AND bc.book_id = %s
              AND br.status IN ('active','overdue')
            LIMIT 1
            """,
            (
                user["user_id"],
                book_id,
            )
        )

        if cursor.fetchone():
            return err(
                "You already have this book",
                409
            )

        cursor.execute(
            """
            SELECT l.loan_id
            FROM loans l
            JOIN book_copies bc
                ON l.copy_id = bc.copy_id
            WHERE l.user_id = %s
              AND bc.book_id = %s
              AND l.status IN ('active','overdue')
            LIMIT 1
            """,
            (
                user["user_id"],
                book_id,
            )
        )

        if cursor.fetchone():
            return err(
                "You already have this book",
                409
            )

        reservation, expired = _get_usable_reservation(
            cursor,
            user["user_id"],
            book_id
        )

        if not reservation:

            message = (
                "Your reservation expired, please reserve again"
                if expired
                else "You must reserve this book first"
            )

            db.rollback()

            return err(
                message,
                400
            )

        cursor.execute(
            """
            SELECT copy_id
            FROM book_copies
            WHERE book_id = %s
              AND status = 'available'
              AND book_condition = 'good'
            ORDER BY copy_id
            LIMIT 1
            FOR UPDATE
            """,
            (book_id,)
        )

        copy = cursor.fetchone()

        if not copy:

            db.rollback()

            return err(
                "No available copy",
                409
            )

        due_date = (
            date.today()
            + timedelta(days=10)
        )

        price = book["loan_price"]

        cursor.execute(
            """
            INSERT INTO loans
                (
                    user_id,
                    copy_id,
                    due_date,
                    status,
                    price
                )
            VALUES
                (%s,%s,%s,'active',%s)
            """,
            (
                user["user_id"],
                copy["copy_id"],
                due_date,
                price,
            )
        )

        loan_id = cursor.lastrowid

        cursor.execute(
            """
            UPDATE book_copies
            SET status = 'borrowed'
            WHERE copy_id = %s
              AND status = 'available'
              AND book_condition = 'good'
            """,
            (copy["copy_id"],)
        )

        if cursor.rowcount != 1:

            db.rollback()

            return err(
                "Copy is no longer available",
                409
            )

        cursor.execute(
            """
            UPDATE reservations
            SET status = 'fulfilled'
            WHERE reservation_id = %s
              AND status = 'waiting'
            """,
            (
                reservation["reservation_id"],
            )
        )

        if cursor.rowcount != 1:

            db.rollback()

            return err(
                "Reservation is no longer available",
                409
            )

        db.commit()

        return jsonify({
            "message":
                "Book loan created successfully",
            "loan_id":
                loan_id,
            "user_id":
                user["user_id"],
            "book_id":
                book_id,
            "copy_id":
                copy["copy_id"],
            "price":
                price,
            "borrow_date":
                date.today().isoformat(),
            "due_date":
                due_date.isoformat(),
            "status":
                "active",
        }), 201

    except mysql.connector.IntegrityError:

        if db:
            db.rollback()

        return err(
            "Loan could not be created",
            409
        )

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "create_loan DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    except Exception:

        if db:
            db.rollback()

        logger.exception(
            "create_loan unexpected error"
        )

        return err(
            "Loan could not be created",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# RETURN LOAN
# =========================================================

@app.route(
    "/loans/<int:loan_id>/return",
    methods=["POST"]
)
@require_auth
def return_loan(user, loan_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
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

            FOR UPDATE
            """,
            (loan_id,)
        )

        loan = cursor.fetchone()

        if not loan:
            return err(
                "Loan not found",
                404
            )

        if loan["user_id"] != user["user_id"]:
            return err(
                "You do not own this loan",
                403
            )

        if loan["status"] == "returned":
            return err(
                "Loan already returned",
                400
            )

        if loan["due_date"] is None:
            return err(
                "Loan has no due date",
                500
            )

        overdue_days = max(
            (
                date.today()
                - loan["due_date"]
            ).days,
            0
        )

        late_fine = (
            Decimal(overdue_days)
            * loan["fine_per_day"]
        )

        cursor.execute(
            """
            UPDATE loans
            SET
                return_time = NOW(),
                status = 'returned',
                fine_amount = %s
            WHERE loan_id = %s
              AND status IN ('active','overdue')
            """,
            (
                late_fine,
                loan_id,
            )
        )

        if cursor.rowcount != 1:

            db.rollback()

            return err(
                "Loan has already been returned",
                409
            )

        cursor.execute(
            """
            UPDATE book_copies
            SET
                status = 'maintenance',
                book_condition = 'pending_inspection'
            WHERE copy_id = %s
              AND status = 'borrowed'
            """,
            (loan["copy_id"],)
        )

        if cursor.rowcount != 1:

            db.rollback()

            return err(
                "Copy is not currently borrowed",
                409
            )

        fine_id = None

        if late_fine > 0:

            cursor.execute(
                """
                INSERT INTO fines
                    (
                        user_id,
                        loan_id,
                        fine_amount,
                        reason,
                        status
                    )
                VALUES
                    (%s,%s,%s,%s,'unpaid')
                """,
                (
                    user["user_id"],
                    loan_id,
                    late_fine,
                    f"Late return ({overdue_days} overdue days)",
                )
            )

            fine_id = cursor.lastrowid

        cursor.execute(
            """
            INSERT INTO payments
                (
                    user_id,
                    loan_id,
                    amount,
                    payment_type
                )
            VALUES
                (%s,%s,%s,'loan')
            """,
            (
                user["user_id"],
                loan_id,
                loan["price"],
            )
        )

        payment_id = cursor.lastrowid

        db.commit()

        return jsonify({
            "message":
                "Loan returned successfully and sent for inspection",
            "loan_id":
                loan_id,
            "payment_id":
                payment_id,
            "fine_id":
                fine_id,
            "fine_amount":
                late_fine,
            "copy_status":
                "maintenance",
            "copy_condition":
                "pending_inspection",
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "return_loan DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    except Exception:

        if db:
            db.rollback()

        logger.exception(
            "return_loan unexpected error"
        )

        return err(
            "Loan return failed",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# RETURN BORROWING
# =========================================================

@app.route(
    "/borrowings/<int:borrowing_id>/return",
    methods=["POST"]
)
@require_auth
def return_borrowing(
    user,
    borrowing_id
):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
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

            FOR UPDATE
            """,
            (borrowing_id,)
        )

        borrowing = cursor.fetchone()

        if not borrowing:
            return err(
                "Borrowing not found",
                404
            )

        if borrowing["user_id"] != user["user_id"]:
            return err(
                "You do not own this borrowing",
                403
            )

        if borrowing["status"] == "returned":
            return err(
                "Borrowing already returned",
                400
            )

        if borrowing["due_date"] is None:
            return err(
                "Borrowing has no due date",
                500
            )

        overdue_days = max(
            (
                date.today()
                - borrowing["due_date"]
            ).days,
            0
        )

        late_fine = (
            Decimal(overdue_days)
            * borrowing["fine_per_day"]
        )

        cursor.execute(
            """
            UPDATE borrowings
            SET
                return_time = NOW(),
                status = 'returned',
                fine_amount = %s
            WHERE borrowing_id = %s
              AND status IN ('active','overdue')
            """,
            (
                late_fine,
                borrowing_id,
            )
        )

        if cursor.rowcount != 1:

            db.rollback()

            return err(
                "Borrowing has already been returned",
                409
            )

        cursor.execute(
            """
            UPDATE book_copies
            SET
                status = 'maintenance',
                book_condition = 'pending_inspection'
            WHERE copy_id = %s
              AND status = 'borrowed'
            """,
            (
                borrowing["copy_id"],
            )
        )

        if cursor.rowcount != 1:

            db.rollback()

            return err(
                "Copy is not currently borrowed",
                409
            )

        fine_id = None

        if late_fine > 0:

            cursor.execute(
                """
                INSERT INTO fines
                    (
                        user_id,
                        borrowing_id,
                        fine_amount,
                        reason,
                        status
                    )
                VALUES
                    (%s,%s,%s,%s,'unpaid')
                """,
                (
                    user["user_id"],
                    borrowing_id,
                    late_fine,
                    f"Late return ({overdue_days} overdue days)",
                )
            )

            fine_id = cursor.lastrowid

        db.commit()

        return jsonify({
            "message":
                "Borrowing returned successfully and sent for inspection",
            "borrowing_id":
                borrowing_id,
            "fine_id":
                fine_id,
            "fine_amount":
                late_fine,
            "copy_status":
                "maintenance",
            "copy_condition":
                "pending_inspection",
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "return_borrowing DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    except Exception:

        if db:
            db.rollback()

        logger.exception(
            "return_borrowing unexpected error"
        )

        return err(
            "Borrowing return failed",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# GET SINGLE BORROWING
# =========================================================

@app.route(
    "/borrowings/<int:borrowing_id>",
    methods=["GET"]
)
@require_auth
def get_borrowing(
    user,
    borrowing_id
):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
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
                br.status,

                CASE
                    WHEN br.status = 'active'
                     AND br.due_date < CURDATE()
                    THEN 'overdue'
                    ELSE br.status
                END AS effective_status

            FROM borrowings br

            JOIN book_copies bc
                ON br.copy_id = bc.copy_id

            JOIN books b
                ON bc.book_id = b.book_id

            WHERE br.borrowing_id = %s
            """,
            (borrowing_id,)
        )

        result = cursor.fetchone()

        if not result:
            return err(
                "Borrowing not found",
                404
            )

        if (
            result["user_id"] != user["user_id"]
            and not is_staff(user)
        ):
            return err(
                "You do not have access to this borrowing",
                403
            )

        return jsonify(result)

    except mysql.connector.Error as e:

        logger.error(
            "get_borrowing DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# GET SINGLE LOAN
# =========================================================

@app.route(
    "/loans/<int:loan_id>",
    methods=["GET"]
)
@require_auth
def get_loan(user, loan_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
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
                l.status,

                CASE
                    WHEN l.status = 'active'
                     AND l.due_date < CURDATE()
                    THEN 'overdue'
                    ELSE l.status
                END AS effective_status

            FROM loans l

            JOIN book_copies bc
                ON l.copy_id = bc.copy_id

            JOIN books b
                ON bc.book_id = b.book_id

            WHERE l.loan_id = %s
            """,
            (loan_id,)
        )

        result = cursor.fetchone()

        if not result:
            return err(
                "Loan not found",
                404
            )

        if (
            result["user_id"] != user["user_id"]
            and not is_staff(user)
        ):
            return err(
                "You do not have access to this loan",
                403
            )

        return jsonify(result)

    except mysql.connector.Error as e:

        logger.error(
            "get_loan DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# MY BORROWINGS
# =========================================================

@app.route(
    "/my-borrowings",
    methods=["GET"]
)
@require_auth
def my_borrowings(user):

    try:
        page, limit, offset = parse_pagination()

    except ValueError as e:
        return err(
            str(e),
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM borrowings
            WHERE user_id = %s
            """,
            (user["user_id"],)
        )

        total = cursor.fetchone()["total"]

        cursor.execute(
            """
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
                br.status,

                CASE
                    WHEN br.status = 'active'
                     AND br.due_date < CURDATE()
                    THEN 'overdue'
                    ELSE br.status
                END AS effective_status

            FROM borrowings br

            JOIN book_copies bc
                ON br.copy_id = bc.copy_id

            JOIN books b
                ON bc.book_id = b.book_id

            WHERE br.user_id = %s

            ORDER BY
                br.borrow_time DESC,
                br.borrowing_id DESC

            LIMIT %s OFFSET %s
            """,
            (
                user["user_id"],
                limit,
                offset,
            )
        )

        return jsonify({
            "page":
                page,
            "limit":
                limit,
            "total":
                total,
            "borrowings":
                cursor.fetchall(),
        })

    except mysql.connector.Error as e:

        logger.error(
            "my_borrowings DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# MY LOANS
# =========================================================

@app.route(
    "/my-loans",
    methods=["GET"]
)
@require_auth
def my_loans(user):

    try:
        page, limit, offset = parse_pagination()

    except ValueError as e:
        return err(
            str(e),
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM loans
            WHERE user_id = %s
            """,
            (user["user_id"],)
        )

        total = cursor.fetchone()["total"]

        cursor.execute(
            """
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
                l.status,

                CASE
                    WHEN l.status = 'active'
                     AND l.due_date < CURDATE()
                    THEN 'overdue'
                    ELSE l.status
                END AS effective_status

            FROM loans l

            JOIN book_copies bc
                ON l.copy_id = bc.copy_id

            JOIN books b
                ON bc.book_id = b.book_id

            WHERE l.user_id = %s

            ORDER BY
                l.borrow_time DESC,
                l.loan_id DESC

            LIMIT %s OFFSET %s
            """,
            (
                user["user_id"],
                limit,
                offset,
            )
        )

        return jsonify({
            "page":
                page,
            "limit":
                limit,
            "total":
                total,
            "loans":
                cursor.fetchall(),
        })

    except mysql.connector.Error as e:

        logger.error(
            "my_loans DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# MY PAYMENTS
# =========================================================

@app.route(
    "/my-payments",
    methods=["GET"]
)
@require_auth
def my_payments(user):

    try:
        page, limit, offset = parse_pagination()

    except ValueError as e:
        return err(
            str(e),
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM payments
            WHERE user_id = %s
            """,
            (user["user_id"],)
        )

        total = cursor.fetchone()["total"]

        cursor.execute(
            """
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
            ORDER BY
                payment_time DESC,
                payment_id DESC
            LIMIT %s OFFSET %s
            """,
            (
                user["user_id"],
                limit,
                offset,
            )
        )

        return jsonify({
            "page":
                page,
            "limit":
                limit,
            "total":
                total,
            "payments":
                cursor.fetchall(),
        })

    except mysql.connector.Error as e:

        logger.error(
            "my_payments DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# MY FINES
# =========================================================

@app.route(
    "/my-fines",
    methods=["GET"]
)
@require_auth
def my_fines(user):

    try:
        page, limit, offset = parse_pagination()

    except ValueError as e:
        return err(
            str(e),
            400
        )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT COUNT(*) AS total
            FROM fines
            WHERE user_id = %s
            """,
            (user["user_id"],)
        )

        total = cursor.fetchone()["total"]

        cursor.execute(
            """
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
            ORDER BY
                created_at DESC,
                fine_id DESC
            LIMIT %s OFFSET %s
            """,
            (
                user["user_id"],
                limit,
                offset,
            )
        )

        return jsonify({
            "page":
                page,
            "limit":
                limit,
            "total":
                total,
            "fines":
                cursor.fetchall(),
        })

    except mysql.connector.Error as e:

        logger.error(
            "my_fines DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# PAY FINE
# =========================================================

@app.route(
    "/fines/<int:fine_id>/pay",
    methods=["POST"]
)
@require_auth
def pay_fine(user, fine_id):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
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
            """,
            (fine_id,)
        )

        fine = cursor.fetchone()

        if not fine:
            return err(
                "Fine not found",
                404
            )

        if fine["user_id"] != user["user_id"]:
            return err(
                "You do not own this fine",
                403
            )

        if fine["status"] == "paid":
            return err(
                "Fine already paid",
                400
            )

        cursor.execute(
            """
            INSERT INTO payments
                (
                    user_id,
                    borrowing_id,
                    loan_id,
                    fine_id,
                    amount,
                    payment_type
                )
            VALUES
                (%s,%s,%s,%s,%s,'fine')
            """,
            (
                user["user_id"],
                fine["borrowing_id"],
                fine["loan_id"],
                fine_id,
                fine["fine_amount"],
            )
        )

        payment_id = cursor.lastrowid

        cursor.execute(
            """
            UPDATE fines
            SET
                status = 'paid',
                paid_at = NOW()
            WHERE fine_id = %s
              AND status = 'unpaid'
            """,
            (fine_id,)
        )

        if cursor.rowcount != 1:

            db.rollback()

            return err(
                "Fine payment failed",
                409
            )

        db.commit()

        return jsonify({
            "message":
                "Fine paid successfully",
            "fine_id":
                fine_id,
            "payment_id":
                payment_id,
            "amount":
                fine["fine_amount"],
            "reason":
                fine["reason"],
            "payment_type":
                "fine",
            "status":
                "paid",
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "pay_fine DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    except Exception:

        if db:
            db.rollback()

        logger.exception(
            "pay_fine unexpected error"
        )

        return err(
            "Fine payment failed",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# INSPECT RETURNED COPY
# =========================================================

@app.route(
    "/librarian/copies/<int:copy_id>/inspect",
    methods=["POST"]
)
@require_staff
def inspect_copy(
    inspector,
    copy_id
):

    data = request.get_json(
        silent=True
    )

    if not isinstance(data, dict):
        return err(
            "Invalid JSON",
            400
        )

    condition = data.get(
        "condition"
    )

    if condition not in [
        "good",
        "damaged",
        "lost"
    ]:
        return err(
            "Condition must be good, damaged, or lost",
            400
        )

    if condition == "good":

        fine_amount = Decimal(
            "0.00"
        )

        if (
            "fine_amount" in data
            and data["fine_amount"] not in (
                0,
                0.0,
                "0",
                "0.0",
                "0.00",
                None,
            )
        ):
            return err(
                "fine_amount must be 0 when condition is good",
                400
            )

    else:

        fine_amount, error = validate_money(
            data.get(
                "fine_amount",
                0
            ),
            "fine_amount",
            allow_zero=False
        )

        if error:
            return err(
                error,
                400
            )

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor(
            dictionary=True,
            buffered=True
        )

        cursor.execute(
            """
            SELECT
                copy_id,
                book_id,
                status,
                book_condition
            FROM book_copies
            WHERE copy_id = %s
            FOR UPDATE
            """,
            (copy_id,)
        )

        copy = cursor.fetchone()

        if not copy:
            return err(
                "Copy not found",
                404
            )

        if copy["status"] != "maintenance":
            return err(
                "Copy is not waiting for inspection",
                400
            )

        if copy["book_condition"] != "pending_inspection":
            return err(
                "Copy is not pending inspection",
                400
            )

        cursor.execute(
            """
            SELECT
                transaction_type,
                transaction_id,
                user_id,
                return_time
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
            """,
            (
                copy_id,
                copy_id,
            )
        )

        transaction = cursor.fetchone()

        if not transaction:
            return err(
                "No returned transaction found",
                400
            )

        reason = (
            "Book damaged"
            if condition == "damaged"
            else "Book lost"
        )

        cursor.execute(
            """
            SELECT fine_id
            FROM fines
            WHERE reason = %s
              AND
              (
                    (
                        borrowing_id = %s
                        AND %s = 'borrowing'
                    )
                    OR
                    (
                        loan_id = %s
                        AND %s = 'loan'
                    )
              )
            LIMIT 1
            """,
            (
                reason,
                transaction["transaction_id"],
                transaction["transaction_type"],
                transaction["transaction_id"],
                transaction["transaction_type"],
            )
        )

        existing_damage_fine = (
            cursor.fetchone()
        )

        if existing_damage_fine:

            db.rollback()

            return jsonify({
                "error":
                    "A damage/loss fine already exists for this returned transaction",
                "fine_id":
                    existing_damage_fine["fine_id"],
            }), 409

        if condition == "good":

            cursor.execute(
                """
                UPDATE book_copies
                SET
                    status = 'available',
                    book_condition = 'good'
                WHERE copy_id = %s
                """,
                (copy_id,)
            )

            db.commit()

            return jsonify({
                "message":
                    "Book inspection completed",
                "copy_id":
                    copy_id,
                "book_id":
                    copy["book_id"],
                "condition":
                    "good",
                "status":
                    "available",
                "fine_id":
                    None,
                "fine_amount":
                    Decimal("0.00"),
                "inspected_by":
                    inspector["user_id"],
                "inspector_role":
                    inspector["role"],
            })

        new_status = (
            "damaged"
            if condition == "damaged"
            else "lost"
        )

        fine_column = (
            "borrowing_id"
            if transaction["transaction_type"] == "borrowing"
            else "loan_id"
        )

        cursor.execute(
            """
            UPDATE book_copies
            SET
                status = %s,
                book_condition = %s
            WHERE copy_id = %s
            """,
            (
                new_status,
                condition,
                copy_id,
            )
        )

        cursor.execute(
            f"""
            INSERT INTO fines
                (
                    user_id,
                    {fine_column},
                    fine_amount,
                    reason,
                    status
                )
            VALUES
                (%s,%s,%s,%s,'unpaid')
            """,
            (
                transaction["user_id"],
                transaction["transaction_id"],
                fine_amount,
                reason,
            )
        )

        fine_id = cursor.lastrowid

        db.commit()

        return jsonify({
            "message":
                "Book inspection completed",
            "copy_id":
                copy_id,
            "book_id":
                copy["book_id"],
            "condition":
                condition,
            "status":
                new_status,
            "fine_id":
                fine_id,
            "fine_amount":
                fine_amount,
            "fine_status":
                "unpaid",
            "inspected_by":
                inspector["user_id"],
            "inspector_role":
                inspector["role"],
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "inspect_copy DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    except Exception:

        if db:
            db.rollback()

        logger.exception(
            "inspect_copy unexpected error"
        )

        return err(
            "Inspection failed",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()



def greetings():
    print("hello world!")
    print("This is my testing branch.")
# =========================================================
# STAFF OVERDUE CHECK
# =========================================================

@app.route(
    "/staff/overdue/check",
    methods=["POST"]
)
@require_staff
def check_overdue(staff):

    db = None
    cursor = None

    try:

        db = get_db_connection()

        cursor = db.cursor()

        cursor.execute(
            """
            UPDATE borrowings
            SET status = 'overdue'
            WHERE status = 'active'
              AND due_date < CURDATE()
            """
        )

        borrowing_count = cursor.rowcount

        cursor.execute(
            """
            UPDATE loans
            SET status = 'overdue'
            WHERE status = 'active'
              AND due_date < CURDATE()
            """
        )

        loan_count = cursor.rowcount

        db.commit()

        return jsonify({
            "message":
                "Overdue check completed",
            "borrowings_marked_overdue":
                borrowing_count,
            "loans_marked_overdue":
                loan_count,
        })

    except mysql.connector.Error as e:

        if db:
            db.rollback()

        logger.error(
            "check_overdue DB error: %s",
            e
        )

        return err(
            "Database error",
            500
        )

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# RUN APP
# =========================================================

if __name__ == "__main__":

    debug_mode = (
        os.environ
        .get(
            "FLASK_DEBUG",
            "false"
        )
        .lower()
        == "true"
    )

    app.run(
        debug=debug_mode
    )
print("this is file")