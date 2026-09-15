import os
import io
import csv
import datetime
from functools import wraps
import jwt
from flask import (
    Flask, request, session, jsonify, render_template,
    redirect, url_for, Response
)
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)

# Secret key configuration
app.secret_key = os.environ.get("SECRET_KEY", "student_logbook_secure_secret_key_2026_jwt_token_auth_32bytes")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", app.secret_key)
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False

app.config["MYSQL_HOST"] = os.environ.get("MYSQL_HOST", "localhost")
app.config["MYSQL_USER"] = os.environ.get("MYSQL_USER", "root")
app.config["MYSQL_PASSWORD"] = os.environ.get("MYSQL_PASSWORD", "20040305dm")
app.config["MYSQL_DB"] = os.environ.get("MYSQL_DB", "mydb")

mysql = MySQL(app)

CORS(
    app,
    supports_credentials=True,
    allow_headers=["Content-Type", "Authorization"],
    methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
        "http://localhost:5176",
        "http://127.0.0.1:5176",
        "http://localhost:5177",
        "http://127.0.0.1:5177",
        "http://localhost:5178",
        "http://127.0.0.1:5178",
        "http://localhost:5179",
        "http://127.0.0.1:5179",
        "http://localhost:5180",
        "http://127.0.0.1:5180",
        "http://localhost:5181",
        "http://127.0.0.1:5181",
        "http://localhost:5182",
        "http://127.0.0.1:5182",
        "http://localhost:5183",
        "http://127.0.0.1:5183"
    ]
)


def create_jwt_token(user_id, name, email, role, supervisor_id=None):
    """Generate a signed JWT token containing user details and expiration."""
    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "user_id": user_id,
        "name": name,
        "email": email,
        "role": role,
        "supervisor_id": supervisor_id,
        "exp": now + datetime.timedelta(hours=JWT_EXPIRATION_HOURS),
        "iat": now
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def token_required(allowed_roles=None):
    """
    Decorator that verifies JWT Bearer token from the Authorization header.
    Falls back to session if header is absent (for backward compatibility).
    Enforces role-based permissions when allowed_roles is provided.
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = None
            auth_header = request.headers.get("Authorization")
            if auth_header:
                parts = auth_header.split()
                if len(parts) == 2 and parts[0].lower() == "bearer":
                    token = parts[1]
                elif len(parts) == 1:
                    token = parts[0]

            current_user = None

            if token:
                try:
                    payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
                    current_user = payload
                    if current_user.get("role") == "student":
                        current_user["student_id"] = current_user.get("user_id")
                    elif current_user.get("role") == "supervisor":
                        current_user["supervisor_id"] = current_user.get("user_id")
                except jwt.ExpiredSignatureError:
                    return jsonify({
                        "success": False,
                        "message": "Token has expired. Please log in again."
                    }), 401
                except jwt.InvalidTokenError:
                    return jsonify({
                        "success": False,
                        "message": "Invalid token. Authorization failed."
                    }), 401
            else:
                # Fallback to session for backward compatibility
                if "student_id" in session:
                    current_user = {
                        "user_id": session["student_id"],
                        "student_id": session["student_id"],
                        "name": session.get("student_name"),
                        "role": session.get("role", "student"),
                        "supervisor_id": session.get("supervisor_id")
                    }
                elif "supervisor_id" in session:
                    current_user = {
                        "user_id": session["supervisor_id"],
                        "supervisor_id": session["supervisor_id"],
                        "name": session.get("supervisor_name"),
                        "role": session.get("role", "supervisor")
                    }
                else:
                    return jsonify({
                        "success": False,
                        "message": "Please log in"
                    }), 401

            if allowed_roles and current_user.get("role") not in allowed_roles:
                return jsonify({
                    "success": False,
                    "message": "ACCESS DENIED!"
                }), 403

            return f(current_user, *args, **kwargs)

        return decorated

    return decorator


# ==========================================
# API ENDPOINTS
# ==========================================

@app.route("/api/health", methods=["GET"])
def api_health():
    """Healthcheck endpoint."""
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT 1")
        cur.close()
        return jsonify({"status": "ok", "database": "connected"}), 200
    except Exception as e:
        return jsonify({"status": "error", "database": str(e)}), 500


@app.route("/api/supervisors", methods=["GET"])
def api_get_supervisors():
    """Returns list of all registered supervisors for registration dropdown."""
    cur = mysql.connection.cursor()
    cur.execute("SELECT supervisor_id, full_name, email, department FROM supervisor ORDER BY full_name ASC")
    rows = cur.fetchall()
    cur.close()

    supervisors = [
        {
            "supervisor_id": row[0],
            "full_name": row[1],
            "email": row[2],
            "department": row[3]
        }
        for row in rows
    ]
    return jsonify({"success": True, "supervisors": supervisors}), 200


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json() or {}

    adm_no = data.get("adm_no")
    full_name = data.get("full_name")
    email = data.get("email")
    password = data.get("password")
    supervisor_id = data.get("supervisor_id")

    if not adm_no or not full_name or not email or not password or not supervisor_id:
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400

    password_hash = generate_password_hash(password)

    cur = mysql.connection.cursor()

    cur.execute(
        "SELECT student_id FROM students WHERE email=%s OR adm_no=%s",
        (email, adm_no)
    )
    existing_student = cur.fetchone()

    if existing_student:
        cur.close()
        return jsonify({
            "success": False,
            "message": "Student with this email or admission number already exists"
        }), 400

    cur.execute(
        """
        INSERT INTO students
        (adm_no, full_name, email, password, supervisor_id, role)
        VALUES (%s, %s, %s, %s, %s, %s)
        """,
        (
            adm_no,
            full_name,
            email,
            password_hash,
            supervisor_id,
            "student"
        )
    )

    mysql.connection.commit()
    student_id = cur.lastrowid
    cur.close()

    return jsonify({
        "success": True,
        "message": "Student registered successfully",
        "student_id": student_id
    }), 201


@app.route("/api/register_supervisor", methods=["POST"])
def api_register_supervisor():
    """Register a new supervisor."""
    data = request.get_json() or {}

    full_name = data.get("full_name")
    email = data.get("email")
    password = data.get("password")
    department = data.get("department", "General")

    if not full_name or not email or not password:
        return jsonify({
            "success": False,
            "message": "Full name, email, and password are required"
        }), 400

    password_hash = generate_password_hash(password)

    cur = mysql.connection.cursor()
    cur.execute("SELECT supervisor_id FROM supervisor WHERE email=%s", (email,))
    existing = cur.fetchone()

    if existing:
        cur.close()
        return jsonify({
            "success": False,
            "message": "Supervisor with this email already exists"
        }), 400

    cur.execute(
        """
        INSERT INTO supervisor (full_name, email, password, department)
        VALUES (%s, %s, %s, %s)
        """,
        (full_name, email, password_hash, department)
    )
    mysql.connection.commit()
    supervisor_id = cur.lastrowid
    cur.close()

    return jsonify({
        "success": True,
        "message": "Supervisor registered successfully",
        "supervisor_id": supervisor_id
    }), 201


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json() or {}

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Email and password are required"
        }), 400

    cur = mysql.connection.cursor()

    # Check student table
    cur.execute(
        "SELECT student_id, adm_no, full_name, email, password, supervisor_id, role FROM students WHERE email=%s",
        (email,)
    )
    student = cur.fetchone()

    if student and check_password_hash(student[4], password):
        session.clear()
        session["student_id"] = student[0]
        session["student_name"] = student[2]
        session["role"] = "student"

        token = create_jwt_token(
            user_id=student[0],
            name=student[2],
            email=student[3],
            role="student",
            supervisor_id=student[5]
        )

        mysql.connection.commit()
        cur.close()

        return jsonify({
            "success": True,
            "role": "student",
            "name": student[2],
            "message": "STUDENT LOGIN SUCCESSFUL",
            "token": token,
            "user": {
                "id": student[0],
                "student_id": student[0],
                "adm_no": student[1],
                "name": student[2],
                "email": student[3],
                "role": "student",
                "supervisor_id": student[5]
            }
        })

    # Check supervisor table
    cur.execute(
        "SELECT supervisor_id, full_name, email, password, department FROM supervisor WHERE email=%s",
        (email,)
    )
    supervisor = cur.fetchone()

    if supervisor and check_password_hash(supervisor[3], password):
        session.clear()
        session["supervisor_id"] = supervisor[0]
        session["supervisor_name"] = supervisor[1]
        session["role"] = "supervisor"

        token = create_jwt_token(
            user_id=supervisor[0],
            name=supervisor[1],
            email=supervisor[2],
            role="supervisor"
        )

        mysql.connection.commit()
        cur.close()

        return jsonify({
            "success": True,
            "role": "supervisor",
            "name": supervisor[1],
            "message": "SUPERVISOR LOGIN SUCCESSFUL",
            "token": token,
            "user": {
                "id": supervisor[0],
                "supervisor_id": supervisor[0],
                "name": supervisor[1],
                "email": supervisor[2],
                "department": supervisor[4],
                "role": "supervisor"
            }
        })

    cur.close()

    return jsonify({
        "success": False,
        "message": "Invalid email or password"
    }), 401


@app.route("/api/me", methods=["GET"])
@token_required()
def api_me(current_user):
    """Returns the current authenticated user's details decoded from JWT/session."""
    return jsonify({
        "success": True,
        "user": current_user
    })


@app.route("/api/change_password", methods=["PUT"])
@token_required()
def api_change_password(current_user):
    """Change user password securely for authenticated student or supervisor."""
    data = request.get_json() or {}
    old_password = data.get("old_password")
    new_password = data.get("new_password")

    if not old_password or not new_password:
        return jsonify({
            "success": False,
            "message": "Both old_password and new_password are required"
        }), 400

    if len(new_password) < 6:
        return jsonify({
            "success": False,
            "message": "New password must be at least 6 characters long"
        }), 400

    cur = mysql.connection.cursor()
    role = current_user.get("role")
    user_id = current_user.get("user_id")

    if role == "student":
        cur.execute("SELECT password FROM students WHERE student_id=%s", (user_id,))
    else:
        cur.execute("SELECT password FROM supervisor WHERE supervisor_id=%s", (user_id,))

    row = cur.fetchone()
    if not row or not check_password_hash(row[0], old_password):
        cur.close()
        return jsonify({
            "success": False,
            "message": "Current password does not match"
        }), 400

    new_hash = generate_password_hash(new_password)
    if role == "student":
        cur.execute("UPDATE students SET password=%s WHERE student_id=%s", (new_hash, user_id))
    else:
        cur.execute("UPDATE supervisor SET password=%s WHERE supervisor_id=%s", (new_hash, user_id))

    mysql.connection.commit()
    cur.close()

    return jsonify({
        "success": True,
        "message": "Password changed successfully"
    }), 200


@app.route("/api/forgot_password", methods=["POST"])
def api_forgot_password():
    """Generate a secure password reset token for student or supervisor."""
    data = request.get_json() or {}
    email = (data.get("email") or "").strip()

    if not email:
        return jsonify({
            "success": False,
            "message": "Email address is required"
        }), 400

    cur = mysql.connection.cursor()
    # Check student table
    cur.execute("SELECT student_id, full_name, email FROM students WHERE email=%s", (email,))
    student = cur.fetchone()

    user_info = None
    if student:
        user_info = {
            "user_id": student[0],
            "name": student[1],
            "email": student[2],
            "role": "student"
        }
    else:
        cur.execute("SELECT supervisor_id, full_name, email FROM supervisor WHERE email=%s", (email,))
        supervisor = cur.fetchone()
        if supervisor:
            user_info = {
                "user_id": supervisor[0],
                "name": supervisor[1],
                "email": supervisor[2],
                "role": "supervisor"
            }

    cur.close()

    if not user_info:
        return jsonify({
            "success": False,
            "message": "No account registered with this email address"
        }), 404

    # Create a 15-minute reset token
    now = datetime.datetime.now(datetime.timezone.utc)
    reset_payload = {
        "user_id": user_info["user_id"],
        "email": user_info["email"],
        "role": user_info["role"],
        "purpose": "password_reset",
        "exp": now + datetime.timedelta(minutes=15),
        "iat": now
    }
    reset_token = jwt.encode(reset_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    return jsonify({
        "success": True,
        "message": f"Password reset verified for {user_info['name']}",
        "reset_token": reset_token,
        "email": user_info["email"],
        "name": user_info["name"],
        "role": user_info["role"]
    }), 200


@app.route("/api/reset_password", methods=["POST"])
def api_reset_password():
    """Reset password using a verified reset token."""
    data = request.get_json() or {}
    reset_token = data.get("reset_token")
    new_password = data.get("new_password")

    if not reset_token or not new_password:
        return jsonify({
            "success": False,
            "message": "Reset token and new password are required"
        }), 400

    if len(new_password) < 6:
        return jsonify({
            "success": False,
            "message": "New password must be at least 6 characters long"
        }), 400

    try:
        payload = jwt.decode(reset_token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        if payload.get("purpose") != "password_reset":
            return jsonify({
                "success": False,
                "message": "Invalid reset token purpose"
            }), 400
    except jwt.ExpiredSignatureError:
        return jsonify({
            "success": False,
            "message": "Password reset token has expired. Please request a new one."
        }), 400
    except jwt.InvalidTokenError:
        return jsonify({
            "success": False,
            "message": "Invalid or corrupted reset token"
        }), 400

    user_id = payload.get("user_id")
    role = payload.get("role")
    new_hash = generate_password_hash(new_password)

    cur = mysql.connection.cursor()
    if role == "student":
        cur.execute("UPDATE students SET password=%s WHERE student_id=%s", (new_hash, user_id))
    elif role == "supervisor":
        cur.execute("UPDATE supervisor SET password=%s WHERE supervisor_id=%s", (new_hash, user_id))
    else:
        cur.close()
        return jsonify({
            "success": False,
            "message": "Invalid user role"
        }), 400

    mysql.connection.commit()
    cur.close()

    return jsonify({
        "success": True,
        "message": "Your password has been successfully reset! You can now log in."
    }), 200


@app.route("/api/stats", methods=["GET"])
@token_required(allowed_roles=["student"])
def api_student_stats(current_user):
    """Returns summary statistics of logbook entries for the current student."""
    cur = mysql.connection.cursor()
    student_id = current_user["student_id"]

    cur.execute("""
        SELECT
            COUNT(*) AS total_entries,
            COALESCE(SUM(hours_worked), 0) AS total_hours,
            COALESCE(SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END), 0) AS approved_entries,
            COALESCE(SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END), 0) AS pending_entries,
            COALESCE(SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END), 0) AS rejected_entries,
            COALESCE(SUM(CASE WHEN status = 'approved' THEN hours_worked ELSE 0 END), 0) AS approved_hours
        FROM logbook_entries
        WHERE student_id=%s
    """, (student_id,))

    row = cur.fetchone()
    cur.close()

    return jsonify({
        "success": True,
        "stats": {
            "total_entries": int(row[0]),
            "total_hours": int(row[1]),
            "approved_entries": int(row[2]),
            "pending_entries": int(row[3]),
            "rejected_entries": int(row[4]),
            "approved_hours": int(row[5])
        }
    }), 200


@app.route("/api/supervisor/stats", methods=["GET"])
@token_required(allowed_roles=["supervisor"])
def api_supervisor_stats(current_user):
    """Returns supervisor overview metrics."""
    supervisor_id = current_user["supervisor_id"]
    cur = mysql.connection.cursor()

    cur.execute("SELECT COUNT(*) FROM students WHERE supervisor_id=%s", (supervisor_id,))
    total_students = cur.fetchone()[0]

    cur.execute("""
        SELECT
            COUNT(*) AS total_entries,
            COALESCE(SUM(CASE WHEN logbook_entries.status = 'pending' THEN 1 ELSE 0 END), 0) AS pending_reviews,
            COALESCE(SUM(CASE WHEN logbook_entries.status = 'approved' THEN 1 ELSE 0 END), 0) AS approved_entries,
            COALESCE(SUM(CASE WHEN logbook_entries.status = 'rejected' THEN 1 ELSE 0 END), 0) AS rejected_entries,
            COALESCE(SUM(logbook_entries.hours_worked), 0) AS total_hours_logged
        FROM logbook_entries
        JOIN students ON logbook_entries.student_id = students.student_id
        WHERE students.supervisor_id=%s
    """, (supervisor_id,))

    row = cur.fetchone()
    cur.close()

    return jsonify({
        "success": True,
        "stats": {
            "total_assigned_students": int(total_students),
            "total_entries": int(row[0]),
            "pending_reviews": int(row[1]),
            "approved_entries": int(row[2]),
            "rejected_entries": int(row[3]),
            "total_hours_logged": int(row[4])
        }
    }), 200


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({
        "success": True,
        "message": "Logged out successfully"
    })


@app.route("/api/test_session", methods=["GET"])
def test_session():
    return jsonify({
        "role": session.get("role"),
        "student_id": session.get("student_id"),
        "student_name": session.get("student_name"),
        "supervisor_id": session.get("supervisor_id")
    })

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({
            "success": False,
            "message": "Email address is required"
        }), 400

    cur = mysql.connection.cursor()

    cur.execute(
        "SELECT student_id FROM students WHERE email=%s",
        (email,)
    )

    student = cur.fetchone()

    if not student:
        cur.execute(
            "SELECT supervisor_id FROM supervisor WHERE email=%s",
            (email,)
        )
        supervisor = cur.fetchone()

    cur.close()

    return jsonify({
        "success": True,
        "message": "If an account exists with this email, password reset instructions have been sent."
    })

@app.route("/api/clear_session", methods=["GET"])
def clear_session():
    session.clear()
    return jsonify({
        "success": True,
        "message": "Session cleared"
    })


@app.route("/api/add_entry", methods=["POST"])
@token_required(allowed_roles=["student"])
def api_add_entry(current_user):
    data = request.get_json() or {}

    entry_date = data.get("entry_date")
    activity = data.get("activity")
    hours_worked = data.get("hours_worked")

    if not entry_date or not activity or not hours_worked:
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400

    try:
        hours_worked = int(hours_worked)
    except (ValueError, TypeError):
        return jsonify({
            "success": False,
            "message": "Hours worked must be a valid number"
        }), 400

    cur = mysql.connection.cursor()

    cur.execute(
        """
        INSERT INTO logbook_entries
        (entry_date, activity, hours_worked, status, student_id)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (
            entry_date,
            activity,
            hours_worked,
            "pending",
            current_user["student_id"]
        )
    )

    mysql.connection.commit()
    entry_id = cur.lastrowid
    cur.close()

    return jsonify({
        "success": True,
        "message": "Entry added successfully",
        "entry_id": entry_id
    }), 201


@app.route("/api/view_entries", methods=["GET"])
@token_required(allowed_roles=["student"])
def api_view_entries(current_user):
    """View student entries with optional filtering by status and date range."""
    status_filter = request.args.get("status")
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    query = """
        SELECT
            entry_id,
            entry_date,
            activity,
            hours_worked,
            supervisor_comment,
            status
        FROM logbook_entries
        WHERE student_id=%s
    """
    params = [current_user["student_id"]]

    if status_filter:
        query += " AND status=%s"
        params.append(status_filter)

    if start_date:
        query += " AND entry_date >= %s"
        params.append(start_date)

    if end_date:
        query += " AND entry_date <= %s"
        params.append(end_date)

    query += " ORDER BY entry_date DESC"

    cur = mysql.connection.cursor()
    cur.execute(query, tuple(params))
    rows = cur.fetchall()
    cur.close()

    entries = []
    for row in rows:
        entries.append({
            "entry_id": row[0],
            "entry_date": str(row[1]),
            "activity": row[2],
            "hours_worked": row[3],
            "supervisor_comment": row[4],
            "status": row[5]
        })

    return jsonify(entries), 200


@app.route("/api/export_entries", methods=["GET"])
@token_required(allowed_roles=["student"])
def api_export_entries(current_user):
    """Export student entries as a downloadable CSV report."""
    cur = mysql.connection.cursor()
    cur.execute(
        """
        SELECT
            entry_id,
            entry_date,
            activity,
            hours_worked,
            supervisor_comment,
            status
        FROM logbook_entries
        WHERE student_id=%s
        ORDER BY entry_date ASC
        """,
        (current_user["student_id"],)
    )
    rows = cur.fetchall()
    cur.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Entry ID", "Date", "Activity / Work Done", "Hours Worked", "Status", "Supervisor Comments"])

    for row in rows:
        writer.writerow([
            row[0],
            str(row[1]),
            row[2],
            row[3],
            row[5],
            row[4] or "None"
        ])

    csv_data = output.getvalue()
    filename = f"logbook_student_{current_user['student_id']}_{datetime.date.today()}.csv"

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename={filename}"}
    )


@app.route("/api/entries/<int:entry_id>", methods=["GET"])
@token_required(allowed_roles=["student"])
def api_get_entry(current_user, entry_id):
    cur = mysql.connection.cursor()

    cur.execute(
        """
        SELECT
            entry_id,
            entry_date,
            activity,
            hours_worked,
            supervisor_comment,
            status
        FROM logbook_entries
        WHERE entry_id=%s AND student_id=%s
        """,
        (entry_id, current_user["student_id"])
    )

    entry = cur.fetchone()
    cur.close()

    if not entry:
        return jsonify({
            "success": False,
            "message": "Entry not found"
        }), 404

    return jsonify({
        "success": True,
        "entry": {
            "entry_id": entry[0],
            "entry_date": str(entry[1]),
            "activity": entry[2],
            "hours_worked": entry[3],
            "supervisor_comment": entry[4],
            "status": entry[5]
        }
    })


@app.route("/api/entries/<int:entry_id>", methods=["PUT"])
@token_required(allowed_roles=["student"])
def api_edit_entry(current_user, entry_id):
    data = request.get_json() or {}

    entry_date = data.get("entry_date")
    activity = data.get("activity")
    hours_worked = data.get("hours_worked")

    if not entry_date or not activity or not hours_worked:
        return jsonify({
            "success": False,
            "message": "All fields are required"
        }), 400

    try:
        hours_worked = int(hours_worked)
    except (ValueError, TypeError):
        return jsonify({
            "success": False,
            "message": "Hours worked must be a valid number"
        }), 400

    cur = mysql.connection.cursor()

    cur.execute(
        """
        UPDATE logbook_entries
        SET entry_date=%s,
            activity=%s,
            hours_worked=%s
        WHERE entry_id=%s
        AND student_id=%s
        """,
        (
            entry_date,
            activity,
            hours_worked,
            entry_id,
            current_user["student_id"]
        )
    )

    mysql.connection.commit()
    updated = cur.rowcount
    cur.close()

    if updated == 0:
        return jsonify({
            "success": False,
            "message": "Entry not found"
        }), 404

    return jsonify({
        "success": True,
        "message": "Entry updated successfully"
    })


@app.route("/api/delete_entry/<int:entry_id>", methods=["DELETE"])
@token_required(allowed_roles=["student"])
def delete_entry(current_user, entry_id):
    cur = mysql.connection.cursor()

    cur.execute(
        """
        DELETE FROM logbook_entries
        WHERE entry_id=%s
        AND student_id=%s
        """,
        (
            entry_id,
            current_user["student_id"]
        )
    )

    mysql.connection.commit()
    deleted = cur.rowcount
    cur.close()

    if deleted == 0:
        return jsonify({
            "success": False,
            "message": "Entry not found"
        }), 404

    return jsonify({
        "success": True,
        "message": "Entry deleted successfully"
    })


@app.route("/api/supervisor_dashboard", methods=["GET"])
@token_required(allowed_roles=["supervisor"])
def api_supervisor_dashboard(current_user):
    cur = mysql.connection.cursor()

    cur.execute(
        """
        SELECT student_id, adm_no, full_name, email
        FROM students
        WHERE supervisor_id=%s
        """,
        (current_user["supervisor_id"],)
    )

    students = cur.fetchall()
    cur.close()

    students_list = []
    for student in students:
        students_list.append({
            "student_id": student[0],
            "adm_no": student[1],
            "full_name": student[2],
            "email": student[3]
        })

    return jsonify({
        "success": True,
        "students": students_list
    })


@app.route("/api/supervisor/student_entries/<int:student_id>", methods=["GET"])
@token_required(allowed_roles=["supervisor"])
def api_student_entries(current_user, student_id):
    cur = mysql.connection.cursor()

    cur.execute(
        """
        SELECT student_id
        FROM students
        WHERE student_id=%s
        AND supervisor_id=%s
        """,
        (
            student_id,
            current_user["supervisor_id"]
        )
    )

    student = cur.fetchone()

    if not student:
        cur.close()
        return jsonify({
            "success": False,
            "message": "Student not found or you do not have permission to view this student's entries"
        }), 403

    cur.execute(
        """
        SELECT
            entry_id,
            entry_date,
            activity,
            hours_worked,
            supervisor_comment,
            status
        FROM logbook_entries
        WHERE student_id=%s
        ORDER BY entry_date DESC
        """,
        (student_id,)
    )

    rows = cur.fetchall()
    cur.close()

    entries = []
    for row in rows:
        entries.append({
            "entry_id": row[0],
            "entry_date": str(row[1]),
            "activity": row[2],
            "hours_worked": row[3],
            "supervisor_comment": row[4],
            "status": row[5]
        })

    return jsonify({
        "success": True,
        "entries": entries
    })


@app.route("/api/supervisor/entries/<int:entry_id>", methods=["GET"])
@token_required(allowed_roles=["supervisor"])
def api_get_supervisor_entry(current_user, entry_id):
    cur = mysql.connection.cursor()

    cur.execute("""
        SELECT
            logbook_entries.entry_id,
            logbook_entries.entry_date,
            logbook_entries.activity,
            logbook_entries.hours_worked,
            logbook_entries.supervisor_comment,
            logbook_entries.status,
            students.full_name,
            students.email
        FROM logbook_entries
        JOIN students
            ON logbook_entries.student_id = students.student_id
        WHERE logbook_entries.entry_id = %s
        AND students.supervisor_id = %s
    """, (entry_id, current_user["supervisor_id"]))

    entry = cur.fetchone()
    cur.close()

    if not entry:
        return jsonify({
            "success": False,
            "message": "Entry not found or you do not have permission to view this entry"
        }), 404

    return jsonify({
        "success": True,
        "entry": {
            "entry_id": entry[0],
            "entry_date": str(entry[1]),
            "activity": entry[2],
            "hours_worked": entry[3],
            "supervisor_comment": entry[4],
            "status": entry[5],
            "student_name": entry[6],
            "student_email": entry[7]
        }
    })


@app.route("/api/supervisor/entries/<int:entry_id>", methods=["PUT"])
@token_required(allowed_roles=["supervisor"])
def api_update_entry(current_user, entry_id):
    data = request.get_json() or {}

    comment = data.get("supervisor_comment")
    status = data.get("status")

    if status not in ["approved", "rejected"]:
        return jsonify({
            "success": False,
            "message": "Invalid status. Must be 'approved' or 'rejected'."
        }), 400

    cur = mysql.connection.cursor()

    cur.execute(
        """
        SELECT logbook_entries.entry_id
        FROM logbook_entries
        JOIN students
        ON logbook_entries.student_id = students.student_id
        WHERE logbook_entries.entry_id=%s
        AND students.supervisor_id=%s
        """,
        (
            entry_id,
            current_user["supervisor_id"]
        )
    )

    entry = cur.fetchone()

    if not entry:
        cur.close()
        return jsonify({
            "success": False,
            "message": "Entry not found or you do not have permission to update this entry"
        }), 403

    cur.execute(
        """
        UPDATE logbook_entries
        SET supervisor_comment=%s,
            status=%s
        WHERE entry_id=%s
        """,
        (
            comment,
            status,
            entry_id
        )
    )

    mysql.connection.commit()
    cur.close()

    return jsonify({
        "success": True,
        "message": "Entry reviewed successfully"
    })


# ==========================================
# WEB TEMPLATE / HTML ROUTES
# ==========================================

@app.route("/")
def index():
    if "student_id" in session:
        return redirect(url_for("web_dashboard"))
    elif "supervisor_id" in session:
        return redirect(url_for("web_supervisor_dashboard"))
    return redirect(url_for("web_login"))


@app.route("/login", methods=["GET", "POST"])
def web_login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        cur = mysql.connection.cursor()
        cur.execute("SELECT student_id, adm_no, full_name, email, password FROM students WHERE email=%s", (email,))
        student = cur.fetchone()

        if student and check_password_hash(student[4], password):
            session.clear()
            session["student_id"] = student[0]
            session["student_name"] = student[2]
            session["role"] = "student"
            cur.close()
            return redirect(url_for("web_dashboard"))

        cur.execute("SELECT supervisor_id, full_name, email, password FROM supervisor WHERE email=%s", (email,))
        supervisor = cur.fetchone()

        if supervisor and check_password_hash(supervisor[3], password):
            session.clear()
            session["supervisor_id"] = supervisor[0]
            session["supervisor_name"] = supervisor[1]
            session["role"] = "supervisor"
            cur.close()
            return redirect(url_for("web_supervisor_dashboard"))

        cur.close()
        return render_template("login.html", error="Invalid email or password")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def web_register():
    if request.method == "POST":
        adm_no = request.form.get("adm_no")
        full_name = request.form.get("full_name")
        email = request.form.get("email")
        password = request.form.get("password")
        check_password = request.form.get("check_password")
        supervisor_id = request.form.get("supervisor_id")

        if password != check_password:
            cur = mysql.connection.cursor()
            cur.execute("SELECT supervisor_id, full_name FROM supervisor")
            supervisors = cur.fetchall()
            cur.close()
            return render_template("register.html", supervisors=supervisors, error="Passwords do not match")

        password_hash = generate_password_hash(password)
        cur = mysql.connection.cursor()
        cur.execute("SELECT student_id FROM students WHERE email=%s OR adm_no=%s", (email, adm_no))
        if cur.fetchone():
            cur.execute("SELECT supervisor_id, full_name FROM supervisor")
            supervisors = cur.fetchall()
            cur.close()
            return render_template("register.html", supervisors=supervisors, error="Student already exists")

        cur.execute(
            "INSERT INTO students (adm_no, full_name, email, password, supervisor_id, role) VALUES (%s, %s, %s, %s, %s, 'student')",
            (adm_no, full_name, email, password_hash, supervisor_id)
        )
        mysql.connection.commit()
        cur.close()
        return redirect(url_for("web_login"))

    cur = mysql.connection.cursor()
    cur.execute("SELECT supervisor_id, full_name FROM supervisor ORDER BY full_name ASC")
    supervisors = cur.fetchall()
    cur.close()
    return render_template("register.html", supervisors=supervisors)


@app.route("/dashboard")
def web_dashboard():
    if "student_id" not in session or session.get("role") != "student":
        return redirect(url_for("web_login"))
    return render_template("dashboard.html", name=session.get("student_name", "Student"))


@app.route("/supervisor_dashboard")
def web_supervisor_dashboard():
    if "supervisor_id" not in session or session.get("role") != "supervisor":
        return redirect(url_for("web_login"))

    cur = mysql.connection.cursor()
    cur.execute("SELECT student_id, adm_no, full_name, email FROM students WHERE supervisor_id=%s", (session["supervisor_id"],))
    students = cur.fetchall()
    cur.close()
    return render_template("supervisor_dashboard.html", name=session.get("supervisor_name", "Supervisor"), students=students)


@app.route("/add_entry", methods=["GET", "POST"])
def web_add_entry():
    if "student_id" not in session or session.get("role") != "student":
        return redirect(url_for("web_login"))

    if request.method == "POST":
        entry_date = request.form.get("entry_date")
        activity = request.form.get("activity")
        hours_worked = request.form.get("hours_worked")

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO logbook_entries (entry_date, activity, hours_worked, status, student_id) VALUES (%s, %s, %s, 'pending', %s)",
            (entry_date, activity, hours_worked, session["student_id"])
        )
        mysql.connection.commit()
        cur.close()
        return redirect(url_for("web_view_entries"))

    return render_template("add_entry.html")


@app.route("/view_entries")
def web_view_entries():
    if "student_id" not in session or session.get("role") != "student":
        return redirect(url_for("web_login"))

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT entry_id, entry_date, activity, hours_worked, supervisor_comment, status FROM logbook_entries WHERE student_id=%s ORDER BY entry_date DESC",
        (session["student_id"],)
    )
    entries = cur.fetchall()
    cur.close()
    return render_template("view_entries.html", entries=entries)


@app.route("/edit_entry/<int:entry_id>", methods=["GET", "POST"])
def web_edit_entry(entry_id):
    if "student_id" not in session or session.get("role") != "student":
        return redirect(url_for("web_login"))

    cur = mysql.connection.cursor()
    if request.method == "POST":
        entry_date = request.form.get("entry_date")
        activity = request.form.get("activity")
        hours_worked = request.form.get("hours_worked")

        cur.execute(
            "UPDATE logbook_entries SET entry_date=%s, activity=%s, hours_worked=%s WHERE entry_id=%s AND student_id=%s",
            (entry_date, activity, hours_worked, entry_id, session["student_id"])
        )
        mysql.connection.commit()
        cur.close()
        return redirect(url_for("web_view_entries"))

    cur.execute("SELECT entry_id, entry_date, activity, hours_worked FROM logbook_entries WHERE entry_id=%s AND student_id=%s", (entry_id, session["student_id"]))
    entry = cur.fetchone()
    cur.close()

    if not entry:
        return redirect(url_for("web_view_entries"))

    return render_template("edit_entry.html", entry=entry)


@app.route("/delete_entry/<int:entry_id>")
def web_delete_entry(entry_id):
    if "student_id" not in session or session.get("role") != "student":
        return redirect(url_for("web_login"))

    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM logbook_entries WHERE entry_id=%s AND student_id=%s", (entry_id, session["student_id"]))
    mysql.connection.commit()
    cur.close()
    return redirect(url_for("web_view_entries"))


@app.route("/student_entries/<int:student_id>")
def web_student_entries(student_id):
    if "supervisor_id" not in session or session.get("role") != "supervisor":
        return redirect(url_for("web_login"))

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT entry_id, entry_date, activity, hours_worked, supervisor_comment, status FROM logbook_entries WHERE student_id=%s ORDER BY entry_date DESC",
        (student_id,)
    )
    entries = cur.fetchall()
    cur.close()
    return render_template("student_entries.html", entries=entries)


@app.route("/review_entry/<int:entry_id>", methods=["GET", "POST"])
def web_review_entry(entry_id):
    if "supervisor_id" not in session or session.get("role") != "supervisor":
        return redirect(url_for("web_login"))

    cur = mysql.connection.cursor()
    if request.method == "POST":
        comment = request.form.get("supervisor_comment")
        status = request.form.get("status")

        cur.execute(
            """
            UPDATE logbook_entries
            JOIN students ON logbook_entries.student_id = students.student_id
            SET logbook_entries.supervisor_comment=%s, logbook_entries.status=%s
            WHERE logbook_entries.entry_id=%s AND students.supervisor_id=%s
            """,
            (comment, status, entry_id, session["supervisor_id"])
        )
        mysql.connection.commit()
        cur.close()
        return redirect(url_for("web_supervisor_dashboard"))

    cur.execute(
        """
        SELECT logbook_entries.entry_date, logbook_entries.activity, logbook_entries.hours_worked, logbook_entries.supervisor_comment, logbook_entries.status
        FROM logbook_entries
        JOIN students ON logbook_entries.student_id = students.student_id
        WHERE logbook_entries.entry_id=%s AND students.supervisor_id=%s
        """,
        (entry_id, session["supervisor_id"])
    )
    entry = cur.fetchone()
    cur.close()

    if not entry:
        return redirect(url_for("web_supervisor_dashboard"))

    return render_template("review_entry.html", entry=entry)


@app.route("/logout")
def web_logout():
    session.clear()
    return redirect(url_for("web_login"))


if __name__ == "__main__":
    print("MY APP.PY IS RUNNING")
    app.run(debug=True)

