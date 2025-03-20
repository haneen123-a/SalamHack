from flask import Blueprint, request, jsonify, render_template, redirect, url_for, make_response
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
import logging as log

auth_bp = Blueprint("auth", __name__)

DB_PATH = "automated.sqlite"
JWT_SECRET = os.environ.get("JWT_SECRET") or "your-jwt-secret-key"

def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            fname TEXT,
            lname TEXT,
            education TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        """)
        conn.commit()
        conn.close()
        log.info("Database initialized or already exists.")
    except sqlite3.Error as e:
        log.error(f"Database initialization failed: {e}")

def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('auth.login'))

        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            current_user = get_user_by_username(data['username'])
            if not current_user:
                return redirect(url_for('auth.login'))
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError, jwt.exceptions.DecodeError):
            resp = make_response(redirect(url_for('auth.login')))
            resp.delete_cookie('token')
            return resp

        return f(current_user, *args, **kwargs)
    return decorated_function

def get_user_by_username(username):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()
        return user
    except sqlite3.Error as e:
        log.error(f"Database error fetching user: {e}")
        return None

@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        data = request.get_json()
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        fname = data.get("fname", "")
        lname = data.get("lname", "")
        education = data.get("education", "")

        if not username or not email or not password:
            return jsonify({"error": "Username, email, and password are required."}), 400

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, password, fname, lname, education) VALUES (?, ?, ?, ?, ?, ?)",
                (username, email, hashed_password, fname, lname, education)
            )
            conn.commit()
            conn.close()
            return jsonify({"message": "Signup successful! Redirecting to login...", "redirect": url_for('auth.login')}), 201
        except sqlite3.IntegrityError:
            return jsonify({"error": "Username or email already exists."}), 400
        except sqlite3.Error as e:
            log.error(f"Database error during signup: {e}")
            return jsonify({"error": f"A database error occurred: {str(e)}"}), 500
        except Exception as e:
            log.exception("An unexpected error occurred during signup")
            return jsonify({"error": f"An error occurred: {str(e)}"}), 500

    return render_template("signup.html")

@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.get_json()
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            return jsonify({"error": "Username and password are required."}), 400

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            user = cursor.fetchone()
            conn.close()

            if user and check_password_hash(user[3], password):
                token = jwt.encode({
                    'username': username,
                    'exp': datetime.now(timezone.utc) + timedelta(days=1),
                    'iat': datetime.now(timezone.utc)
                }, JWT_SECRET, algorithm="HS256")

                resp = make_response(jsonify({"message": "Login successful!"}))
                resp.set_cookie('token', token, httponly=True, secure=False, samesite='Strict')
                return resp, 200
            else:
                return jsonify({"error": "Invalid username or password."}), 401
        except sqlite3.Error as e:
            log.error(f"Database error during login: {e}")
            return jsonify({"error": f"A database error occurred: {str(e)}"}), 500
        except Exception as e:
            log.exception("An unexpected error occurred during login")
            return jsonify({"error": f"An error occurred: {str(e)}"}), 500

    return render_template("login.html")

@auth_bp.route("/logout")
def logout():
    resp = make_response(redirect(url_for('auth.login')))
    resp.delete_cookie('token')
    return resp

@auth_bp.route("/update-profile", methods=["GET", "POST"])
@token_required
def update_profile(current_user):
    if request.method == "POST":
        data = request.get_json()
        fname = data.get("fname")
        lname = data.get("lname")
        email = data.get("email")
        username = data.get("username")
        education = data.get("education")

        if not all([fname, lname, email, username, education]):
            return jsonify({"error": "All fields are required"}), 400

        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            if username != current_user[1]: 
                cursor.execute("SELECT id FROM users WHERE username = ? AND id != ?", (username, current_user[0]))
                if cursor.fetchone():
                    return jsonify({"error": "Username already exists"}), 400
                    
            if email != current_user[2]:  
                cursor.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, current_user[0]))
                if cursor.fetchone():
                    return jsonify({"error": "Email already exists"}), 400

            cursor.execute("""
                UPDATE users 
                SET fname = ?, lname = ?, email = ?, username = ?, education = ?
                WHERE id = ?
            """, (fname, lname, email, username, education, current_user[0]))
            
            conn.commit()
            conn.close()

            return jsonify({
                "message": "Profile updated successfully",
                "user": {
                    "username": username,
                    "email": email,
                    "fname": fname,
                    "lname": lname,
                    "education": education
                }
            }), 200

        except sqlite3.Error as e:
            log.error(f"Database error during profile update: {e}")
            return jsonify({"error": f"A database error occurred: {str(e)}"}), 500
        except Exception as e:
            log.exception("An unexpected error occurred during profile update")
            return jsonify({"error": f"An error occurred: {str(e)}"}), 500

    return jsonify({
        "username": current_user[1],
        "email": current_user[2],
        "fname": current_user[4],
        "lname": current_user[5],
        "education": current_user[6]
    }), 200