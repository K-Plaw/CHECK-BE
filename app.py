# Flask: Core web framework to create the API
from flask import Flask, request, jsonify

# Flask-CORS: Enables Cross-Origin Resource Sharing so frontend (on different port/domain) can call this backend
from flask_cors import CORS

# Flask-JWT-Extended: Adds JSON Web Token (JWT) authentication for secure access to protected routes
from flask_jwt_extended import (
    JWTManager,           # Manages JWT setup
    create_access_token,  # Creates JWT token after login
    jwt_required,         # Decorator to protect routes (only allow if token is valid)
    get_jwt_identity      # Gets user ID from the JWT token
)

# Flask-Bcrypt: Securely hashes passwords (never store plain text passwords!)
from flask_bcrypt import Bcrypt

# sqlite3: Built-in Python module to interact with SQLite database (lightweight, file-based)
import sqlite3

# os: To read environment variables (like PORT) when deploying
import os


# ======================================
# 🛠️ CREATE FLASK APP
# ======================================
app = Flask(__name__)
CORS(app)  # Enable CORS

# ======================================
# 🔐 CONFIGURATION
# ======================================
app.config["SECRET_KEY"] = "supersecretkey"
app.config["JWT_SECRET_KEY"] = "jwtsecretkey"

bcrypt = Bcrypt(app)
jwt = JWTManager(app)


# ======================================
# 🗄️ DATABASE INITIALIZATION
# ======================================
def init_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT,
            priority TEXT,
            status INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

init_db()


# ======================================
# 🏠 BASE ROUTE
# ======================================
@app.route("/")
def home():
    return {"message": "Welcome to Check TodoList App Backend API"}


# ======================================
# 🔐 AUTH ROUTES
# ======================================
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not all([username, email, password]):
        return jsonify({"error": "Missing required fields"}), 400

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    try:
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute(
            "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
            (username, email, pw_hash)
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or Email already exists"}), 400


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, password FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()

    if user and bcrypt.check_password_hash(user["password"], password):
        token = create_access_token(identity=str(user["id"]))  # 🔑 FIXED
        return jsonify({"token": token}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401


# ======================================
# 📝 TASK ROUTES
# ======================================
@app.route("/tasks", methods=["GET"])
@jwt_required()
def get_tasks():
    user_id = int(get_jwt_identity())  # 🔑 FIXED
    try:
        conn = sqlite3.connect("database.db")
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("""
            SELECT id, title, description, category, priority, status
            FROM tasks
            WHERE user_id = ?
        """, (user_id,))
        rows = c.fetchall()
        conn.close()
        tasks = [dict(row) for row in rows]
        return jsonify(tasks), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/tasks", methods=["POST"])
@jwt_required()
def add_task():
    user_id = int(get_jwt_identity())  # 🔑 FIXED
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    title = data.get("title")
    description = data.get("description", "")
    category = data.get("category", "Personal")
    priority = data.get("priority", "Medium")
    status = int(data.get("status", 0))

    if not title or not isinstance(title, str) or not title.strip():
        return jsonify({"error": "Title is required and must be a non-empty string"}), 400

    valid_categories = ["Work", "Personal", "Study", "Shopping", "Other"]
    valid_priorities = ["Low", "Medium", "High"]

    if category not in valid_categories:
        return jsonify({"error": "Invalid category"}), 400
    if priority not in valid_priorities:
        return jsonify({"error": "Invalid priority"}), 400

    try:
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("""
            INSERT INTO tasks (user_id, title, description, category, priority, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, title, description, category, priority, status))
        conn.commit()
        task_id = c.lastrowid
        conn.close()
        return jsonify({"message": "Task added", "id": task_id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/tasks/<int:task_id>", methods=["PUT"])
@jwt_required()
def update_task(task_id):
    user_id = int(get_jwt_identity())  # 🔑 FIXED
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid JSON"}), 400

    title = data.get("title")
    description = data.get("description", "")
    category = data.get("category", "Personal")
    priority = data.get("priority", "Medium")
    status = int(data.get("status", 0))

    if not title or not isinstance(title, str) or not title.strip():
        return jsonify({"error": "Title is required and must be a string"}), 400

    valid_categories = ["Work", "Personal", "Study", "Shopping", "Other"]
    valid_priorities = ["Low", "Medium", "High"]

    if category not in valid_categories:
        return jsonify({"error": "Invalid category"}), 400
    if priority not in valid_priorities:
        return jsonify({"error": "Invalid priority"}), 400

    try:
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("""
            UPDATE tasks
            SET title = ?, description = ?, category = ?, priority = ?, status = ?
            WHERE id = ? AND user_id = ?
        """, (title, description, category, priority, status, task_id, user_id))
        conn.commit()
        conn.close()

        if c.rowcount == 0:
            return jsonify({"error": "Task not found or unauthorized"}), 404

        return jsonify({"message": "Task updated"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/tasks/<int:task_id>", methods=["DELETE"])
@jwt_required()
def delete_task(task_id):
    user_id = int(get_jwt_identity())  # 🔑 FIXED
    try:
        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, user_id))
        conn.commit()
        conn.close()

        if c.rowcount == 0:
            return jsonify({"error": "Task not found or unauthorized"}), 404

        return jsonify({"message": "Task deleted"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ======================================
# 🚀 RUN THE APP
# ======================================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
