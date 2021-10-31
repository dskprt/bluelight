from flask import Flask
from flask import jsonify
from flask import request
from flask import redirect
from flask import render_template

from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import verify_jwt_in_request

import os, psutil, json, hashlib, base64

config = None
default_config = {
    "jwt-secret": "SECRETKEY",
    "users": [
        {
            "username": "DEFAULT_USER",
            "password": "DEFAULT_PASS",
            "salt": "DEFAULT_SALT"
        }
    ]
}

def setup_config():
    global config

    if os.path.exists(os.environ["HOME"] + "/.bluelight/config.json"):
        with open(os.environ["HOME"] + "/.bluelight/config.json", "r") as f:
            config = json.load(f)
    else:
        os.makedirs(os.environ["HOME"] + "/.bluelight", exist_ok=True)
        with open(os.environ["HOME"] + "/.bluelight/config.json", "w") as f:
            default_config["jwt-secret"] = input("JWT Secret >> ")
            
            username = input("Username >> ")
            password = input("Password >> ")

            salt = os.urandom(64)

            username_hash = hashlib.pbkdf2_hmac(
                "sha256",
                username.encode("utf-8"),
                salt,
                200000,
                128
            )

            password_hash = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                200000,
                128
            )

            default_config["users"][0]["username"] = base64.b64encode(username_hash).decode('UTF-8')
            default_config["users"][0]["password"] = base64.b64encode(password_hash).decode('UTF-8')
            default_config["users"][0]["salt"] = base64.b64encode(salt).decode('UTF-8')
            
            json.dump(default_config, f)
            config = default_config

setup_config()

process = psutil.Process(os.getpid())
app = Flask("main")

app.config["JWT_SECRET_KEY"] = config["jwt-secret"]
jwt = JWTManager(app)

@app.route("/", methods=["GET"])
@jwt_required(optional=True)
def root():
    current_identity = get_jwt_identity()

    if current_identity:
        return redirect("/status")
    else:
        return redirect("/login")

@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    salt = base64.b64decode(config["users"][0]["salt"])

    username_hash = hashlib.pbkdf2_hmac(
        "sha256",
        username.encode("utf-8"),
        salt,
        200000,
        128
    )

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000,
        128
    )

    if username != base64.b64decode(config["users"][0]["username"]) or password != base64.b64decode(config["users"][0]["password"]):
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route("/status", methods=["GET"])
@jwt_required()
def status():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

def main():
    port = 5000

    if "PORT" in os.environ:
        port = int(os.environ["PORT"])

    app.run(host="0.0.0.0", port=port)
