#!/usr/bin/env python

import os
from flask_cors import CORS
from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity
from datetime import timedelta, datetime
from controller import (
    login,
    register,
    refresh,
    get_users,
    obtain,
    obtain_weapon,
    get_weapons,
    get_weapon,
    get_collection,
)

app = Flask(__name__)
CORS(app)

app.config["SECRET_KEY"] = "super-secret"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=30)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)


@app.route("/", methods=["GET"])
def home():
    return "♥ s(hr)imple API for Terraria."


@app.route("/login", methods=["POST"])
def login_r():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    return login(username, password), 200


@app.route("/register", methods=["POST"])
def register_r():
    email = request.json.get("email", None)
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    return register(email, username, password), 200


@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh_r():
    return refresh(), 200


@app.route("/users", methods=["GET"])
@jwt_required()
def users_r():
    return get_users(), 200


@app.route("/weapons", methods=["GET"])
def weapons_r():

    options = {}
    for key in request.args:
        options[key] = request.args.get(key)
    weapons = get_weapons(options)
    return weapons, 200


@app.route("/weapons/<weapon_name>", methods=["GET"])
def weapon_r(weapon_name):
    weapon = get_weapon(weapon_name)
    return weapon, 200


@app.route("/obtain/<weapon_id>", methods=["POST"])
@jwt_required()
def obtain_weapon_r():
    try:
        current_user = get_jwt_identity()
        weapon = obtain_weapon(current_user, request)
        return weapon, 200
    except Exception as e:
        response = {
            "meta": {
                "code": f"{401} Unauthorized",
                "status": "User session has expired.",
                # Generate today's date
                "dateRetrieved": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response), 401


@app.route("/obtain", methods=["POST"])
@jwt_required()
def obtain_r():
    try:
        current_user = get_jwt_identity()
        result = obtain(current_user, request)
        return result, 200
    except Exception as e:
        print(e)
        response = {
            "meta": {
                "code": f"{401} Unauthorized",
                "status": "User session has expired.",
                # Generate today's date
                "dateRetrieved": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response), 401


@app.route("/collection", methods=["GET"])
@jwt_required()
def collection_r():
    try:
        current_user = get_jwt_identity()
        result = get_collection(current_user)
        return result, 200
    except Exception as e:
        print(e)
        response = {
            "meta": {
                "code": f"{401} Unauthorized",
                "status": "User session has expired.",
                # Generate today's date
                "dateRetrieved": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response), 401
