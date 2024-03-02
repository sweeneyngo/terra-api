from flask import jsonify
from thefuzz import process
import json
import csv
import datetime as dt
import bcrypt
import dotenv
import os
from bson import json_util
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
)
from pymongo import MongoClient
from pymongo.server_api import ServerApi

dotenv.load_dotenv()
uri = os.getenv("MONGO_URI")
client = MongoClient(uri, server_api=ServerApi("1"))


def authenticate(username, password):
    user = client.terra.users.find_one({"username": username})
    if user and bcrypt.checkpw(password.encode("utf-8"), user["password"]):
        return {"username": user["username"]}


def register(email, username, password):

    if email is None or username is None or password is None:
        response = {
            "meta": {
                "code": f"{400} Bad Request",
                "status": "Please provide an email, username, and password.",
                # Generate today's date
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response)

    if client.terra.users.find_one({"username": username}) is not None:
        response = {
            "meta": {
                "code": f"{409} Conflict",
                "status": "Username already exists.",
                # Generate today's date
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response)

    # Create a new user
    user = {
        "email": email,
        "username": username,
        "password": bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()),
        "roles": ["user"],
        "dateRegistered": dt.datetime.now(),
        "dateLastLoggedIn": dt.datetime.now(),
        "preferences": {
            "timezone": "UTC",
            "theme": "light",
            "language": "en",
        },
        "accessToken": None,
        "refreshToken": None,
        "accessExpiry": None,
        "refreshExpiry": None,
    }

    # Send to MongoDB
    data = client.terra.users.insert_one(user)
    if not data:
        response = {
            "meta": {
                "code": f"{500} Internal Server Error",
                "status": "Failed to register user.",
                # Generate today's date
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response)

    # Send a response
    response = {
        "meta": {
            "code": f"{201} Created",
            "status": "Successfully registered.",
            # Generate today's date
            "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "response": user,
        "status": "Success",
    }
    return jsonify(json.loads(json_util.dumps(response)))


def login(username, password):
    user = authenticate(username, password)
    if not user:
        response = {
            "meta": {
                "code": f"{401} Unauthorized",
                "status": "Invalid username or password.",
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return response

    access_expiry = dt.timedelta(days=1)
    refresh_expiry = dt.timedelta(days=30)
    access_token = create_access_token(identity=user, expires_delta=access_expiry)
    refresh_token = create_refresh_token(identity=user, expires_delta=refresh_expiry)

    # Send to MongoDB
    client.terra.users.update_one(
        {"username": user["username"]},
        {
            "$set": {
                "dateLastLoggedIn": dt.datetime.now(),
                "accessToken": access_token,
                "refreshToken": refresh_token,
                "accessExpiry": int(access_expiry.total_seconds()),
                "refreshExpiry": int(refresh_expiry.total_seconds()),
            }
        },
    )

    # Send a response
    response = {
        "meta": {
            "code": f"{200} OK",
            "status": "Successfully logged in.",
            # Generate today's date
            "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "response": {
            "username": user["username"],
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "accessExpiry": access_expiry.total_seconds(),
            "refreshExpiry": refresh_expiry.total_seconds(),
        },
        "status": "Success",
    }

    return json.loads(json_util.dumps(response))


def refresh():
    current_user = get_jwt_identity()
    access_expiry = dt.timedelta(days=1)
    access_token = create_access_token(
        identity=current_user, expires_delta=access_expiry
    )

    # Send a response
    response = {
        "meta": {
            "code": f"{200} OK",
            "status": "Successfully refreshed access token.",
            "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "response": {
            "username": current_user["username"],
            "accessToken": access_token,
            "accessExpiry": access_expiry.total_seconds(),
        },
        "status": "Success",
    }

    return json.loads(json_util.dumps(response))


def get_users():
    users = client.terra.users.find()
    response = {
        "meta": {
            "code": f"{200} OK",
            "status": "Successfully retrieved all users.",
            "total": client.terra.users.count_documents({}),
            # Generate today's date
            "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "response": users,
        "status": "Success",
    }
    return json.loads(json_util.dumps(response))


def get_weapons(options: dict = {}):
    """Get all weapons from MongoDB."""

    # Check if options matches the schema
    weapons = client.terra.weapons.find(options)
    if weapons is None:
        response = {
            "meta": {
                "code": f"{404} Not Found",
                "status": "No weapons found in database. Ensure params are correct.",
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return response

    response = {
        "meta": {
            "code": f"{200} OK",
            "status": "Successfully retrieved all weapons.",
            "total": client.terra.weapons.count_documents({}),
            "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "response": weapons,
        "status": "Success",
    }
    return json.loads(json_util.dumps(response))


def obtain(user, request):
    """Given a list of { gameID, timestamp, isObtained }, update the user's collection with the obtained weapons."""

    if request.json is None:
        response = {
            "meta": {
                "code": f"{400} Bad Request",
                "status": "Please provide a payload of { gameID, timestamp, isObtained }.",
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return response

    if user is None:
        response = {
            "meta": {
                "code": f"{401} Unauthorized",
                "status": "Please log in to use this feature.",
                # Generate today's date
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return response

    user_id = client.terra.users.find_one({"username": user["username"]})["_id"]

    obtained_weapons = []
    unobtained_weapons = []

    for entry in request.json:
        if entry["isObtained"] is True:
            obtained_weapons.append(
                {
                    "gameId": entry["gameId"],
                    "timestamp": dt.datetime.strptime(
                        entry["timestamp"], "%m/%d/%y, %H:%M:%S:%f"
                    ),
                }
            )
        else:
            unobtained_weapons.append(entry["gameId"])

    # Remove all unobtained weapons from the user's collection
    collection = client.terra.collections.find_one({"user_id": user_id})
    if unobtained_weapons and collection:
        client.terra.collections.update_one(
            {"user_id": user_id},
            {"$pull": {"ids.weapon_ids": {"gameId": {"$in": unobtained_weapons}}}},
        )

    # Update users' collections with obtained weapons & timestamp
    if obtained_weapons and collection:
        client.terra.collections.update_one(
            {"user_id": user_id},
            {
                "$push": {
                    "ids.weapon_ids": {
                        "$each": [
                            {
                                "gameId": entry["gameId"],
                                "dateObtained": entry["timestamp"],
                            }
                            for entry in obtained_weapons
                        ]
                    }
                }
            },
        )
    elif obtained_weapons and not collection:
        client.terra.collections.insert_one(
            {
                "user_id": user_id,
                "ids": {
                    "weapon_ids": [
                        {
                            "gameId": entry["gameId"],
                            "dateObtained": entry["timestamp"],
                        }
                        for entry in obtained_weapons
                    ],
                },
                "dateSubmitted": dt.datetime.now(),
            }
        )

    data = {
        "user_id": user_id,
        "ids": {
            "weapon_ids": [
                {
                    "gameId": entry["gameId"],
                    "dateObtained": entry["timestamp"],
                    "isObtained": True,
                }
                for entry in obtained_weapons
            ],
        },
        "dateSubmitted": dt.datetime.now(),
    }

    data["ids"]["weapon_ids"].extend(
        [
            {"gameId": weapon, "dateObtained": None, "isObtained": False}
            for weapon in unobtained_weapons
        ]
    )

    response = {
        "meta": {
            "code": f"{201} Created",
            "status": "Successfully obtained weapons.",
            "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "response": data,
        "status": "Success",
    }
    return json.loads(json_util.dumps(response))


def get_collection(user):
    """Get a user's collection in JSON.

    Create a view (join) of the user's collection ("obtained IDs") & associated weapon data.
    """

    if user is None:
        response = {
            "meta": {
                "code": f"{401} Unauthorized",
                "status": "Please log in to use this feature.",
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return response

    user_id = client.terra.users.find_one({"username": user["username"]})["_id"]

    # Get the user's collection
    collection = client.terra.collections.find_one({"user_id": user_id})

    if collection is None:
        response = {
            "meta": {
                "code": f"{404} Not Found",
                "status": "No collection found for this user.",
                # Generate today's date
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return response

    # Map user's collection with weapon data
    weapon_ids = [str(tup["gameId"]) for tup in collection["ids"]["weapon_ids"]]
    weapons = client.terra.weapons.find({"gameId": {"$in": weapon_ids}})

    data = []
    for weapon in weapons:
        for weapon_id in weapon_ids:
            if weapon["gameId"] == weapon_id:
                weapon["isObtained"] = True
                data.append(weapon)
                break

    response = {
        "meta": {
            "code": f"{200} OK",
            "status": "Successfully retrieved user's collection.",
            "total": len(collection["ids"]["weapon_ids"]),
            "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "response": data,
        "status": "Success",
    }
    return json.loads(json_util.dumps(response))


# @dev-only
def bulk_dump_obtain(user, request):

    if request.json is None or request.json.get("weapon_ids") is None:
        response = {
            "meta": {
                "code": f"{400} Bad Request",
                "status": "Please provide a payload of IDs.",
                # Generate today's date
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response)

    if user is None:
        response = {
            "meta": {
                "code": f"{401} Unauthorized",
                "status": "Please log in to use this feature.",
                # Generate today's date
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response)

    user_id = client.terra.users.find_one({"username": user["username"]})["_id"]
    weapon_ids = request.json.get("weapon_ids")
    data = {
        "user_id": user_id,
        "ids": {
            "weapon_ids": [
                {"gameId": str(weapon), "dateObtained": dt.datetime.now()}
                for weapon in weapon_ids
            ],
        },
        "dateSubmitted": dt.datetime.now(),
    }

    # Update users' collections with obtained weapons and timestamp
    if client.terra.collections.find_one({"user_id": user_id}):
        client.terra.collections.update_one(
            {"user_id": user_id},
            {
                "$push": {
                    "ids.weapon_ids": {
                        "$each": data["ids"]["weapon_ids"],
                    }
                }
            },
        )
    else:
        client.terra.collections.insert_one(data)

    response = {
        "meta": {
            "code": f"{201} Created",
            "status": "Successfully obtained weapons.",
            "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "response": data,
        "status": "Success",
    }
    return json.loads(json_util.dumps(response))


# @deprecated
def get_weapon(weapon_name: str):
    """Get a weapon in JSON by name."""
    threshold = 82
    try:
        with open("db/weapons.json", "r") as file:
            data = json.load(file)
            result = None

            # Use fuzzywuzzy on all the weapons to find the closest match
            best_weapon_name, best_score = process.extractOne(
                weapon_name, [entry["name"] for entry in data.values()]
            )

            if best_score < threshold:
                raise KeyError(f"{weapon_name} not found in database.")

            for _, entry in data.items():
                if entry["name"] == best_weapon_name:
                    result = entry

            # Send a response
            response = {
                "meta": {
                    "code": f"{200} OK",
                    "status": f"Successfully retrieved {best_weapon_name}.",
                    "fuzzyScore": best_score,
                    "correctedName": best_weapon_name,
                    "originalName": weapon_name,
                    # Generate today's date
                    "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                },
                "response": result,
                "status": "Success",
            }

            return jsonify(response)

    except FileNotFoundError:
        response = {
            "meta": {
                "code": f"{500} Internal Server Error",
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response)
    except KeyError:
        response = {
            "meta": {
                "code": f"{404} Not Found",
                "status": f"{weapon_name} not found in database.",
                # Generate today's date
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response)


# @deprecated
def obtain_weapon(user, request):
    """Obtain weapon in JSON, return the weapon data."""
    try:
        if user is None:
            response = {
                "meta": {
                    "code": f"{401} Unauthorized",
                    "status": "Please log in to use this feature.",
                    # Generate today's date
                    "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                },
                "response": None,
                "status": "Error",
            }
            return jsonify(response)

        # Assign the userID & weaponIDs in Collections relation
        user_id = client.terra.users.find_one({"username": user["username"]})["_id"]
        weapon_id = request.json.get("weapon_id")

        # Update the user's collection, update weapon id to an id object id: { weapon_ids: [] }
        data = {
            "user_id": user_id,
            "ids": {
                "weapon_ids": [{"id": weapon_id, "dateObtained": dt.datetime.now()}],
            },
            "dateSubmitted": dt.datetime.now(),
        }

        # Modify current user's collection if collection exists
        if client.terra.collections.find_one({"user_id": user_id}):
            client.terra.collections.update_one(
                {"user_id": user_id},
                {
                    "$push": {
                        "ids.weapon_ids": {
                            "id": weapon_id,
                            "dateObtained": dt.datetime.now(),
                        }
                    }
                },
            )
        else:
            # Create a new collection if it does not exist
            client.terra.collections.insert_one(
                {
                    "user_id": user_id,
                    "ids": {
                        "weapon_ids": [
                            {"id": weapon_id, "dateObtained": dt.datetime.now()}
                        ],
                    },
                    "dateSubmitted": dt.datetime.now(),
                }
            )

        response = {
            "meta": {
                "code": f"{201} Created",
                "status": "Successfully obtained weapon.",
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": data,
            "status": "Success",
        }

        return jsonify(json.loads(json_util.dumps(response)))

    except FileNotFoundError:
        response = {
            "meta": {
                "code": f"{500} Internal Server Error",
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response)
    except KeyError:
        response = {
            "meta": {
                "code": f"{404} Not Found",
                "status": f"{weapon_name} not found in database.",
                # Generate today's date
                "dateRetrieved": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            },
            "response": None,
            "status": "Error",
        }
        return jsonify(response)
