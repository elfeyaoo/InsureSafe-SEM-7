# db.py - MongoDB helpers
import os, hashlib, hmac, secrets
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime

# ---------------- MongoDB Connection ---------------- #
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["insure_db"]

# ---------------- Collections ---------------- #
users_col = db["users"]
policies_col = db["policies"]
user_policies_col = db["user_policies"]
claims_col = db["claims"]

# ---------------- Password Hashing ---------------- #
def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
    return pwd_hash, salt

def verify_password(stored_hash, stored_salt, password_attempt):
    attempt_hash, _ = hash_password(password_attempt, stored_salt)
    return hmac.compare_digest(stored_hash, attempt_hash)

# ---------------- User Functions ---------------- #
def init_db():
    users_col.create_index("email", unique=True)
    policies_col.create_index("name", unique=True)
    create_default_admin()

def add_user(
    name,
    email,
    password,
    id_photo_path=None,
    phone=None,
    address=None,
    age=None,
    annual_income=None,
    is_admin=False
):
    pwd_hash, salt = hash_password(password)
    user = {
        "name": name,
        "email": email,
        "password_hash": pwd_hash,
        "salt": salt,
        "id_photo_path": id_photo_path,
        "phone": phone,
        "address": address,
        "age": int(age) if age else None,
        "annual_income": int(annual_income) if annual_income else None,
        "is_admin": is_admin,
        "is_active": True,
        "created_at": datetime.utcnow()
    }
    return users_col.insert_one(user).inserted_id

def get_user_by_email(email):
    return users_col.find_one({"email": email})

def get_user_by_id(user_id):
    if isinstance(user_id, str):
        user_id = ObjectId(user_id)
    return users_col.find_one({"_id": user_id})

def authenticate_user(email, password):
    user = get_user_by_email(email)
    if user and verify_password(user["password_hash"], user["salt"], password):
        return user
    return None

def toggle_user_active(uid):
    from bson import ObjectId
    try:
        oid = ObjectId(uid)
    except:
        oid = uid
    user = users_col.find_one({"_id": oid})
    if not user:
        return None
    new_status = not user.get("is_active", True)  # default True
    users_col.update_one({"_id": oid}, {"$set": {"is_active": new_status}})
    return new_status

# ---------------- Policy Functions ---------------- #
def add_policy(name, description, requirements="", sum_insured=0):
    policy = {
        "name": name,
        "description": description,
        "requirements": requirements,
        "sum_insured": sum_insured,
        "created_at": datetime.utcnow()
    }
    return policies_col.insert_one(policy).inserted_id

def get_policy_by_id(pid):
    if isinstance(pid, str):
        pid = ObjectId(pid)
    return policies_col.find_one({"_id": pid})

# ---------------- User-Policy Functions ---------------- #
def assign_policy_to_user(user_id, policy_id, status="pending", doc_valid=False):
    if isinstance(user_id, str):
        user_id = ObjectId(user_id)
    if isinstance(policy_id, str):
        policy_id = ObjectId(policy_id)
    record = {
        "user_id": user_id,
        "policy_id": policy_id,
        "status": status,
        "doc_valid": doc_valid,
        "applied_at": datetime.utcnow()
    }
    return user_policies_col.insert_one(record).inserted_id

def get_user_policies(user_id):
    if isinstance(user_id, str):
        user_id = ObjectId(user_id)
    return list(user_policies_col.aggregate([
        {"$match": {"user_id": user_id}},
        {"$lookup": {
            "from": "policies",
            "localField": "policy_id",
            "foreignField": "_id",
            "as": "policy"
        }},
        {"$unwind": "$policy"},
        {"$sort": {"applied_at": -1}}
    ]))

def update_user_policy_status(up_id, status, doc_valid=None):
    if isinstance(up_id, str):
        up_id = ObjectId(up_id)
    upd = {"status": status}
    if doc_valid is not None:
        upd["doc_valid"] = doc_valid
    user_policies_col.update_one({"_id": up_id}, {"$set": upd})

# ---------------- Claims Functions ---------------- #
def add_claim(user_id, policy_id, amount, status="pending", risk_score=None, decision=None):
    if isinstance(user_id, str):
        user_id = ObjectId(user_id)
    if isinstance(policy_id, str):
        policy_id = ObjectId(policy_id)
    record = {
        "user_id": user_id,
        "policy_id": policy_id,
        "amount": amount,
        "status": status,
        "risk_score": risk_score,
        "decision": decision,
        "created_at": datetime.utcnow()
    }
    return claims_col.insert_one(record).inserted_id

def db_update_claim_status(claim_id, status, decision=None):
    if isinstance(claim_id, str):
        claim_id = ObjectId(claim_id)
    upd = {"status": status}
    if decision is not None:
        upd["decision"] = decision
    claims_col.update_one({"_id": claim_id}, {"$set": upd})

def get_all_policies():
    return list(policies_col.find().sort("created_at", -1))

def get_all_users():
    return list(users_col.find({}, {"password_hash": 0, "salt": 0}))

# ---------------- Default Admin Setup ---------------- #
def create_default_admin():
    admin_email = "admin@mail.com"
    admin_pass = "admin123"

    existing_admin = users_col.find_one({"email": admin_email})
    if not existing_admin:
        pwd_hash, salt = hash_password(admin_pass)
        users_col.insert_one({
            "name": "System Admin",
            "email": admin_email,
            "password_hash": pwd_hash,
            "salt": salt,
            "is_admin": True,
            "is_active": True,
            "created_at": datetime.utcnow()
        })
        print(f"[INFO] Default admin created → {admin_email} / {admin_pass}")
    # else:
    #     print("[INFO] Default admin already exists.")
