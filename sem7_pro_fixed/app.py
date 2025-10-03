from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
import os, time
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
from bson.objectid import ObjectId

# ---- Services ----
from services.recommender import recommend_policies
from services.face_verify import FaceVerifier
from services.ocr_verify import DocumentVerifier
from services.claims_ai import ClaimsAI

# ---- Database Helpers ----
from db import (
    init_db, add_user, authenticate_user, get_user_by_id, get_user_by_email,
    add_policy, get_policy_by_id, assign_policy_to_user, get_user_policies,
    update_user_policy_status, add_claim, db_update_claim_status, toggle_user_active,
    get_all_users, get_all_policies, users_col, claims_col, policies_col
)

# ============================================================
# APP CONFIG
# ============================================================
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["ID_PHOTOS"] = "id_photos"
app.config["DEMO_MODE"] = True

# Serializer for token generation
serializer = URLSafeTimedSerializer(app.secret_key)

# Ensure upload dirs exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
init_db()   # ensures default admin exists

# ---- AI Services ----
face_verifier = FaceVerifier(demo=app.config["DEMO_MODE"])
doc_verifier = DocumentVerifier(demo=app.config["DEMO_MODE"])
claims_ai = ClaimsAI(demo=app.config["DEMO_MODE"])

# ============================================================
# AUTH HELPERS
# ============================================================
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        if not session.get("face_verified") and session.get("role") != "admin":
            return redirect(url_for("face_auth"))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        user = get_user_by_id(session["user_id"])
        if not user or not user.get("is_admin"):
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# =====================================
# UPLOADS SERVING ROUTE
# =====================================
from flask import send_from_directory

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# ============================================================
# ROUTES: INDEX
# ============================================================
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/get-started")
def get_started():
    return redirect(url_for("login"))

# ============================================================
# ROUTES: AUTH
# ============================================================
@app.route("/auth/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        id_photo = request.files.get("id_photo")
        phone = request.form.get("phone","").strip()
        address = request.form.get("address","").strip()

        if not (name and email and password and id_photo):
            flash("All fields including ID photo are required.", "warning")
            return redirect(url_for("signup"))

        if get_user_by_email(email):
            flash("Email already registered.", "danger")
            return redirect(url_for("signup"))

        # Save ID photo
        id_dir = os.path.join(app.config["UPLOAD_FOLDER"], "id_photos")
        os.makedirs(id_dir, exist_ok=True)
        filename = secure_filename(f"{int(time.time())}_{id_photo.filename}")
        id_photo.save(os.path.join(id_dir, filename))
        idp_path = os.path.join("id_photos", filename)  # relative path for DB

        try:
            add_user(
                name, email, password,
                id_photo_path=idp_path,
                is_admin=False,
                phone=phone,
                address=address
            )
            flash("Signup successful. Please login.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"Signup failed: {e}", "danger")

    return render_template("auth_signup.html")

@app.route("/auth/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").lower()
        password = request.form.get("password", "")

        user = authenticate_user(email, password)
        if user:
            # ✅ Check if user is active
            if not user.get("is_active", True):
                flash("Your account is inactive. Contact admin.", "danger")
                return redirect(url_for("login"))

            # Existing login logic
            session["role"] = "admin" if user.get("is_admin") else "user"
            session["user_id"] = str(user["_id"])

            if user.get("is_admin"):
                session["face_verified"] = True
                flash("Admin login successful.", "success")
                return redirect(url_for("admin"))
            else:
                session["face_verified"] = False
                session["pending_user_id"] = str(user["_id"])
                flash("Password OK. Please complete face verification.", "info")
                return redirect(url_for("face_auth"))

        flash("Invalid credentials.", "danger")
    return render_template("auth_login.html")

# ===================== FORGOT PASSWORD =====================
@app.route("/auth/forgot", methods=["GET","POST"])
@app.route("/auth/forgot/<token>", methods=["GET","POST"])
def forgot(token=None):
    if token:
        # Reset form
        try:
            email = serializer.loads(token, salt="password-reset", max_age=3600)
        except:
            flash("The reset link is invalid or expired.", "danger")
            return redirect(url_for("forgot"))

        if request.method == "POST":
            password = request.form.get("password")
            confirm = request.form.get("confirm")

            if not password or not confirm:
                flash("Please fill in both password fields.", "warning")
                return redirect(request.url)

            if password != confirm:
                flash("Passwords do not match.", "warning")
                return redirect(request.url)

            user = get_user_by_email(email)
            if user:
                users_col.update_one({"_id": user["_id"]}, {"$set": {"password": password}})
                flash("Password reset successfully.", "success")
                return redirect(url_for("login"))
            else:
                flash("User not found.", "danger")
                return redirect(url_for("forgot"))

        return render_template("auth_forgot.html", reset=True, token=token, email=email)

    # Email input form
    if request.method == "POST":
        email = request.form.get("email","").lower()
        if not email:
            flash("Please enter your email.", "warning")
            return redirect(url_for("forgot"))

        user = get_user_by_email(email)
        if user:
            # generate token and redirect to reset page
            token = serializer.dumps(email, salt="password-reset")
            return redirect(url_for("forgot", token=token))
        else:
            flash(f"If {email} exists, you can reset your password.", "info")
            return redirect(url_for("login"))

    return render_template("auth_forgot.html", reset=False)

# ============================================================
# FACE AUTH
# ============================================================
@app.route("/auth/face", methods=["GET","POST"])
def face_auth():
    uid = session.get("pending_user_id")
    if not uid:
        return redirect(url_for("login"))

    result = None
    if request.method == "POST":
        selfie = request.files.get("selfie")
        if selfie and selfie.filename:
            user = get_user_by_id(uid)
            if not user or not user.get("id_photo_path"):
                flash("ID photo not found. Please contact support.", "danger")
                return redirect(url_for("login"))

            sf_dir = os.path.join(app.config["UPLOAD_FOLDER"], "selfies")
            os.makedirs(sf_dir, exist_ok=True)
            filename = secure_filename(f"{int(time.time())}_{selfie.filename}")
            sf_path = os.path.join(sf_dir, filename)
            selfie.save(sf_path)

            # Build full server paths for verification
            profile_photo_path = os.path.join(app.config["UPLOAD_FOLDER"], user["id_photo_path"])
            result = face_verifier.compare(profile_photo_path, sf_path)

            if result.get("match"):
                session["user_id"] = uid
                session["face_verified"] = True
                session.pop("pending_user_id", None)
                flash("Welcome! Face verification passed.", "success")
                return redirect(url_for("dashboard"))
            else:
                flash("Face verification failed.", "danger")

    return render_template("auth_face.html", result=result)

# ============================================================
# LOGOUT
# ============================================================
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# ============================================================
# POLICIES (User-facing)
# ============================================================
@app.route("/policies")
@login_required
def policies():
    user = get_user_by_id(session["user_id"])
    age = user.get("age", 30)
    salary = user.get("annual_income", 500000)
    existing_policies = get_user_policies(session["user_id"])

    # Compute existing premiums & count for recommendation
    existing_ids = [p["policy_id"] for p in existing_policies]
    existing_premiums = sum([p["premium_amount"] for p in policies_col.find({"_id": {"$in": [ObjectId(pid) for pid in existing_ids]}})])
    existing_count = len(existing_ids)

    recommended = recommend_policies(
        age=age,
        annual_income=salary,
        existing_premiums=existing_premiums,
        existing_policy_count=existing_count
    )
    recommended_ids = [p["id"] for p in recommended]

    # Fetch all policies from DB
    all_policies = list(policies_col.find())

    return render_template(
        "policies.html",
        policies=all_policies,
        recommended_ids=recommended_ids
    )

# ============================================================
# APPLY POLICY
# ============================================================
# ============================================================
# APPLY POLICY
# ============================================================
@app.route("/apply/<pid>", methods=["GET","POST"])
@login_required
def apply_policy(pid):
    policy = get_policy_by_id(pid)
    if not policy:
        abort(404)

    result = None
    CATEGORY_REQUIREMENTS = {
        "Health": ["aadhar_card", "pan_card", "medical_records"],
        "Car": ["aadhar_card", "pan_card", "driving_license", "vehicle_registration", "legal_rc"],
        "Life": ["aadhar_card", "pan_card", "income_proof", "medical_records"],
        "Bike": ["aadhar_card", "pan_card", "driving_license", "bike_registration", "legal_rc"],
        "Family": ["aadhar_card", "pan_card", "family_details"]
    }

    # Map of human-readable names for flash messages / form labels
    REQUIREMENT_LABELS = {
        "aadhar_card": "Aadhar Card",
        "pan_card": "PAN Card",
        "medical_records": "Medical Certificate / Records",
        "income_proof": "Income Proof",
        "driving_license": "Driving License",
        "vehicle_registration": "Vehicle Registration",
        "bike_registration": "Bike Registration",
        "legal_rc": "Legal RC",
        "family_details": "Family Member Details"
    }

    required_fields = CATEGORY_REQUIREMENTS.get(policy.get("category", "General"), ["aadhar_card", "pan_card"])
    human_readable_requirements = [REQUIREMENT_LABELS[f] for f in required_fields]

    if request.method == "POST":
        # Collect basic info
        form_data = {
            "name": request.form.get("name",""),
            "dob": request.form.get("dob",""),
            "gender": request.form.get("gender",""),
            "email": request.form.get("email",""),
            "phone": request.form.get("phone",""),
            "address": request.form.get("address","")
        }

        # Save uploaded documents
        uploaded_docs = {}
        doc_dir = os.path.join(app.config["UPLOAD_FOLDER"], "documents", str(session["user_id"]))
        os.makedirs(doc_dir, exist_ok=True)

        for field in required_fields:
            file = request.files.get(field)
            if not file or not file.filename:
                flash(f"Please upload required document: {REQUIREMENT_LABELS[field]}", "warning")
                return redirect(request.url)

            fpath = os.path.join(doc_dir, secure_filename(f"{int(time.time())}_{file.filename}"))
            file.save(fpath)
            uploaded_docs[field] = fpath

        # Validate uploaded documents (can be extended per document type)
        validation_data = {
            "name": form_data["name"],
            "dob": form_data["dob"]
        }

        # For simplicity, validate only first document as main verification
        main_doc_field = required_fields[0]
        result = doc_verifier.validate(uploaded_docs[main_doc_field], validation_data)
        valid = bool(result.get("is_valid"))

        # Save policy assignment
        assign_policy_to_user(
            session["user_id"], pid,
            status="active" if valid else "pending",
            doc_valid=valid,
            uploaded_docs=uploaded_docs
        )

        if valid:
            flash("Application submitted and verified. Policy activated.", "success")
        else:
            flash("Document mismatch. Application pending manual review.", "warning")
        return redirect(url_for("dashboard"))

    return render_template(
        "apply_policy.html",
        policy=policy,
        requirements=human_readable_requirements,
        result=result
    )

# ============================================================
# DASHBOARD & CLAIMS
# ============================================================
@app.route("/dashboard", methods=["GET","POST"])
@login_required
def dashboard():
    uid = session["user_id"]
    mypol = get_user_policies(uid)

    claim_report = None
    if request.method == "POST":
        pid = request.form.get("policy_id")
        amount = float(request.form.get("claim_amount") or 0)
        files = request.files.getlist("claim_files")

        saved = []
        for f in files:
            if f and f.filename:
                c_dir = os.path.join(app.config["UPLOAD_FOLDER"], "claims")
                os.makedirs(c_dir, exist_ok=True)
                path = os.path.join(c_dir, secure_filename(f"{int(time.time())}_{f.filename}"))
                f.save(path)
                saved.append(path)

        sum_insured = 500000 if pid != "ELITE_PLUS" else 2000000
        claim_report = claims_ai.evaluate(saved, {"claim_amount": amount, "policy_sum_insured": sum_insured})

        add_claim(uid, pid, amount, status="pending",
                  risk_score=claim_report.get("risk_score"),
                  decision=claim_report.get("decision"))
        flash("Claim evaluated by AI.", "info")

    return render_template("dashboard.html", policies=mypol, claim_report=claim_report)

# ============================================================
# PROFILE
# ============================================================
@app.route("/profile")
@login_required
def profile():
    uid = session["user_id"]
    user = get_user_by_id(uid)
    policies = get_user_policies(uid)
    return render_template("profile.html", user=user, policies=policies)

@app.route("/profile/edit", methods=["POST"])
@login_required
def edit_profile():
    uid = session["user_id"]
    user = get_user_by_id(uid)
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    # Form data
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    phone = request.form.get("phone", "").strip() or None
    address = request.form.get("address", "").strip() or None
    id_photo = request.files.get("id_photo")

    # Check for duplicate email
    existing_user = users_col.find_one({"email": email, "_id": {"$ne": user["_id"]}})
    if existing_user:
        return jsonify({"status": "error", "message": "Email already used by another account."})

    update_data = {"name": name, "email": email, "phone": phone, "address": address}

    # Handle ID photo upload
    if id_photo and id_photo.filename:
        # Ensure upload directory exists
        id_dir = os.path.join(app.config["UPLOAD_FOLDER"], "id_photos")
        os.makedirs(id_dir, exist_ok=True)

        # Use a safe filename and store relative path
        filename = secure_filename(f"{int(time.time())}_{id_photo.filename}")
        file_path = os.path.join(id_dir, filename)
        id_photo.save(file_path)
        update_data["id_photo_path"] = f"id_photos/{filename}"  # relative path

    # Update DB
    users_col.update_one({"_id": user["_id"]}, {"$set": update_data})
    updated_user = get_user_by_id(uid)

    return jsonify({
        "status": "success",
        "message": "Profile updated successfully.",
        "user": {
            "name": updated_user["name"],
            "email": updated_user["email"],
            "phone": updated_user.get("phone", ""),
            "address": updated_user.get("address", ""),
            "id_photo_path": updated_user.get("id_photo_path", "")
        }
    })

# ============================================================
# ADMIN
# ============================================================
@app.route("/admin")
@admin_required
def admin():
    try:
        users = list(users_col.find())
        policy_defs = list(policies_col.find())
        claims = list(claims_col.find())

        enriched_policies = []
        for u in users:
            uid_str = str(u["_id"])
            user_policies = get_user_policies(uid_str) or []
            for up in user_policies:
                policy = get_policy_by_id(up.get("policy_id"))
                enriched_policies.append({
                    **up,
                    "user": u,
                    "policy": policy
                })

        enriched_claims = []
        for c in claims:
            user = get_user_by_id(c.get("user_id"))
            policy = get_policy_by_id(c.get("policy_id"))
            enriched_claims.append({
                **c,
                "user": user,
                "policy": policy
            })

        counts = {
            "n_users": len(users),
            "n_up": len(policy_defs),
            "n_c": len(claims),
        }

        return render_template(
            "admin.html",
            users=users,
            policies=enriched_policies,
            policy_defs=policy_defs,
            claims=enriched_claims,
            counts=counts
        )

    except Exception as e:
        flash(f"Failed to load admin data: {e}", "danger")
        return render_template(
            "admin.html",
            users=[], policies=[], policy_defs=[], claims=[], counts={"n_users":0,"n_up":0,"n_c":0}
        )

@app.route("/admin/update_policy_status/<policy_id>/<status>")
@admin_required
def update_policy_status(policy_id, status):
    update_user_policy_status(policy_id, status, doc_valid=status.lower() in ("approved","active"))
    flash("Policy status updated.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/update_claim_status/<claim_id>/<status>")
@admin_required
def update_claim_status(claim_id, status):
    decision = "Valid" if status.lower() in ("approved","approve") else "Invalid"
    db_update_claim_status(claim_id, status, decision)
    flash("Claim status updated.", "success")
    return redirect(url_for("admin"))

@app.route("/admin/toggle/<uid>")
@admin_required
def admin_toggle(uid):
    new_status = toggle_user_active(uid)
    if new_status is not None:
        flash(f"User status updated to {'Active' if new_status else 'Inactive'}.", "success")
    else:
        flash("User not found.", "danger")
    return redirect(url_for("admin"))

# ============================================================
# POLICY MANAGEMENT (Admin)
# ============================================================
@app.route("/admin/policy/add", methods=["POST"])
@admin_required
def add_policy():
    try:
        data = request.form
        policy = {
            "name": data.get("name"),
            "description": data.get("description"),
            "requirements": data.get("requirements"),
            "min_age": int(data.get("min_age") or 0),
            "max_age": int(data.get("max_age") or 100),
            "min_income": float(data.get("min_income") or 0),
            "max_income": float(data.get("max_income") or 0),
            "premium_amount": float(data.get("premium_amount") or 0),
            "duration_years": int(data.get("duration_years") or 1),
            "category": data.get("category"),
            "created_at": int(time.time())
        }
        policies_col.insert_one(policy)
        flash("Policy added successfully.", "success")
    except Exception as e:
        flash(f"Failed to add policy: {e}", "danger")
    return redirect(url_for("admin"))

@app.route("/admin/policy/delete/<policy_id>", methods=["GET","POST"])
@admin_required
def admin_delete_policy(policy_id):
    try:
        oid = ObjectId(policy_id)
    except:
        oid = policy_id
    try:
        res = policies_col.delete_one({"_id": oid})
        if res.deleted_count:
            flash("Policy deleted.", "success")
        else:
            flash("Policy not found.", "warning")
    except Exception as e:
        flash(f"Failed to delete policy: {e}", "danger")
    return redirect(url_for("admin"))

# ============================================================
# TEMPLATE FILTERS
# ============================================================
@app.template_filter("datetimeformat")
def datetimeformat(value, format="%Y-%m-%d %H:%M"):
    if isinstance(value, int):
        value = datetime.fromtimestamp(value)
    elif isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    elif not isinstance(value, datetime):
        return value
    return value.strftime(format)

# ============================================================
# MAIN
# ============================================================
if __name__ == "__main__":
    app.run(debug=True)
