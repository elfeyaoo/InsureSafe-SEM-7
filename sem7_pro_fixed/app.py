from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from flask_mail import Mail, Message
import os, time, random
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
from itsdangerous import URLSafeTimedSerializer
from bson.objectid import ObjectId
from werkzeug.exceptions import RequestEntityTooLarge
import base64
from io import BytesIO
from PIL import Image
from services import otp_service
from bson import ObjectId


# ---- Services ----
from services.recommender import recommend_policies
from services.face_verify import FaceVerifier
from services.ocr_verify import DocumentVerifier
from services.claims_ai import ClaimsAI
from services.otp_service import send_otp, verify_otp

# ---- Database Helpers ----
from db import (
    init_db, add_user, authenticate_user, get_user_by_id, get_user_by_email,
    add_policy, get_policy_by_id, assign_policy_to_user, get_user_policies,
    update_user_policy_status, add_claim, db_update_claim_status, toggle_user_active,
    get_all_users, get_all_policies, users_col, claims_col, policies_col, user_policies_col
)

# ============================================================
# APP CONFIG
# ============================================================
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["ID_PHOTOS"] = "id_photos"
app.config["DEMO_MODE"] = os.getenv("DEMO_MODE", "false").lower() == "true"
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024

# ================= EMAIL (BREVO SMTP) =================
app.config["MAIL_SERVER"] = "smtp-relay.brevo.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = "a003a2001@smtp-brevo.com"
app.config["MAIL_PASSWORD"] = "xsmtpsib-338ccb36a9bdc0db0df009780089229a11ec700eb5d672be1716386932f06a2a-oAwqUt78QSPdoLE2"
app.config["MAIL_DEFAULT_SENDER"] = "insuresafe67@gmail.com"

mail = Mail(app)

# Serializer for token generation
serializer = URLSafeTimedSerializer(app.secret_key)

# Ensure upload dirs exist
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
init_db()   # ensures default admin exists

# ---- AI Services ----
face_verifier = FaceVerifier(model_name="ArcFace")
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

def detect_claim_type(policy, saved_files):
    """
    Detect whether claim is vehicle-based or normal
    """
    # Policy-based detection
    if policy.get("category", "").lower() in ("car", "bike"):
        return "vehicle"

    # File-based detection
    image_exts = (".jpg", ".jpeg", ".png")
    image_files = [f for f in saved_files if f.lower().endswith(image_exts)]

    if image_files and len(image_files) == len(saved_files):
        return "vehicle"

    return "normal"

# =====================================
# UPLOADS SERVING ROUTE
# =====================================
from flask import send_from_directory

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    return "Uploaded image is too large", 413


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
@app.route("/auth/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        step = request.form.get("step", "send_otp")

        name = request.form.get("name","").strip()
        email = request.form.get("email","").strip().lower()
        password = request.form.get("password","")
        phone = request.form.get("phone","").strip()
        address = request.form.get("address","").strip()
        age = request.form.get("age")
        annual_income = request.form.get("annual_income")
        id_photo = request.files.get("id_photo")

        # ================= STEP 1: SEND OTP =================
        if step == "send_otp":

            if not (name and email and password and id_photo):
                flash("All fields including ID photo are required.", "warning")
                return redirect(url_for("signup"))

            if get_user_by_email(email):
                flash("Email already registered.", "danger")
                return redirect(url_for("signup"))

            # Save ID photo temporarily
            id_dir = os.path.join(app.config["UPLOAD_FOLDER"], "temp_ids")
            os.makedirs(id_dir, exist_ok=True)

            filename = secure_filename(f"{int(time.time())}_{id_photo.filename}")
            temp_path = os.path.join(id_dir, filename)
            id_photo.save(temp_path)

            # Store signup data temporarily in session
            session["signup_data"] = {
                "name": name,
                "email": email,
                "password": password,
                "phone": phone,
                "address": address,
                "age": age,
                "annual_income": annual_income,
                "id_photo_path": temp_path
            }

            # 🔐 SEND OTP (Brevo)
            otp_service.send_otp(mail, email, purpose="signup")

            flash("OTP sent to your email.", "success")
            return render_template(
                "auth_signup.html",
                otp_sent=True,
                email=email
            )

        # ================= STEP 2: VERIFY OTP =================
        elif step == "verify_otp":
            otp = request.form.get("otp", "").strip()
            data = session.get("signup_data")

            if not data:
                flash("Session expired. Please sign up again.", "danger")
                return redirect(url_for("signup"))

            ok, msg = otp_service.verify_otp(
                data["email"],
                otp,
                purpose="signup"
            )

            if not ok:
                flash(msg, "danger")
                return render_template(
                    "auth_signup.html",
                    otp_sent=True,
                    email=data["email"]
                )

            # Move ID photo to final folder
            final_dir = os.path.join(app.config["UPLOAD_FOLDER"], "id_photos")
            os.makedirs(final_dir, exist_ok=True)

            final_name = os.path.basename(data["id_photo_path"])
            final_path = os.path.join(final_dir, final_name)
            os.rename(data["id_photo_path"], final_path)

            try:
                add_user(
                    name=data["name"],
                    email=data["email"],
                    password=data["password"],
                    id_photo_path=f"id_photos/{final_name}",
                    phone=data["phone"],
                    address=data["address"],
                    age=int(data["age"]) if data["age"] else None,
                    annual_income=float(data["annual_income"]) if data["annual_income"] else None,
                    is_admin=False,
                    email_verified=True   # ✅ VERIFIED VIA OTP
                )

                session.pop("signup_data", None)
                flash("Signup successful. Please login.", "success")
                return redirect(url_for("login"))

            except Exception as e:
                flash(f"Signup failed: {e}", "danger")
                return redirect(url_for("signup"))

    return render_template("auth_signup.html")

@app.route("/auth/resend-otp", methods=["POST"])
def resend_otp():
    data = session.get("signup_data")

    if not data:
        return jsonify({"ok": False, "msg": "Session expired"})

    email = data["email"]

    # 🔒 Cooldown check (60s)
    last_sent = session.get("otp_last_sent")
    if last_sent and time.time() - last_sent < 60:
        return jsonify({
            "ok": False,
            "msg": "Please wait before resending OTP"
        })

    send_otp(email, purpose="signup")
    session["otp_last_sent"] = time.time()

    return jsonify({"ok": True, "msg": "OTP resent"})

@app.route("/auth/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        user = authenticate_user(email, password)

        if not user:
            flash("Invalid credentials.", "danger")
            return redirect(url_for("login"))

        # ✅ Ensure account is active
        if not user.get("is_active", True):
            flash("Your account is inactive. Contact admin.", "danger")
            return redirect(url_for("login"))

        # ✅ Email verification check (admins bypass)
        if not user.get("is_admin") and not user.get("email_verified", False):
            flash("Please verify your email before logging in.", "warning")
            return redirect(url_for("login"))

        # 🔐 Clear old session (safety)
        session.clear()

        # ---------------- LOGIN CONTINUES ----------------
        session["role"] = "admin" if user.get("is_admin") else "user"
        session["user_id"] = str(user["_id"])

        if user.get("is_admin"):
            session["face_verified"] = True
            flash("Admin login successful.", "success")
            return redirect(url_for("admin"))

        # 👤 Normal user → face auth
        session["face_verified"] = False
        session["pending_user_id"] = str(user["_id"])
        flash("Password OK. Please complete face verification.", "info")
        return redirect(url_for("face_auth"))

    return render_template("auth_login.html")

# ============================================================
# ROUTES: FORGET PASSWORD
# ============================================================
@app.route("/auth/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        step = request.form.get("step", "send_otp")
        email = request.form.get("email", "").strip().lower()

        # ======================
        # STEP 1: SEND OTP
        # ======================
        if step == "send_otp":
            if not email:
                flash("Please enter your email.", "warning")
                return redirect(url_for("forgot"))

            user = get_user_by_email(email)

            # 🔐 Security: don’t reveal if user exists
            if user:
                otp_service.send_otp(mail, email, purpose="forgot")

            flash("If this email exists, an OTP has been sent.", "info")

            return render_template(
                "auth_forgot.html",
                otp_sent=True,
                email=email
            )

        # ======================
        # STEP 2: VERIFY OTP
        # ======================
        elif step == "verify_otp":
            otp = request.form.get("otp", "").strip()

            ok, msg = otp_service.verify_otp(
                email,
                otp,
                purpose="forgot"
            )

            if not ok:
                flash(msg, "danger")
                return render_template(
                    "auth_forgot.html",
                    otp_sent=True,
                    email=email
                )

            # ✅ OTP VERIFIED → ALLOW PASSWORD RESET
            session["reset_email"] = email
            return redirect(url_for("reset_password"))

    return render_template("auth_forgot.html", otp_sent=False)

@app.route("/auth/reset-password", methods=["GET", "POST"])
def reset_password():
    email = session.get("reset_email")
    if not email:
        flash("Session expired. Please try again.", "danger")
        return redirect(url_for("forgot"))

    if request.method == "POST":
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if not password or not confirm:
            flash("Please fill all fields.", "warning")
            return redirect(request.url)

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(request.url)

        user = get_user_by_email(email)
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("forgot"))

        # 🔐 Update password securely
        pwd_hash, salt = hash_password(password)
        users_col.update_one(
            {"_id": user["_id"]},
            {"$set": {
                "password_hash": pwd_hash,
                "salt": salt
            }}
        )

        session.pop("reset_email", None)
        flash("Password reset successful. Please login.", "success")
        return redirect(url_for("login"))

    return render_template("auth_reset.html", email=email)

# ============================================================
# FACE AUTH
# ============================================================
@app.route("/auth/face", methods=["GET", "POST"])
def face_auth():
    uid = session.get("pending_user_id")
    if not uid:
        return redirect(url_for("login"))

    result = None

    if request.method == "POST":
        captured_image = request.form.get("captured_image")  # Base64 webcam string

        if captured_image:
            try:
                user = get_user_by_id(uid)

                if not user or not user.get("id_photo_path"):
                    flash("ID photo not found. Please contact support.", "danger")
                    return redirect(url_for("login"))

                img_data = captured_image.split(",")[1]
                decoded_img = base64.b64decode(img_data)

                img = Image.open(BytesIO(decoded_img))

                # Resize + compress to avoid Request Entity Too Large
                img = img.resize((480, 360))
                sf_dir = os.path.join(app.config["UPLOAD_FOLDER"], "selfies")
                os.makedirs(sf_dir, exist_ok=True)

                filename = secure_filename(f"{int(time.time())}_selfie.jpg")
                sf_path = os.path.join(sf_dir, filename)

                img.save(sf_path, "JPEG", quality=60)

                stored_path = os.path.join(app.config["UPLOAD_FOLDER"], user["id_photo_path"])

                result = face_verifier.compare(stored_path, sf_path)

                if result.get("match"):
                    session["user_id"] = uid
                    session["face_verified"] = True
                    session.pop("pending_user_id", None)

                    flash("✅ Face verification successful!", "success")
                    return redirect(url_for("dashboard"))

                flash("❌ Face mismatch. Try again.", "danger")

            except Exception as e:
                print("Face Auth Error:", e)
                flash("Error processing image. Try again.", "danger")

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
    uid = session["user_id"]
    user = get_user_by_id(uid)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("logout"))

    # User features with defaults
    age = user.get("age", 30)
    annual_income = user.get("annual_income", 500_000)

    # User's existing policies
    existing_policies = get_user_policies(uid) or []
    existing_policy_ids = [
        str(p.get("policy_id")) for p in existing_policies if p.get("policy_id")
    ]

    # Compute total premium (optional)
    total_premium = 0.0
    if existing_policy_ids:
        try:
            object_ids = [ObjectId(pid) for pid in existing_policy_ids]
            cursor = policies_col.find({"_id": {"$in": object_ids}})
            total_premium = sum(float(p.get("premium_amount", 0)) for p in cursor)
        except Exception:
            total_premium = 0.0

    # Get recommended policies
    recommended = recommend_policies(
        age=age,
        annual_income=annual_income,
        existing_premiums=total_premium,
        existing_policy_count=len(existing_policy_ids)
    ) or []

    # Fetch all policies
    all_policies = list(policies_col.find())

    # Map policy names to DB documents
    name_to_doc = { (p.get("name") or "").strip().lower(): p for p in all_policies }

    # Map recommender output to DB _id and score
    recommended_ids = []
    scores = {}
    for r in recommended:
        rec_name = (r.get("name") or "").strip().lower()
        matched = name_to_doc.get(rec_name)
        if matched:
            pid = str(matched["_id"])
            recommended_ids.append(pid)
            scores[pid] = float(r.get("score", 0))

    # Sort policies: Owned+Recommended > Recommended > Remaining
    def sort_key(p):
        pid = str(p["_id"])
        if pid in existing_policy_ids and pid in recommended_ids:
            return (0, -scores.get(pid, 0))
        elif pid in recommended_ids:
            return (1, -scores.get(pid, 0))
        else:
            return (2, 0)

    all_policies.sort(key=sort_key)

    return render_template(
        "policies.html",
        policies=all_policies,
        recommended_ids=recommended_ids,
        scores=scores,
        existing_policy_ids=existing_policy_ids
    )

# ============================================================
# APPLY POLICY
# ============================================================
@app.route("/apply/<pid>", methods=["GET", "POST"])
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

    # ✅ Required document KEYS
    required_fields = CATEGORY_REQUIREMENTS.get(
        policy.get("category", "General"),
        ["aadhar_card", "pan_card"]
    )

    # ✅ Pass KEY → LABEL mapping to template
    requirements = {
        field: REQUIREMENT_LABELS[field]
        for field in required_fields
    }

    if request.method == "POST":

        # -----------------------------
        # 1️⃣ Collect user-entered data
        # -----------------------------
        form_data = {
            "name": request.form.get("name", "").strip(),
            "dob": request.form.get("dob", "").strip(),
            "gender": request.form.get("gender", "").strip(),
            "email": request.form.get("email", "").strip(),
            "phone": request.form.get("phone", "").strip(),
            "address": request.form.get("address", "").strip()
        }

        # -----------------------------
        # 2️⃣ Save uploaded documents
        # -----------------------------
        uploaded_docs = {}
        doc_dir = os.path.join(
            app.config["UPLOAD_FOLDER"],
            "documents",
            str(session["user_id"])
        )
        os.makedirs(doc_dir, exist_ok=True)

        for field in required_fields:
            file = request.files.get(field)

            if not file or not file.filename:
                flash(f"Please upload: {REQUIREMENT_LABELS[field]}", "warning")
                return redirect(request.url)

            filename = secure_filename(f"{int(time.time())}_{file.filename}")
            fpath = os.path.join(doc_dir, filename)
            file.save(fpath)

            uploaded_docs[field] = fpath

        # -----------------------------
        # 3️⃣ OCR / Document Verification
        # -----------------------------
        validation_data = {
            "name": form_data["name"],
            "dob": form_data["dob"],
            "gender": form_data["gender"]
        }

        # ✅ Use Aadhaar as primary verification
        primary_doc_key = "aadhar_card"
        result = doc_verifier.validate(
            uploaded_docs[primary_doc_key],
            validation_data
        )

        valid = bool(result.get("is_valid"))

        # -----------------------------
        # 4️⃣ Save policy assignment
        # -----------------------------
        assign_policy_to_user(
            user_id=session["user_id"],
            policy_id=pid,
            status="active" if valid else "pending",
            doc_valid=valid,
            uploaded_docs=uploaded_docs
        )

        if valid:
            flash("✅ Application verified. Policy activated.", "success")
        else:
            flash("⚠ Document mismatch. Sent for manual review.", "warning")

        return redirect(url_for("dashboard"))

    return render_template(
        "apply_policy.html",
        policy=policy,
        requirements=requirements,   # ✅ dictionary
        result=result
    )

# ============================================================
# DASHBOARD & CLAIMS
# ============================================================
from datetime import datetime, timedelta
from bson import ObjectId

@app.route("/dashboard")
@login_required
def dashboard():
    uid = session["user_id"]
    now = datetime.utcnow()

    # ----------------------------
    # User policies
    # ----------------------------
    policies = get_user_policies(uid)

    # ----------------------------
    # Claims with policy join
    # ----------------------------
    claims = list(claims_col.aggregate([
        {"$match": {"user_id": ObjectId(uid)}},
        {"$lookup": {
            "from": "policies",
            "localField": "policy_id",
            "foreignField": "_id",
            "as": "policy"
        }},
        {"$unwind": "$policy"},
        {"$sort": {"created_at": -1}}
    ]))

    # ----------------------------
    # Latest claim + cooldown map
    # ----------------------------
    claim_map = {}
    cooldown_map = {}

    # ----------------------------
    # Mini claim summary per policy
    # ----------------------------
    claim_summary = {}

    for c in claims:
        pid = str(c["policy_id"])

        # Init summary
        if pid not in claim_summary:
            claim_summary[pid] = {
                "approved": 0,
                "pending": 0,
                "rejected": 0
            }

        status = c.get("status")
        if status in claim_summary[pid]:
            claim_summary[pid][status] += 1

        # Latest claim per policy
        if pid not in claim_map:
            claim_map[pid] = c

            # Cooldown only if rejected
            if status == "rejected":
                cooldown_map[pid] = c["created_at"] + timedelta(days=30)

    return render_template(
        "dashboard.html",
        policies=policies,
        claims=claims,
        claim_map=claim_map,
        claim_summary=claim_summary,   # ✅ NEW
        cooldown_map=cooldown_map,     # ✅ FIXED
        now=now                        # ✅ FIXED
    )

# ============================================================
# APPLY CLAIM (Dedicated AI Claims Page)
# ============================================================
@app.route("/claim/apply/<policy_id>", methods=["GET", "POST"])
@login_required
def apply_claim(policy_id):
    policy = get_policy_by_id(policy_id)
    if not policy:
        abort(404)

    claim_type = request.args.get("type", "vehicle")
    report = None

    if request.method == "POST":
        claim_type = request.form.get("claim_type")

        # =====================================================
        # 🚗 VEHICLE CLAIM
        # =====================================================
        if claim_type == "vehicle":
            stage = request.form.get("stage")

            # ---------- STAGE 1: ESTIMATE ----------
            if stage == "estimate":
                files = request.files.getlist("claim_files")

                if not files or not files[0].filename:
                    flash("Please upload at least one damage image.", "warning")
                    return redirect(request.url)

                image_paths = []
                c_dir = os.path.join(app.config["UPLOAD_FOLDER"], "claims")
                os.makedirs(c_dir, exist_ok=True)

                for f in files:
                    path = os.path.join(
                        c_dir,
                        secure_filename(f"{int(time.time())}_{f.filename}")
                    )
                    f.save(path)
                    image_paths.append(path)

                report = claims_ai.evaluate_vehicle_damage(
                    image_paths=image_paths,
                    vehicle_type=policy.get("category", "").lower()
                )

            # ---------- STAGE 2: BARGAIN ----------
            elif stage == "bargain":
                ai_estimate = float(request.form.get("ai_estimate", 0))
                claim_amount = float(request.form.get("claim_amount", 0))

                report = claims_ai.evaluate_bargain(ai_estimate, claim_amount)

                add_claim(
                    session["user_id"],
                    policy_id,
                    claim_amount,
                    status="pending",
                    risk_score=report["risk_score"],
                    decision=report["decision"],
                    claim_type="vehicle"
                )

                flash("Vehicle claim submitted successfully.", "success")

        # =====================================================
        # 📄 DOCUMENT CLAIM
        # =====================================================
        elif claim_type == "document":
            files = request.files.getlist("claim_files")
            claim_amount = float(request.form.get("claim_amount", 0))

            if not files:
                flash("Please upload claim documents.", "warning")
                return redirect(request.url)

            file_paths = []
            c_dir = os.path.join(app.config["UPLOAD_FOLDER"], "claims")
            os.makedirs(c_dir, exist_ok=True)

            for f in files:
                path = os.path.join(
                    c_dir,
                    secure_filename(f"{int(time.time())}_{f.filename}")
                )
                f.save(path)
                file_paths.append(path)

            report = claims_ai.evaluate(
                files=file_paths,
                metadata={
                    "claim_amount": claim_amount,
                    "policy_sum_insured": policy.get("sum_insured", 100000)
                }
            )

            add_claim(
                session["user_id"],
                policy_id,
                claim_amount,
                status="pending",
                risk_score=report["risk_score"],
                decision=report["decision"],
                claim_type="document"
            )

            flash("Document claim submitted successfully.", "success")

    return render_template(
        "apply_claim.html",
        policy=policy,
        report=report,
        claim_type=claim_type
    )

# ============================================================
# PROFILE
# ============================================================
@app.route("/profile")
@login_required
def profile():
    uid = session["user_id"]
    user = get_user_by_id(uid)

    # ✅ Fix backslashes in stored image paths
    if user and user.get("id_photo_path"):
        user["id_photo_path"] = user["id_photo_path"].replace("\\", "/")

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

        for u in users:
            if "email_verified" not in u:
                u["email_verified"] = False

        policy_defs = list(policies_col.find())

        enriched_claims = list(claims_col.aggregate([
            {
                "$lookup": {
                    "from": "users",
                    "localField": "user_id",
                    "foreignField": "_id",
                    "as": "user"
                }
            },
            { "$unwind": "$user" },
            {
                "$lookup": {
                    "from": "policies",
                    "localField": "policy_id",
                    "foreignField": "_id",
                    "as": "policy"
                }
            },
            { "$unwind": "$policy" },
            { "$sort": { "created_at": -1 } }
        ]))

        for c in enriched_claims:
            c.setdefault("claim_type", "normal")

        # ✅ USER POLICIES (DOCUMENT REVIEW)
        user_policies = list(user_policies_col.aggregate([
            {
                "$lookup": {
                    "from": "users",
                    "localField": "user_id",
                    "foreignField": "_id",
                    "as": "user"
                }
            },
            { "$unwind": "$user" },
            {
                "$lookup": {
                    "from": "policies",
                    "localField": "policy_id",
                    "foreignField": "_id",
                    "as": "policy"
                }
            },
            { "$unwind": "$policy" },
            { "$sort": { "applied_at": -1 } }
        ]))

        counts = {
            "n_users": users_col.count_documents({}),
            "n_up": policies_col.count_documents({}),
            "n_c": claims_col.count_documents({}),
        }

        return render_template(
            "admin.html",
            users=users,
            policy_defs=policy_defs,
            claims=enriched_claims,
            user_policies=user_policies,
            counts=counts
        )

    except Exception as e:
        flash(f"Admin load failed: {e}", "danger")
        return render_template(
            "admin.html",
            users=[],
            policy_defs=[],
            claims=[],
            user_policies=[],
            counts={"n_users": 0, "n_up": 0, "n_c": 0}
        )

@app.route("/admin/verify_email/<uid>")
@admin_required
def admin_verify_email(uid):
    try:
        users_col.update_one(
            {"_id": ObjectId(uid)},
            {"$set": {"email_verified": True}}
        )
        flash("User email verified successfully.", "success")
    except Exception as e:
        flash(f"Verification failed: {e}", "danger")

    return redirect(url_for("admin"))

@app.route("/admin/update_policy_status/<policy_id>/<status>")
@admin_required
def update_policy_status(policy_id, status):
    try:
        update_user_policy_status(
            policy_id,
            status,
            doc_valid=status.lower() in ("approved", "active")
        )
        flash("Policy status updated.", "success")
    except Exception as e:
        flash(f"Failed to update policy: {e}", "danger")

    return redirect(url_for("admin"))

@app.route("/admin/update_claim_status/<claim_id>/<status>")
@admin_required
def update_claim_status(claim_id, status):
    try:
        status = status.lower()

        if status == "approved":
            decision = "Auto-Approve"
        elif status == "manual":
            decision = "Manual Review"
        else:
            decision = "Rejected"

        db_update_claim_status(claim_id, status, decision)
        flash("Claim status updated.", "success")

    except Exception as e:
        flash(f"Failed to update claim: {e}", "danger")

    return redirect(url_for("admin"))

@app.route("/admin/verify_policy/<user_policy_id>")
@admin_required
def admin_verify_policy(user_policy_id):
    try:
        update_user_policy_status(
            user_policy_id=user_policy_id,
            status="active",
            doc_valid=True
        )
        flash("Policy documents verified and policy activated.", "success")
    except Exception as e:
        flash(f"Policy verification failed: {e}", "danger")

    return redirect(url_for("admin"))

@app.route("/admin/toggle/<uid>")
@admin_required
def admin_toggle(uid):
    try:
        new_status = toggle_user_active(uid)
        if new_status is not None:
            flash(
                f"User {'activated' if new_status else 'deactivated'}.",
                "success"
            )
        else:
            flash("User not found.", "warning")
    except Exception as e:
        flash(f"Toggle failed: {e}", "danger")

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
            "category": data.get("category"),
            "description": data.get("description"),
            "requirements": data.get("requirements", ""),
            "min_age": int(data.get("min_age", 0)),
            "max_age": int(data.get("max_age", 100)),
            "min_income": float(data.get("min_income", 0)),
            "max_income": float(data.get("max_income", 0)),
            "premium_amount": float(data.get("premium_amount", 0)),
            "duration_years": int(data.get("duration_years", 1)),
            "created_at": datetime.utcnow()
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
