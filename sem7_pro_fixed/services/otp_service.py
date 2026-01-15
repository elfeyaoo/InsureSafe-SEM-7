# services/otp_service.py
import random
from datetime import datetime, timedelta
from flask_mail import Message
from db import otp_col


OTP_EXPIRY_MINUTES = 5
MAX_ATTEMPTS = 5


def send_otp(mail, email, purpose="signup"):
    """
    Sends OTP to email using Brevo SMTP
    """

    otp = str(random.randint(100000, 999999))
    expires_at = datetime.utcnow() + timedelta(minutes=OTP_EXPIRY_MINUTES)

    # Remove old OTPs
    otp_col.delete_many({"email": email, "purpose": purpose})

    otp_col.insert_one({
        "email": email,
        "otp": otp,
        "purpose": purpose,
        "attempts": 0,
        "expires_at": expires_at,
        "created_at": datetime.utcnow()
    })

    msg = Message(
        subject="Your InsureSafe OTP",
        recipients=[email],
        body=f"""
Your One-Time Password (OTP) is: {otp}

Purpose: {purpose.upper()}
Valid for {OTP_EXPIRY_MINUTES} minutes.

If you did not request this, ignore this email.
"""
    )

    mail.send(msg)


def verify_otp(email, otp, purpose="signup"):
    record = otp_col.find_one({
        "email": email,
        "purpose": purpose
    })

    if not record:
        return False, "OTP not found or expired."

    if datetime.utcnow() > record["expires_at"]:
        otp_col.delete_one({"_id": record["_id"]})
        return False, "OTP expired."

    if record["attempts"] >= MAX_ATTEMPTS:
        return False, "Too many attempts. OTP locked."

    if record["otp"] != otp:
        otp_col.update_one(
            {"_id": record["_id"]},
            {"$inc": {"attempts": 1}}
        )
        return False, "Invalid OTP."

    # ✅ Success → delete OTP
    otp_col.delete_one({"_id": record["_id"]})
    return True, "OTP verified successfully."
