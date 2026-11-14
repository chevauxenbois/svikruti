"""Loan applicant onboarding: collects identity and KYC documents."""

from flask import Flask, request, jsonify

from .models import Applicant, db
from .vault import encrypt_field

app = Flask(__name__)


@app.post("/applicants")
def create_applicant():
    payload = request.json
    applicant = Applicant(
        full_name=payload["full_name"],
        email=payload["email"],
        phone_number=payload["phone_number"],
        date_of_birth=payload["date_of_birth"],
        aadhaar=encrypt_field(payload["aadhaar"]),
        pan_number=encrypt_field(payload["pan_number"]),
    )
    db.session.add(applicant)
    db.session.commit()
    app.logger.info("applicant created id=%s", applicant.id)
    return jsonify({"id": applicant.id}), 201
