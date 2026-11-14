from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Applicant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    aadhaar = db.Column(db.LargeBinary, nullable=False)  # AES-GCM ciphertext
    pan_number = db.Column(db.LargeBinary, nullable=False)  # AES-GCM ciphertext
