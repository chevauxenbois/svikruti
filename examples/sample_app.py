import logging

logger = logging.getLogger(__name__)


def signup(request, db):
    email = request.json["email"]
    mobile = request.json["mobile"]
    aadhaar = request.json.get("aadhaar")
    logger.info("new signup email=%s", email)
    db.users.insert({"email": email, "mobile": mobile, "aadhaar": aadhaar})
