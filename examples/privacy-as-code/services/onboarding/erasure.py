"""Erasure requests (DPDP Act Sec. 12, GDPR Art. 17).

Applicant records are anonymised once the PML retention period ends, or on a
verified erasure request when no retention obligation applies.
"""

from .models import Applicant, db


def handle_erasure_request(applicant_id: int) -> None:
    applicant = Applicant.query.get(applicant_id)
    if applicant is None:
        return
    _anonymise(applicant)
    db.session.commit()


def _anonymise(applicant: Applicant) -> None:
    applicant.full_name = "erased"
    applicant.email = f"erased+{applicant.id}@invalid"
    applicant.phone_number = ""
    applicant.aadhaar = b""
    applicant.pan_number = b""
