"""Repayment reminders over SMS through MSG91."""

import os

import requests

MSG91_URL = "https://control.msg91.com/api/v5/flow/"


def send_reminder(phone_number: str, template_id: str) -> None:
    response = requests.post(
        MSG91_URL,
        json={"template_id": template_id, "recipients": [{"mobiles": phone_number}]},
        headers={"authkey": os.environ["MSG91_AUTH_KEY"]},
        timeout=10,
    )
    response.raise_for_status()


def send_due_reminders(borrowers) -> None:
    """Reminders run on consent: a borrower who withdraws stops getting them."""
    for borrower in borrowers:
        if not borrower.reminder_consent:
            continue
        send_reminder(borrower.phone_number, "emi_due")
