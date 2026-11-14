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
