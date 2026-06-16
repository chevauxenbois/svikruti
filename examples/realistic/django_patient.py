from django.db import models


class Patient(models.Model):
    full_name = models.CharField(max_length=255)
    email = models.EmailField()
    phone_number = models.CharField(max_length=20)
    diagnosis = models.TextField()
    prescription = models.TextField()
    blood_group = models.CharField(max_length=4)


def create_patient(request):
    payload = request.json()
    Patient.objects.create(
        full_name=payload["full_name"],
        email=payload["email"],
        phone_number=payload["phone_number"],
        diagnosis=payload["diagnosis"],
        prescription=payload["prescription"],
        blood_group=payload["blood_group"],
    )
