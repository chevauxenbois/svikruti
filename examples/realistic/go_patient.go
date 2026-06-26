package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type PatientRequest struct {
	EmailAddress string `json:"email_address"`
	Diagnosis    string `json:"diagnosis"`
}

func createPatient(w http.ResponseWriter, r *http.Request) {
	var payload PatientRequest
	json.NewDecoder(r.Body).Decode(&payload)
	log.Printf("patient diagnosis %s", payload.Diagnosis)
	db.Create(payload)
}
