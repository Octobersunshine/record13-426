package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type CertInfo struct {
	Subject         string `json:"subject"`
	Issuer          string `json:"issuer"`
	SerialNumber    string `json:"serialNumber"`
	NotBefore       string `json:"notBefore"`
	NotAfter        string `json:"notAfter"`
	DaysRemaining   int    `json:"daysRemaining"`
	IsExpired       bool   `json:"isExpired"`
}

func parseCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST method allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var req struct {
		CertPath string `json:"certPath"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON format", http.StatusBadRequest)
		return
	}

	if req.CertPath == "" {
		http.Error(w, "certPath is required", http.StatusBadRequest)
		return
	}

	certInfo, err := parseCertificate(req.CertPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to parse certificate: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certInfo)
}

func parseCertificate(certPath string) (*CertInfo, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}

	var cert *x509.Certificate
	block, _ := pem.Decode(certData)
	if block != nil {
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PEM certificate: %w", err)
		}
	} else {
		cert, err = x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("parse DER certificate: %w", err)
		}
	}

	now := time.Now()
	daysRemaining := int(time.Until(cert.NotAfter).Hours() / 24)

	return &CertInfo{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SerialNumber:  cert.SerialNumber.String(),
		NotBefore:     cert.NotBefore.Format(time.RFC3339),
		NotAfter:      cert.NotAfter.Format(time.RFC3339),
		DaysRemaining: daysRemaining,
		IsExpired:     now.After(cert.NotAfter),
	}, nil
}

func main() {
	http.HandleFunc("/parse-cert", parseCertHandler)
	fmt.Println("server starting on :8080")
	http.ListenAndServe(":8080", nil)
}
