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
	Subject       string `json:"subject"`
	Issuer        string `json:"issuer"`
	SerialNumber  string `json:"serialNumber"`
	NotBefore     string `json:"notBefore"`
	NotAfter      string `json:"notAfter"`
	DaysRemaining int    `json:"daysRemaining"`
	IsExpired     bool   `json:"isExpired"`
}

type ChainNodeInfo struct {
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	SerialNumber string `json:"serialNumber"`
	NotBefore    string `json:"notBefore"`
	NotAfter     string `json:"notAfter"`
	IsCA         bool   `json:"isCA"`
	IsSelfSigned bool   `json:"isSelfSigned"`
	IsExpired    bool   `json:"isExpired"`
	DaysRemaining int   `json:"daysRemaining"`
}

type ChainVerifyResult struct {
	Valid           bool            `json:"valid"`
	ChainLength     int             `json:"chainLength"`
	Chain           []ChainNodeInfo `json:"chain"`
	Errors          []string        `json:"errors"`
	Warnings        []string        `json:"warnings"`
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

func verifyCertChainHandler(w http.ResponseWriter, r *http.Request) {
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
		CertPath              string   `json:"certPath"`
		IntermediateCertPaths []string `json:"intermediateCertPaths"`
		RootCertPaths         []string `json:"rootCertPaths"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid JSON format", http.StatusBadRequest)
		return
	}

	if req.CertPath == "" {
		http.Error(w, "certPath is required", http.StatusBadRequest)
		return
	}

	result, err := verifyCertificateChain(req.CertPath, req.IntermediateCertPaths, req.RootCertPaths)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to verify certificate chain: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func isEncryptedPEM(block *pem.Block) bool {
	if procType, ok := block.Headers["Proc-Type"]; ok {
		if len(procType) >= 9 && procType[:9] == "4,ENCRYPTED" {
			return true
		}
	}
	if len(block.Type) >= 9 && block.Type[:9] == "ENCRYPTED" {
		return true
	}
	return false
}

func loadCertificate(certPath string) (*x509.Certificate, error) {
	certData, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read certificate file: %w", err)
	}

	var cert *x509.Certificate
	block, _ := pem.Decode(certData)
	if block != nil {
		if isEncryptedPEM(block) {
			return nil, fmt.Errorf("encrypted PEM certificate is not supported, please decrypt first")
		}
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
	return cert, nil
}

func parseCertificate(certPath string) (*CertInfo, error) {
	cert, err := loadCertificate(certPath)
	if err != nil {
		return nil, err
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

func isSelfSigned(cert *x509.Certificate) bool {
	return cert.Subject.String() == cert.Issuer.String()
}

func toChainNode(cert *x509.Certificate) ChainNodeInfo {
	now := time.Now()
	return ChainNodeInfo{
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		SerialNumber:  cert.SerialNumber.String(),
		NotBefore:     cert.NotBefore.Format(time.RFC3339),
		NotAfter:      cert.NotAfter.Format(time.RFC3339),
		IsCA:          cert.IsCA,
		IsSelfSigned:  isSelfSigned(cert),
		IsExpired:     now.After(cert.NotAfter),
		DaysRemaining: int(time.Until(cert.NotAfter).Hours() / 24),
	}
}

func loadCerts(paths []string) ([]*x509.Certificate, []string) {
	var certs []*x509.Certificate
	var errors []string
	for _, p := range paths {
		cert, err := loadCertificate(p)
		if err != nil {
			errors = append(errors, fmt.Sprintf("load %s: %v", p, err))
			continue
		}
		certs = append(certs, cert)
	}
	return certs, errors
}

func verifyCertificateChain(certPath string, intermediateCertPaths, rootCertPaths []string) (*ChainVerifyResult, error) {
	leafCert, err := loadCertificate(certPath)
	if err != nil {
		return nil, err
	}

	intermediates, loadErrors := loadCerts(intermediateCertPaths)
	roots, rootLoadErrors := loadCerts(rootCertPaths)
	loadErrors = append(loadErrors, rootLoadErrors...)

	result := &ChainVerifyResult{
		Valid:    true,
		Chain:    []ChainNodeInfo{},
		Errors:   loadErrors,
		Warnings: []string{},
	}

	now := time.Now()

	if now.Before(leafCert.NotBefore) {
		result.Errors = append(result.Errors, fmt.Sprintf("leaf certificate not yet valid (valid from %s)", leafCert.NotBefore.Format(time.RFC3339)))
	}
	if now.After(leafCert.NotAfter) {
		result.Errors = append(result.Errors, fmt.Sprintf("leaf certificate expired at %s", leafCert.NotAfter.Format(time.RFC3339)))
	}
	for _, c := range intermediates {
		if now.After(c.NotAfter) {
			result.Errors = append(result.Errors, fmt.Sprintf("intermediate certificate expired: %s", c.Subject.String()))
		}
		if !c.IsCA {
			result.Errors = append(result.Errors, fmt.Sprintf("intermediate is not a CA: %s", c.Subject.String()))
		}
	}
	for _, c := range roots {
		if !isSelfSigned(c) {
			result.Warnings = append(result.Warnings, fmt.Sprintf("root certificate is not self-signed: %s", c.Subject.String()))
		}
		if !c.IsCA {
			result.Errors = append(result.Errors, fmt.Sprintf("root is not a CA: %s", c.Subject.String()))
		}
		if now.After(c.NotAfter) {
			result.Errors = append(result.Errors, fmt.Sprintf("root certificate expired: %s", c.Subject.String()))
		}
	}

	rootPool := x509.NewCertPool()
	for _, c := range roots {
		rootPool.AddCert(c)
	}

	intermediatePool := x509.NewCertPool()
	for _, c := range intermediates {
		intermediatePool.AddCert(c)
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
		CurrentTime:   now,
		KeyUsages:      []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	chains, err := leafCert.Verify(verifyOpts)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("chain verification failed: %v", err))
	} else if len(chains) == 0 {
		result.Valid = false
		result.Errors = append(result.Errors, "no valid chain found")
	} else {
		bestChain := chains[0]
		result.ChainLength = len(bestChain)
		for _, c := range bestChain {
			result.Chain = append(result.Chain, toChainNode(c))
		}
		if len(roots) == 0 {
			chainRoot := bestChain[len(bestChain)-1]
			if !isSelfSigned(chainRoot) {
				result.Warnings = append(result.Warnings, "chain terminates at a non-self-signed certificate; provide root cert for full verification")
			}
		}
	}

	if len(result.Errors) > 0 {
		result.Valid = false
	}
	if result.Chain == nil {
		result.Chain = []ChainNodeInfo{}
	}
	if result.Warnings == nil {
		result.Warnings = []string{}
	}

	return result, nil
}

func main() {
	http.HandleFunc("/parse-cert", parseCertHandler)
	http.HandleFunc("/verify-cert-chain", verifyCertChainHandler)
	fmt.Println("server starting on :8080")
	http.ListenAndServe(":8080", nil)
}
