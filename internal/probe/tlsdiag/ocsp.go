package tlsdiag

import (
	"crypto/x509"
	"time"

	"golang.org/x/crypto/ocsp"
)

// analyzeStapledOCSP returns a report describing the OCSP response
// returned in the handshake, when present. It is strictly passive: no
// outbound HTTP request is ever issued.
//
// The issuer is used to validate the response signature. When the
// chain is incomplete (no issuer presented) we re-parse without
// verification so that at least the status field is exposed for
// diagnostics.
func analyzeStapledOCSP(leaf *x509.Certificate, presented []*x509.Certificate, ocspBytes []byte, now time.Time) *OCSPReport {
	rep := &OCSPReport{}
	if len(ocspBytes) == 0 {
		return rep
	}
	rep.Stapled = true

	var issuer *x509.Certificate
	if len(presented) > 1 {
		issuer = presented[1]
	}

	resp, err := ocsp.ParseResponse(ocspBytes, issuer)
	sigValid := true
	if err != nil {
		resp, err = ocsp.ParseResponse(ocspBytes, nil)
		if err != nil {
			rep.StapleStatus = "unparseable"
			return rep
		}
		sigValid = false
	}
	rep.StapleSigValid = &sigValid

	switch resp.Status {
	case ocsp.Good:
		rep.StapleStatus = "good"
	case ocsp.Revoked:
		rep.StapleStatus = "revoked"
		revokedAt := resp.RevokedAt
		rep.RevokedAt = &revokedAt
		rep.RevocationReason = revocationReasonString(resp.RevocationReason)
	case ocsp.Unknown:
		rep.StapleStatus = "unknown"
	}
	if leaf != nil && resp.SerialNumber != nil && leaf.SerialNumber != nil && leaf.SerialNumber.Cmp(resp.SerialNumber) != 0 {
		rep.StapleStatus = "serial_mismatch"
	}
	thisUpdate := resp.ThisUpdate
	rep.StapleThisUpdate = &thisUpdate
	rep.StapleAgeHours = now.Sub(resp.ThisUpdate).Hours()
	if !resp.NextUpdate.IsZero() {
		nextUpdate := resp.NextUpdate
		rep.StapleNextUpdate = &nextUpdate
		rep.StapleExpired = now.After(resp.NextUpdate)
	}
	return rep
}

// revocationReasonString maps the OCSP revocation reason enum onto the
// human-readable label defined by RFC 5280.
func revocationReasonString(r int) string {
	switch r {
	case 0:
		return "unspecified"
	case 1:
		return "key_compromise"
	case 2:
		return "ca_compromise"
	case 3:
		return "affiliation_changed"
	case 4:
		return "superseded"
	case 5:
		return "cessation_of_operation"
	case 6:
		return "certificate_hold"
	case 8:
		return "remove_from_crl"
	case 9:
		return "privilege_withdrawn"
	case 10:
		return "aa_compromise"
	}
	return "unknown"
}
