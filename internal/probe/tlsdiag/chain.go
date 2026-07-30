package tlsdiag

import (
	"crypto/x509"
	"time"
)

// analyzeChain runs a multi-pass verification of the presented chain:
//
//  1. Strict: with everything the server presented. If this succeeds,
//     the chain is good.
//  2. Time-stripped: re-run with CurrentTime set inside the leaf's
//     validity window. Succeeds means "the chain is fine, the only
//     problem is expiry".
//  3. Hostname-stripped: re-run without DNSName. Succeeds means the
//     hostname doesn't match but the chain itself is OK.
//  4. AIA-recoverable: NOT IMPLEMENTED in v1 — AIA fetch is a
//     secondary SSRF channel and is hard-disabled.
//
// The analyseChain also reports structural anomalies that do not
// require crypto verification (ordering, root inclusion, extraneous
// certs, leaf-not-first, duplicate certificates).
func analyzeChain(
	presented []*x509.Certificate,
	hostname string,
	roots *x509.CertPool,
	now time.Time,
	includePEM bool,
) ChainReport {
	rep := ChainReport{Length: len(presented), PresentedCerts: []CertReport{}}
	if len(presented) == 0 {
		rep.VerificationError = "no certificates presented"
		return rep
	}
	leaf := presented[0]

	for i, c := range presented {
		rep.PresentedCerts = append(rep.PresentedCerts, describeCert(c, hostname, now, includePEM))
		if i == 0 && c != leaf {
			// Only used for assertion in tests.
			_ = i
		}
	}

	intermediates := x509.NewCertPool()
	for _, c := range presented[1:] {
		intermediates.AddCert(c)
	}
	opts := x509.VerifyOptions{
		DNSName:       hostname,
		Intermediates: intermediates,
		Roots:         roots,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	chains, err := leaf.Verify(opts)
	if err == nil {
		rep.Complete = true
		rep.TrustedBySystem = true
		rep.HostnameMatches = true
		rep.VerifiedChains = describeVerifiedChains(chains)
	} else {
		rep.VerificationError = err.Error()
		// Try without the time constraint to disentangle "expired"
		// from "chain broken".
		optsNoTime := opts
		optsNoTime.CurrentTime = leaf.NotBefore.Add(time.Second)
		if _, e2 := leaf.Verify(optsNoTime); e2 == nil {
			rep.Complete = true
		}
		// Try without the hostname to disentangle "wrong name"
		// from "chain broken".
		optsNoName := opts
		optsNoName.DNSName = ""
		if _, e3 := leaf.Verify(optsNoName); e3 == nil {
			if !rep.Complete {
				rep.Complete = true
			}
		} else if !rep.Complete {
			rep.MissingIntermediate = isOnlyMissingIntermediate(err)
		}
	}

	matches, matched := hostnameMatches(leaf, hostname)
	rep.HostnameMatches = matches
	rep.MatchedName = matched

	rep.Ordered = isChainOrdered(presented)
	if len(presented) > 1 && isSelfSigned(presented[len(presented)-1]) {
		rep.RootIncluded = true
	}
	if extras := findExtraneous(presented); len(extras) > 0 {
		rep.ExtraneousCerts = extras
	}

	// Duplicate detection.
	if dup := findDuplicate(presented); len(dup) > 0 {
		if rep.ExtraneousCerts == nil {
			rep.ExtraneousCerts = dup
		} else {
			rep.ExtraneousCerts = append(rep.ExtraneousCerts, dup...)
		}
	}
	return rep
}

// describeVerifiedChains returns a list of certificate subject chains
// that successfully validated. The output is intentionally minimal —
// one subject string per certificate — to keep the report size small.
func describeVerifiedChains(chains [][]*x509.Certificate) [][]string {
	if len(chains) == 0 {
		return nil
	}
	out := make([][]string, 0, len(chains))
	for _, c := range chains {
		row := make([]string, 0, len(c))
		for _, cert := range c {
			row = append(row, cert.Subject.String())
		}
		out = append(out, row)
	}
	return out
}

// findDuplicate returns subjects of certificates that appear more than
// once in the presented chain.
func findDuplicate(certs []*x509.Certificate) []string {
	if len(certs) < 2 {
		return nil
	}
	seen := make(map[string]int, len(certs))
	for _, c := range certs {
		seen[c.Subject.String()]++
	}
	var out []string
	for sub, n := range seen {
		if n > 1 {
			out = append(out, sub)
		}
	}
	return out
}

// isOnlyMissingIntermediate attempts to distinguish "chain broken
// because the issuer is missing" from other verification failures, so
// we can attribute the right finding.
//
// Go's x509 package does not surface a typed error for this, so the
// heuristic looks for the canonical error wording.
func isOnlyMissingIntermediate(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	// "unable to get local issuer certificate" is Go's wording when
	// the issuer is missing from the supplied intermediates pool.
	return containsCI(s, "unable to get local issuer certificate") ||
		containsCI(s, "certificate signed by unknown authority")
}

func containsCI(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(haystack) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			h := haystack[i+j]
			n := needle[j]
			if h >= 'A' && h <= 'Z' {
				h += 'a' - 'A'
			}
			if n >= 'A' && n <= 'Z' {
				n += 'a' - 'A'
			}
			if h != n {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// chainHasNoEndEntity returns true when no certificate in the chain is
// plausibly a leaf (no ExtKeyUsage serverAuth AND no DNSNames / IP
// addresses). Used by rules.go to detect "leaf-not-first" anomalies.
func chainHasNoEndEntity(certs []*x509.Certificate) bool {
	if len(certs) == 0 {
		return true
	}
	for _, c := range certs {
		if len(c.DNSNames) > 0 || len(c.IPAddresses) > 0 || len(c.URIs) > 0 {
			return false
		}
	}
	return true
}
