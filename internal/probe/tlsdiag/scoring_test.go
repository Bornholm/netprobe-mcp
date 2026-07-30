// Tests for the grade / score computation.

package tlsdiag

import (
	"testing"
)

func TestComputeGrade_Healthy(t *testing.T) {
	rep := &Report{
		Handshake: HandshakeInfo{Version: "TLS 1.3"},
		Summary:   FindingCounts{},
	}
	g, s := computeGrade(rep)
	if g != "A+" {
		t.Errorf("expected grade A+, got %s (score %d)", g, s)
	}
	if s != 100 {
		t.Errorf("expected score=100, got %d", s)
	}
}

func TestComputeGrade_A_NotAplus(t *testing.T) {
	// A but not A+: score is 100 but TLS 1.2, not 1.3.
	rep := &Report{
		Handshake: HandshakeInfo{Version: "TLS 1.2"},
		Summary:   FindingCounts{},
	}
	g, s := computeGrade(rep)
	if g != "A" {
		t.Errorf("expected grade A, got %s (score %d)", g, s)
	}
}

func TestComputeGrade_Critical(t *testing.T) {
	rep := &Report{
		Summary: FindingCounts{Critical: 1},
	}
	g, s := computeGrade(rep)
	if g != "F" {
		t.Errorf("expected grade F on critical, got %s (score %d)", g, s)
	}
	if s != 0 {
		t.Errorf("expected score=0 on critical, got %d", s)
	}
}

func TestComputeGrade_HighMediumLow(t *testing.T) {
	rep := &Report{
		Handshake: HandshakeInfo{Version: "TLS 1.3"},
		Summary:   FindingCounts{High: 2, Medium: 1, Low: 1},
	}
	// 100 - 2*20 - 1*8 - 1*3 = 49 → E
	g, s := computeGrade(rep)
	if g != "E" || s != 49 {
		t.Errorf("expected grade E, score 49, got %s score %d", g, s)
	}
}

func TestComputeGrade_NilReport(t *testing.T) {
	g, s := computeGrade(nil)
	if g != "F" || s != 0 {
		t.Errorf("expected F/0 on nil report, got %s/%d", g, s)
	}
}

func TestGradeFromScore(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{100, "A"},
		{95, "A"},
		{94, "B"},
		{85, "B"},
		{84, "C"},
		{70, "C"},
		{69, "D"},
		{55, "D"},
		{54, "E"},
		{40, "E"},
		{39, "F"},
		{0, "F"},
	}
	for _, c := range cases {
		if got := gradeFromScore(c.score); got != c.want {
			t.Errorf("gradeFromScore(%d) = %s, want %s", c.score, got, c.want)
		}
	}
}
