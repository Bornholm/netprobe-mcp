// Grade and score computation. Maps a report onto a letter grade
// (A+ .. F) and a 0-100 score. The function is purely functional
// and lives outside the analyser so that any phase can contribute
// inputs without rewiring the type.

package tlsdiag

// computeGrade returns the grade letter and the underlying score.
//
// Rules:
//
//   - Any critical finding caps the grade at F.
//   - Otherwise score = 100 - 20*high - 8*medium - 3*low.
//   - Grade bands: A+ ≥ 95, A ≥ 85, B ≥ 70, C ≥ 55, D ≥ 40, E ≥ 20,
//     F < 20.
//   - A+ requires score == 100 AND TLS 1.3 was negotiated AND no
//     finding of medium severity or above.
//
// The function is conservative: "healthy" findings (info, low) do
// not affect the score by themselves.
func computeGrade(rep *Report) (string, int) {
	if rep == nil {
		return "F", 0
	}
	if rep.Summary.Critical > 0 {
		return "F", 0
	}
	score := 100 - 20*rep.Summary.High - 8*rep.Summary.Medium - 3*rep.Summary.Low
	if score < 0 {
		score = 0
	}

	grade := gradeFromScore(score)
	if grade == "A" && score == 100 && rep.Handshake.Version == "TLS 1.3" && rep.Summary.Medium == 0 && rep.Summary.High == 0 {
		grade = "A+"
	}
	return grade, score
}

// gradeFromScore returns the letter grade for a numeric score.
func gradeFromScore(score int) string {
	switch {
	case score >= 95:
		return "A"
	case score >= 85:
		return "B"
	case score >= 70:
		return "C"
	case score >= 55:
		return "D"
	case score >= 40:
		return "E"
	}
	return "F"
}
