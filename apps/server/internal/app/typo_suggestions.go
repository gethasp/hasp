package app

import "strings"

// levenshtein returns the edit distance between two strings using iterative DP.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	// Allocate two rows.
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			del := prev[j] + 1
			ins := curr[j-1] + 1
			sub := prev[j-1] + cost
			m := del
			if ins < m {
				m = ins
			}
			if sub < m {
				m = sub
			}
			curr[j] = m
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

// typoThreshold returns the maximum edit distance that qualifies as a typo
// suggestion for an input of length n.
func typoThreshold(n int) int {
	if n <= 3 {
		return 1
	}
	return 2
}

// closestMatch finds the closest candidate to input (case-insensitive) from
// candidates. Returns ("", false) when nothing is within the typo threshold.
func closestMatch(input string, candidates []string) (string, bool) {
	lower := strings.ToLower(input)
	threshold := typoThreshold(len([]rune(lower)))
	best := threshold + 1
	bestCandidate := ""
	for _, c := range candidates {
		d := levenshtein(lower, strings.ToLower(c))
		if d < best {
			best = d
			bestCandidate = c
		}
	}
	if best > threshold {
		return "", false
	}
	return bestCandidate, true
}
