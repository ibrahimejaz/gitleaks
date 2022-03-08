package config

import (
	"regexp"
)

type Rule struct {
	Description string
	RuleID      string
	Entropy     float64
	SecretGroup int
	Regex       *regexp.Regexp
	Path        *regexp.Regexp
	Tags        []string
	Allowlist   Allowlist
	Extractors  []Rule
}

func (r *Rule) IncludeEntropy(secret string) (bool, float64) {
	// group = 0 will check the entropy of the whole regex match
	e := shannonEntropy(secret)
	if e > r.Entropy {
		return true, e
	}

	return false, e
}

func (r *Rule) EntropySet() bool {
	if r.Entropy == 0.0 {
		return false
	}
	return true
}
