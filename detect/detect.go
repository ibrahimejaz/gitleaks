package detect

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

var newlineRe *regexp.Regexp

func init() {
	newlineRe = regexp.MustCompile("\n")
}

type Options struct {
	Verbose bool
	Redact  bool
}

const MAXGOROUTINES = 40

type Detector struct {
	cfg     config.Config
	verbose bool
	redact  bool
}

type TextFragment struct {
	text      string
	linePairs [][]int
	filepath  string
	commit    string
}

func (d *Detector) DetectString(s string) []report.Finding {
	var findings []report.Finding
	return findings
}

func (d *Detector) DetectRule(r *config.Rule, b []byte, filePath string, commit string, linePairs [][]int) []report.Finding {
	var findings []report.Finding
	matchIndices := r.Regex.FindAllIndex(b, -1)
	for _, m := range matchIndices {
		location := getLocation(linePairs, m[0], m[1])
		secret := strings.Trim(string(b[m[0]:m[1]]), "\n")
		f := report.Finding{
			Description: r.Description,
			File:        filePath,
			RuleID:      r.RuleID,
			StartLine:   location.startLine,
			EndLine:     location.endLine,
			StartColumn: location.startColumn,
			EndColumn:   location.endColumn,
			Secret:      secret,
			Match:       secret,
			Tags:        r.Tags,
		}

		if r.Allowlist.RegexAllowed(f.Secret) || d.cfg.Allowlist.RegexAllowed(f.Secret) {
			continue
		}

		// extract secret from secret group if set
		if r.SecretGroup != 0 {
			groups := r.Regex.FindStringSubmatch(secret)
			if len(groups)-1 > r.SecretGroup || len(groups) == 0 {
				// Config validation should prevent this
				break
			}
			secret = groups[r.SecretGroup]
			f.Secret = secret
		}

		// extract secret from secret group if set
		if r.EntropySet() {
			include, entropy := r.IncludeEntropy(secret)
			if include {
				f.Entropy = float32(entropy)
			} else {
				return findings
			}
		}

		// check if rule has extractor and update finding if match
		for _, extractor := range r.Extractors {
			if extractor.Regex != nil && extractor.SecretGroup != 0 {
				groups := extractor.Regex.FindStringSubmatch(f.Match)
				if len(groups) < extractor.SecretGroup || len(groups) == 0 {
					continue
				}
				f.Secret = groups[extractor.SecretGroup]
				f.RuleID = extractor.ID
				f.Description = extractor.Description
				fmt.Println(f)
				goto APPENDFINDING
			} else if extractor.Regex != nil {
				// no secret group specific, check if there is a match
				secret := extractor.Regex.FindString(f.Match)
				if secret != "" {
					f.Secret = secret
					goto APPENDFINDING
				}
			}
		}
	APPENDFINDING:
		findings = append(findings, f)
	}
	return findings
}

func (d *Detector) Detect(b []byte, filePath string, commit string) []report.Finding {
	var findings []report.Finding
	// check if we should skip file based on the global allowlist or if the file is the same as the gitleaks config
	if d.cfg.Allowlist.PathAllowed(filePath) || filePath == d.cfg.Path {
		return findings
	}

	b = bytes.ToLower(b)
	linePairs := newlineRe.FindAllIndex(b, -1)
NEXTRULE:
	for _, r := range d.cfg.Rules {
		if r.Allowlist.CommitAllowed(commit) {
			continue
		}
		if r.Allowlist.PathAllowed(filePath) {
			continue
		}

		// Check if path should be considered
		if r.Path != nil {
			if r.Path.Match([]byte(filePath)) {
				if r.Regex == nil {
					// This is a path only rule
					f := report.Finding{
						Description: r.Description,
						File:        filePath,
						RuleID:      r.RuleID,
						Match:       fmt.Sprintf("file detected: %s", filePath),
						Tags:        r.Tags,
					}
					findings = append(findings, f)
					continue NEXTRULE
				}
			}
		}

		findings = append(findings, d.DetectRule(r, b, filePath, commit, linePairs)...)
	}
	return findings
}

func printFinding(f report.Finding) {
	var b []byte
	b, _ = json.MarshalIndent(f, "", "	")
	fmt.Println(string(b))
}
