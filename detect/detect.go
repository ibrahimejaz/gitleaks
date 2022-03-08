package detect

import (
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

type DetectFragment struct {
	text      string
	linePairs [][]int
	filepath  string
	commit    string
	rule      *config.Rule
	finding   *report.Finding
}

func NewDetector(cfg config.Config, verbose bool, redact bool) *Detector {
	return &Detector{
		cfg:     cfg,
		verbose: verbose,
		redact:  redact,
	}
}

func (d *Detector) detectRule(r *config.Rule, b []byte, filePath string, commit string, linePairs [][]int) []report.Finding {
	var findings []report.Finding
	matchIndices := r.Regex.FindAllIndex(b, -1)
nextmatch:
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
				continue nextmatch
			}
		}

		// Check if the finding has an extractor associated with the rule, if it does, then recurse into
		// detectRule to fill in details about the finding
		foundExtractor := false
		for _, extractor := range r.Extractors {
			extractorFindings := d.detectRule(&extractor, b, filePath, commit, linePairs)
			if len(extractorFindings) == 1 {
				foundExtractor = true
				fmt.Println(extractorFindings)
				f.Secret = extractorFindings[0].Secret
				f.RuleID = extractor.RuleID
				f.Description = extractor.Description
			}
		}

		// if the rule does not have any extractors associated with it, then add the finding to the findings
		// OR if the rule has an extractor associated with it AND the extractor found a finding, then add the
		// finding to the findings. This is to prevent duplicate findings.
		if len(r.Extractors) == 0 || foundExtractor {
			findings = append(findings, f)
		}
	}
	return findings
}

func (d *Detector) Detect(b []byte, filePath string, commit string) []report.Finding {
	var findings []report.Finding
	// check if we should skip file based on the global allowlist or if the file is the same as the gitleaks config
	if d.cfg.Allowlist.PathAllowed(filePath) || filePath == d.cfg.Path {
		return findings
	}

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

		findings = append(findings, d.detectRule(r, b, filePath, commit, linePairs)...)
	}

	// TODO
	// DEDUPE
	// POST FILTER (common words)
	// process.env
	// settings
	// getenv
	// env
	// config.
	// cfg.

	return findings
}

func printFinding(f report.Finding) {
	var b []byte
	b, _ = json.MarshalIndent(f, "", "	")
	fmt.Println(string(b))
}
