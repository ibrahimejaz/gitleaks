package detect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

type DetectFragment struct {
	text      string
	linePairs [][]int
	filepath  string
	commit    string
	rule      *config.Rule
	finding   *report.Finding
}

var (
	newlineRe *regexp.Regexp
	stopwords = []string{
		"process",
		"env",
		"setting",
		"getenv",
		"config",
		"cfg",
		"secret",
		"password",
		"token",
	}
)

const MAXGOROUTINES = 40

func init() {
	newlineRe = regexp.MustCompile("\n")
}

// Detector contains a configuration and a set of options for reporting
type Detector struct {
	cfg     config.Config
	verbose bool
	redact  bool
}

// NewDetector creates a new detector with the given configuration
func NewDetector(cfg config.Config, verbose bool, redact bool) *Detector {
	return &Detector{
		cfg:     cfg,
		verbose: verbose,
		redact:  redact,
	}
}

// Detect finds secrets
func (d *Detector) Detect(b []byte, filePath string, commit string) []report.Finding {
	var findings []report.Finding

	// check if we should skip file based on the global allowlist or if the file is the same as the gitleaks config
	if d.cfg.Allowlist.PathAllowed(filePath) || filePath == d.cfg.Path {
		return findings
	}

	// linePairs is used for determining the start and end line of a finding
	linePairs := newlineRe.FindAllIndex(b, -1)
nextrule:
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
					continue nextrule
				}
			} else {
				continue
			}
		}

		detectRuleFindings := d.detectRule(r, b, filePath, commit, linePairs)
		if len(r.Extractors) > 0 {
			// check extractors before appending findings
			for _, finding := range detectRuleFindings {
				for _, extractor := range r.Extractors {
					extractorFindings := d.detectRule(&extractor, []byte(finding.Match), filePath, commit, linePairs)
					if len(extractorFindings) > 0 {
						extractorFindings[0].StartLine = finding.StartLine
						extractorFindings[0].EndLine = finding.EndLine
						extractorFindings[0].StartColumn = finding.StartColumn
						extractorFindings[0].EndColumn = finding.EndColumn
						findings = append(findings, extractorFindings[0])
						break
					}
				}
			}
		} else {
			findings = append(findings, detectRuleFindings...)
		}

		// findings = postProcess(findings)
	}

	return findings
}

func (d *Detector) detectRule(r *config.Rule, b []byte, filePath string, commit string, linePairs [][]int) []report.Finding {
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
		skip := false
		if r.EntropySet() {
			include, entropy := r.IncludeEntropy(secret)
			if include {
				f.Entropy = float32(entropy)
			} else {
				skip = true
			}
		}
		if skip {
			continue
		}

		findings = append(findings, f)
	}
	return findings
}

func postProcess(findings []report.Finding) []report.Finding {
	var retFindings []report.Finding
	for _, f := range findings {
		include := true
		// deduplicate
		if strings.Contains(strings.ToLower(f.RuleID), "generic") {
			for _, fPrime := range findings {
				if f.StartLine == fPrime.StartLine &&
					f.EndLine == fPrime.EndLine &&
					f.Commit == fPrime.Commit &&
					f.RuleID != fPrime.RuleID &&
					strings.Contains(fPrime.Secret, f.Secret) &&
					!strings.Contains(strings.ToLower(fPrime.RuleID), "generic") {

					genericMatch := strings.Replace(f.Match, f.Secret, "REDACTED", -1)
					betterMatch := strings.Replace(fPrime.Match, fPrime.Secret, "REDACTED", -1)
					log.Debug().Msgf("skipping %s finding (%s), %s rule takes precendence (%s)", f.RuleID, genericMatch, fPrime.RuleID, betterMatch)
					include = false
					break
				}
			}
		}

		// check if secret has any stop words
		for _, stopword := range stopwords {
			if strings.Contains(strings.ToLower(f.Secret), stopword) {
				include = false
				break
			}
		}

		if include {
			retFindings = append(retFindings, f)
		}
	}

	return retFindings
}

func printFinding(f report.Finding) {
	var b []byte
	b, _ = json.MarshalIndent(f, "", "	")
	fmt.Println(string(b))
}
