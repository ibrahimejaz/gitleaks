package detect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/report"
)

type Options struct {
	Verbose bool
	Redact  bool
}

const MAXGOROUTINES = 4

func DetectFindings(cfg config.Config, b []byte, filePath string, commit string) []report.Finding {
	var findings []report.Finding
	linePairs := regexp.MustCompile("\n").FindAllIndex(b, -1)

	// check if we should skip file based on the global allowlist or if the file is the same as the gitleaks config
	if cfg.Allowlist.PathAllowed(filePath) || filePath == cfg.Path {
		return findings
	}

	for _, r := range cfg.Rules {
		pathSkip := false
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
					pathSkip = true
				}
			} else {
				pathSkip = true
			}
		}
		if pathSkip {
			continue
		}

		start := time.Now()
		matchIndices := r.Regex.FindAllIndex(b, -1)
		Timings.Add(r.Regex.String(), time.Now().Sub(start))
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

			if r.Allowlist.RegexAllowed(f.Secret) || cfg.Allowlist.RegexAllowed(f.Secret) {
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
					findings = append(findings, f)
				}
			} else {
				findings = append(findings, f)
			}

			// check if rule has extractor and augment finding if match
			for _, extractor := range r.Extractors {
				if extractor.MustContain != "" {
					if strings.Contains(strings.ToLower(f.Match),
						strings.ToLower(extractor.MustContain)) {
						if extractor.Regex.MatchString(f.Secret) {
							fmt.Println(f)
							f.RuleID = extractor.ID
						}
					}
				}
			}
		}
	}

	return findings
}

func printFinding(f report.Finding) {
	var b []byte
	b, _ = json.MarshalIndent(f, "", "	")
	fmt.Println(string(b))
}
