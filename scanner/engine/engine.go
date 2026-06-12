package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// allContentRules is every prefiltered regex rule (secrets + code).
func allContentRules() []*Rule {
	out := make([]*Rule, 0, len(secretRules)+len(codeRules))
	out = append(out, secretRules...)
	out = append(out, codeRules...)
	return out
}

// Windowed matching: rule regexes only run on slices of the file around
// prefilter literal hits, never the whole content. This keeps the engine
// fast inside WASM even on multi-MB repositories (regex execution is the
// dominant cost otherwise — see the pprof history in the repo).
const (
	winBefore          = 400  // bytes of context before a literal hit
	winAfter           = 2000 // bytes after (long matches, e.g. JWTs)
	maxHitsPerLiteral  = 12
	lineExpandCap      = 300 // how far a window may grow to reach line bounds
)

// ruleWindows returns merged [start,end) content windows around every
// prefilter hit, expanded (within a cap) to line boundaries so ^/$ keep
// their meaning.
func ruleWindows(lower string, pres []string) [][2]int {
	var hits []int
	for _, lit := range pres {
		from := 0
		for n := 0; n < maxHitsPerLiteral; n++ {
			i := strings.Index(lower[from:], lit)
			if i < 0 {
				break
			}
			hits = append(hits, from+i)
			from += i + len(lit)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sort.Ints(hits)
	var wins [][2]int
	for _, h := range hits {
		s := h - winBefore
		if s < 0 {
			s = 0
		}
		e := h + winAfter
		if e > len(lower) {
			e = len(lower)
		}
		if len(wins) > 0 && s <= wins[len(wins)-1][1] {
			if e > wins[len(wins)-1][1] {
				wins[len(wins)-1][1] = e
			}
		} else {
			wins = append(wins, [2]int{s, e})
		}
	}
	for i := range wins {
		s, e := wins[i][0], wins[i][1]
		if s > 0 {
			lo := s - lineExpandCap
			if lo < 0 {
				lo = 0
			}
			if j := strings.LastIndexByte(lower[lo:s], '\n'); j >= 0 {
				s = lo + j + 1
			}
		}
		if e < len(lower) {
			hi := e + lineExpandCap
			if hi > len(lower) {
				hi = len(lower)
			}
			if j := strings.IndexByte(lower[e:hi], '\n'); j >= 0 {
				e += j
			}
		}
		wins[i] = [2]int{s, e}
	}
	return wins
}

// lineIndex precomputes line-start offsets for offset→line lookups.
type lineIndex []int

func buildLineIndex(s string) lineIndex {
	idx := lineIndex{0}
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			idx = append(idx, i+1)
		}
	}
	return idx
}

func (li lineIndex) lineOf(off int) int {
	lo, hi := 0, len(li)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if li[mid] <= off {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1 // 1-based
}

func (li lineIndex) lineText(s string, line int) string {
	start := li[line-1]
	end := len(s)
	if line < len(li) {
		end = li[line] - 1
	}
	t := s[start:end]
	return strings.TrimRight(t, "\r")
}

const maxSnippet = 180

func clipSnippet(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxSnippet {
		return s[:maxSnippet] + "…"
	}
	return s
}

// downgrade lowers severity one notch for findings in test/example paths.
func downgrade(s Severity) Severity {
	switch s {
	case SevCritical:
		return SevHigh
	case SevHigh:
		return SevMedium
	case SevMedium:
		return SevLow
	default:
		return SevInfo
	}
}

// Scan analyzes the given files and produces the full report.
func Scan(files []InputFile, optsIn Options) *Report {
	opts := optsIn.withDefaults()
	start := time.Now()
	rules := allContentRules()

	report := &Report{
		Files:     make([]FileInfo, 0, len(files)),
		Findings:  []Finding{},
		Languages: map[string]int64{},
	}
	report.Stats.RuleCount = len(rules) + len(configChecks) + 1 // +1: repo checks

	var totalScanned int64
	findingsByFile := map[string][]int{} // path -> indices into report.Findings

	addFinding := func(f Finding) {
		if len(report.Findings) >= opts.MaxFindings {
			return
		}
		if IsTestLike(f.File) && f.Category != CatHygiene {
			f.Severity = downgrade(f.Severity)
			f.TestContext = true
			f.Message += " (Found under a test/example path — severity reduced; verify it is not a live value.)"
		}
		f.ID = fmt.Sprintf("F%04d", len(report.Findings)+1)
		findingsByFile[f.File] = append(findingsByFile[f.File], len(report.Findings))
		report.Findings = append(report.Findings, f)
	}

	for i, in := range files {
		if opts.Progress != nil && (i%25 == 0 || i == len(files)-1) {
			opts.Progress(i+1, len(files), in.Path)
		}

		info := FileInfo{Path: in.Path, Size: len(in.Data), Lang: DetectLang(in.Path)}
		if len(in.Data) == 0 && in.Size > 0 {
			info.Size = in.Size
		}
		info.Binary = IsBinary(in.Data)
		info.Vendored = IsVendored(in.Path)

		if !info.Binary {
			info.Lines = CountLines(in.Data)
			info.Minified = IsMinified(in.Data, info.Lines)
			report.Stats.TotalLines += info.Lines
		}
		if info.Lang != "" && !info.Binary {
			report.Languages[info.Lang] += int64(len(in.Data))
		}
		report.Stats.TotalBytes += int64(len(in.Data))

		skip := false
		switch {
		case info.Binary:
			report.Stats.SkippedBinary++
			skip = true
		case info.Vendored || info.Minified || IsGenerated(in.Path):
			report.Stats.SkippedVendored++
			skip = true
		case len(in.Data) > opts.MaxFileBytes:
			report.Stats.SkippedLarge++
			skip = true
		case totalScanned > opts.MaxTotalBytes:
			report.Stats.SkippedLarge++
			skip = true
		}

		if !skip {
			report.Stats.ScannedFiles++
			totalScanned += int64(len(in.Data))
			content := string(in.Data)
			lower := strings.ToLower(content)
			var li lineIndex // built lazily on first finding

			for _, rule := range rules {
				if !rule.appliesTo(info.Lang) {
					continue
				}
				if rule.PathRe != nil && !rule.PathRe.MatchString(in.Path) {
					continue
				}
				var windows [][2]int
				if len(rule.Pre) > 0 {
					windows = ruleWindows(lower, rule.Pre)
					if windows == nil {
						continue
					}
				} else {
					windows = [][2]int{{0, len(content)}}
				}
				count := 0
				seenAt := map[int]bool{} // windows may overlap after expansion
			windowLoop:
				for _, w := range windows {
					slice := content[w[0]:w[1]]
					matches := rule.Re.FindAllStringSubmatchIndex(slice, opts.MaxPerRulePerFile+6)
					for _, m := range matches {
						if count >= opts.MaxPerRulePerFile {
							break windowLoop
						}
						start, end := m[0]+w[0], m[1]+w[0]
						if seenAt[start] {
							continue
						}
						seenAt[start] = true
						value := content[start:end]
						if rule.ValueGroup > 0 && 2*rule.ValueGroup+1 < len(m) && m[2*rule.ValueGroup] >= 0 {
							value = content[m[2*rule.ValueGroup]+w[0] : m[2*rule.ValueGroup+1]+w[0]]
						}
						if li == nil {
							li = buildLineIndex(content)
						}
						// Some patterns consume a preceding newline (boundary
						// prefixes like [^.\w]); attribute the finding to the
						// line the real match starts on.
						pos := start
						for pos < end && (content[pos] == '\n' || content[pos] == '\r') {
							pos++
						}
						ln := li.lineOf(pos)
						lineText := li.lineText(content, ln)
						if rule.Validate != nil && !rule.Validate(value, lineText) {
							continue
						}
						snippet := lineText
						if rule.Mask && value != "" {
							snippet = strings.Replace(lineText, value, maskValue(value), 1)
						}
						addFinding(Finding{
							RuleID: rule.ID, Title: rule.Title, Category: rule.Category,
							Severity: rule.Severity, File: in.Path, Line: ln,
							Snippet: clipSnippet(snippet), Message: rule.Message,
							Recommendation: rule.Recommendation, CWE: rule.CWE,
							Confidence: rule.Confidence,
						})
						count++
					}
				}
			}

			for _, check := range configChecks {
				if !check.match(in.Path) {
					continue
				}
				for _, f := range check.run(in.Path, content, nil) {
					f.Snippet = clipSnippet(f.Snippet)
					addFinding(f)
				}
			}
		}

		report.Files = append(report.Files, info)
	}

	for _, f := range repoChecks(files) {
		addFinding(f)
	}

	report.Dependencies = extractDeps(files)
	if report.Dependencies == nil {
		report.Dependencies = []Dependency{} // JSON must be [], never null
	}

	// Dedupe identical rule+file+line findings (overlapping rules can collide).
	seen := map[string]bool{}
	deduped := report.Findings[:0]
	for _, f := range report.Findings {
		key := f.RuleID + "\x00" + f.File + "\x00" + fmt.Sprint(f.Line)
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, f)
	}
	report.Findings = deduped

	// Sort by severity desc, then path for stable presentation.
	sort.SliceStable(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if SeverityRank(a.Severity) != SeverityRank(b.Severity) {
			return SeverityRank(a.Severity) > SeverityRank(b.Severity)
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	for i := range report.Findings {
		report.Findings[i].ID = fmt.Sprintf("F%04d", i+1)
	}

	// Roll finding counts up onto files.
	counts := map[string]int{}
	maxSev := map[string]Severity{}
	for _, f := range report.Findings {
		if f.File == "" {
			continue
		}
		counts[f.File]++
		if cur, ok := maxSev[f.File]; !ok || SeverityRank(f.Severity) > SeverityRank(cur) {
			maxSev[f.File] = f.Severity
		}
	}
	for i := range report.Files {
		p := report.Files[i].Path
		report.Files[i].Findings = counts[p]
		report.Files[i].MaxSeverity = maxSev[p]
	}

	report.Stats.FileCount = len(files)
	report.Stats.DurationMs = time.Since(start).Milliseconds()
	return report
}
