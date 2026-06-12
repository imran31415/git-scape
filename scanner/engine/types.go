// Package engine implements ThreatScape's client-side security analysis
// engine. It is compiled to WebAssembly and runs entirely in the browser:
// no repository content ever leaves the user's machine.
package engine

// Severity levels, ordered from worst to least concerning.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// SeverityRank returns a sortable rank (higher = more severe).
func SeverityRank(s Severity) int {
	switch s {
	case SevCritical:
		return 5
	case SevHigh:
		return 4
	case SevMedium:
		return 3
	case SevLow:
		return 2
	case SevInfo:
		return 1
	}
	return 0
}

// MaxSeverity returns the more severe of a and b.
func MaxSeverity(a, b Severity) Severity {
	if SeverityRank(a) >= SeverityRank(b) {
		return a
	}
	return b
}

// Category groups findings into threat archetypes. The frontend maps each
// category to a distinct 3D "threat actor" hovering over the city.
type Category string

const (
	CatSecret    Category = "secret"     // leaked credentials / keys
	CatInjection Category = "injection"  // code / command / SQL injection
	CatXSS       Category = "xss"        // cross-site scripting sinks
	CatCrypto    Category = "crypto"     // weak cryptography / randomness
	CatNetwork   Category = "network"    // cleartext transport, TLS bypass
	CatConfig    Category = "config"     // infrastructure misconfiguration
	CatCICD      Category = "cicd"       // CI/CD pipeline risks
	CatDependency Category = "dependency" // vulnerable third-party packages (filled by OSV on the JS side)
	CatHygiene   Category = "hygiene"    // repo hygiene / process gaps
)

// Finding is a single security observation tied to a file (and usually a line).
type Finding struct {
	ID             string   `json:"id"`
	RuleID         string   `json:"ruleId"`
	Title          string   `json:"title"`
	Category       Category `json:"category"`
	Severity       Severity `json:"severity"`
	File           string   `json:"file"`
	Line           int      `json:"line,omitempty"`
	Snippet        string   `json:"snippet,omitempty"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation,omitempty"`
	CWE            string   `json:"cwe,omitempty"`
	Confidence     string   `json:"confidence"` // high | medium | low
	// TestContext marks findings under test/example/docs paths: severity is
	// already downgraded one level, and the scorer weighs them lower still.
	TestContext bool `json:"testContext,omitempty"`
}

// FileInfo describes one repository file; the frontend turns these into
// buildings in the city.
type FileInfo struct {
	Path        string   `json:"path"`
	Size        int      `json:"size"`
	Lines       int      `json:"lines"`
	Lang        string   `json:"lang,omitempty"`
	Binary      bool     `json:"binary,omitempty"`
	Vendored    bool     `json:"vendored,omitempty"`
	Minified    bool     `json:"minified,omitempty"`
	Findings    int      `json:"findings,omitempty"`
	MaxSeverity Severity `json:"maxSeverity,omitempty"`
}

// Dependency is a declared third-party package, extracted from a manifest.
// The frontend cross-references these against the OSV.dev vulnerability
// database (CORS-enabled, queried straight from the browser).
type Dependency struct {
	Ecosystem string `json:"ecosystem"` // npm | PyPI | Go | crates.io | RubyGems | Maven | Packagist
	Name      string `json:"name"`
	Version   string `json:"version"`
	File      string `json:"file"`
	Dev       bool   `json:"dev,omitempty"`
	Exact     bool   `json:"exact"` // true when pinned to an exact version
}

// ScanStats summarizes what the engine looked at.
type ScanStats struct {
	FileCount       int   `json:"fileCount"`
	ScannedFiles    int   `json:"scannedFiles"`
	SkippedBinary   int   `json:"skippedBinary"`
	SkippedVendored int   `json:"skippedVendored"`
	SkippedLarge    int   `json:"skippedLarge"`
	TotalBytes      int64 `json:"totalBytes"`
	TotalLines      int   `json:"totalLines"`
	DurationMs      int64 `json:"durationMs"`
	RuleCount       int   `json:"ruleCount"`
}

// Report is the engine's complete output, serialized to JSON for the frontend.
// Scoring happens on the JS side so OSV results can be folded in first.
type Report struct {
	Files        []FileInfo       `json:"files"`
	Findings     []Finding        `json:"findings"`
	Dependencies []Dependency     `json:"dependencies"`
	Languages    map[string]int64 `json:"languages"` // bytes per language
	Stats        ScanStats        `json:"stats"`
}

// InputFile is one file handed to the engine. Size is only consulted when
// Data is nil (content withheld, e.g. an oversized file we still want to
// appear in the city skyline).
type InputFile struct {
	Path string
	Data []byte
	Size int
}

// Options tunes engine limits. Zero values select defaults.
type Options struct {
	MaxFileBytes    int   // per-file content cap (default 400 KiB)
	MaxTotalBytes   int64 // total scanned content cap (default 100 MiB)
	MaxFindings     int   // global findings cap (default 1500)
	MaxPerRulePerFile int // identical-rule-per-file cap (default 10)
	Progress        func(done, total int, path string)
}

func (o *Options) withDefaults() Options {
	out := *o
	if out.MaxFileBytes <= 0 {
		out.MaxFileBytes = 400 * 1024
	}
	if out.MaxTotalBytes <= 0 {
		out.MaxTotalBytes = 100 * 1024 * 1024
	}
	if out.MaxFindings <= 0 {
		out.MaxFindings = 1500
	}
	if out.MaxPerRulePerFile <= 0 {
		out.MaxPerRulePerFile = 10
	}
	return out
}
