package engine

import (
	"bytes"
	"path"
	"strings"
)

// extToLang maps file extensions to display languages. Doubles as the
// "is this source code we understand" gate for code rules.
var extToLang = map[string]string{
	".js":     "JavaScript",
	".jsx":    "JavaScript",
	".mjs":    "JavaScript",
	".cjs":    "JavaScript",
	".ts":     "TypeScript",
	".tsx":    "TypeScript",
	".mts":    "TypeScript",
	".py":     "Python",
	".pyw":    "Python",
	".go":     "Go",
	".rb":     "Ruby",
	".rake":   "Ruby",
	".java":   "Java",
	".kt":     "Kotlin",
	".kts":    "Kotlin",
	".scala":  "Scala",
	".php":    "PHP",
	".cs":     "C#",
	".c":      "C",
	".h":      "C",
	".cpp":    "C++",
	".cc":     "C++",
	".cxx":    "C++",
	".hpp":    "C++",
	".rs":     "Rust",
	".swift":  "Swift",
	".m":      "Objective-C",
	".sh":     "Shell",
	".bash":   "Shell",
	".zsh":    "Shell",
	".ps1":    "PowerShell",
	".sql":    "SQL",
	".html":   "HTML",
	".htm":    "HTML",
	".vue":    "Vue",
	".svelte": "Svelte",
	".css":    "CSS",
	".scss":   "CSS",
	".less":   "CSS",
	".json":   "JSON",
	".yml":    "YAML",
	".yaml":   "YAML",
	".toml":   "TOML",
	".xml":    "XML",
	".md":     "Markdown",
	".rst":    "Markdown",
	".txt":    "Text",
	".env":    "DotEnv",
	".tf":     "Terraform",
	".tfvars": "Terraform",
	".proto":  "Protobuf",
	".gradle": "Gradle",
	".dart":   "Dart",
	".ex":     "Elixir",
	".exs":    "Elixir",
	".lua":    "Lua",
	".pl":     "Perl",
	".r":      "R",
	".ipynb":  "Notebook",
}

// specialNames classifies well-known extensionless files.
var specialNames = map[string]string{
	"dockerfile":     "Docker",
	"makefile":       "Makefile",
	"gemfile":        "Ruby",
	"rakefile":       "Ruby",
	"jenkinsfile":    "Groovy",
	"vagrantfile":    "Ruby",
	"procfile":       "Config",
	"cmakelists.txt": "CMake",
	".gitignore":     "Config",
	".dockerignore":  "Config",
	".editorconfig":  "Config",
	".npmrc":         "Config",
	".babelrc":       "JSON",
	".eslintrc":      "JSON",
}

// DetectLang returns a display language for a path ("" when unknown).
func DetectLang(p string) string {
	base := strings.ToLower(path.Base(p))
	if l, ok := specialNames[base]; ok {
		return l
	}
	if strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile") {
		return "Docker"
	}
	if strings.HasPrefix(base, ".env") {
		return "DotEnv"
	}
	ext := strings.ToLower(path.Ext(base))
	if l, ok := extToLang[ext]; ok {
		return l
	}
	return ""
}

// codeLangs are languages the SAST rules understand.
var codeLangs = map[string]bool{
	"JavaScript": true, "TypeScript": true, "Python": true, "Go": true,
	"Ruby": true, "Java": true, "Kotlin": true, "PHP": true, "C#": true,
	"C": true, "C++": true, "Rust": true, "Shell": true, "Vue": true,
	"Svelte": true, "HTML": true, "Swift": true, "Scala": true,
}

var vendoredDirs = []string{
	"node_modules/", "bower_components/", "vendor/", "third_party/",
	"thirdparty/", "external/", ".yarn/", "dist/", "build/", "out/",
	"target/", "venv/", ".venv/", "site-packages/", "__pycache__/",
	".terraform/", "coverage/", ".next/", ".nuxt/", "Pods/",
}

// IsVendored reports whether the path points into dependency / build output
// trees that the project's authors did not write.
func IsVendored(p string) bool {
	lp := strings.ToLower(p)
	for _, d := range vendoredDirs {
		if strings.HasPrefix(lp, d) || strings.Contains(lp, "/"+d) {
			return true
		}
	}
	base := path.Base(lp)
	if strings.HasSuffix(base, ".min.js") || strings.HasSuffix(base, ".min.css") ||
		strings.HasSuffix(base, ".bundle.js") || strings.HasSuffix(base, ".map") {
		return true
	}
	return false
}

// testPathHints mark files whose findings should be downgraded (examples,
// fixtures and tests frequently contain intentional "secrets").
var testPathHints = []string{
	"test/", "tests/", "__tests__/", "spec/", "specs/", "fixture", "fixtures/",
	"example", "examples/", "sample", "samples/", "mock", "mocks/", "demo",
	"e2e/", "testdata/", "docs/", "doc/", "_test.", ".test.", ".spec.",
}

// IsTestLike reports whether findings in this path deserve reduced severity.
func IsTestLike(p string) bool {
	lp := strings.ToLower(p)
	for _, h := range testPathHints {
		if strings.Contains(lp, h) {
			return true
		}
	}
	return false
}

// generatedNames are machine-written files that are pointless (and slow) to
// pattern-scan; they are still parsed for dependencies and shown in the city.
var generatedNames = map[string]bool{
	"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true,
	"go.sum": true, "cargo.lock": true, "composer.lock": true,
	"gemfile.lock": false, // small + dep-relevant; keep scanning
	"poetry.lock": true, "pipfile.lock": true, "flake.lock": true,
	"bun.lock": true, "deno.lock": true, "shrinkwrap.json": true,
}

// IsGenerated reports whether content rules should skip this file.
func IsGenerated(p string) bool {
	return generatedNames[strings.ToLower(path.Base(p))]
}

// IsBinary sniffs for NUL bytes in the first 8 KiB — the standard
// git-style heuristic.
func IsBinary(data []byte) bool {
	n := len(data)
	if n == 0 {
		return false
	}
	if n > 8192 {
		n = 8192
	}
	return bytes.IndexByte(data[:n], 0) >= 0
}

// IsMinified detects generated single-line bundles where line-based findings
// are meaningless noise.
func IsMinified(data []byte, lines int) bool {
	if len(data) < 2048 {
		return false
	}
	if lines == 0 {
		lines = 1
	}
	return len(data)/lines > 400
}

// CountLines counts newline-terminated lines (a trailing partial line counts).
func CountLines(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	n := bytes.Count(data, []byte{'\n'})
	if data[len(data)-1] != '\n' {
		n++
	}
	return n
}
