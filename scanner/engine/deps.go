package engine

import (
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

// Dependency extraction. The engine only *parses* manifests; vulnerability
// matching happens in the browser against OSV.dev (which is CORS-enabled),
// so the full pipeline still needs no backend.

const maxDepsPerFile = 600

var semverPrefix = regexp.MustCompile(`^[\^~><=! ]*v?`)

// cleanVersion strips range operators; returns the concrete version and
// whether it was an exact pin.
func cleanVersion(v string) (string, bool) {
	v = strings.TrimSpace(v)
	if v == "" || v == "*" || v == "latest" {
		return "", false
	}
	exact := !strings.ContainsAny(v, "^~><=*x|")
	v = semverPrefix.ReplaceAllString(v, "")
	// "1.2.3 - 2.0.0" or "1.x" style → take the first concrete chunk
	if i := strings.IndexAny(v, " ,|"); i > 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "git") ||
		strings.HasPrefix(v, "http") || strings.HasPrefix(v, "link:") || strings.HasPrefix(v, "workspace:") {
		return "", false
	}
	return v, exact
}

type depParser struct {
	match func(p string) bool
	parse func(p string, data []byte) []Dependency
}

var depParsers = []depParser{
	{ // package.json -------------------------------------------------- npm
		match: func(p string) bool { return path.Base(p) == "package.json" },
		parse: func(p string, data []byte) []Dependency {
			var pkg struct {
				Dependencies    map[string]string `json:"dependencies"`
				DevDependencies map[string]string `json:"devDependencies"`
			}
			if json.Unmarshal(data, &pkg) != nil {
				return nil
			}
			var out []Dependency
			add := func(m map[string]string, dev bool) {
				for name, ver := range m {
					if v, exact := cleanVersion(ver); v != "" {
						out = append(out, Dependency{Ecosystem: "npm", Name: name, Version: v, File: p, Dev: dev, Exact: exact})
					}
				}
			}
			add(pkg.Dependencies, false)
			add(pkg.DevDependencies, true)
			return out
		},
	},
	{ // package-lock.json (v2/v3): exact resolved versions ------------- npm
		match: func(p string) bool { return path.Base(p) == "package-lock.json" },
		parse: func(p string, data []byte) []Dependency {
			var lock struct {
				Packages map[string]struct {
					Version string `json:"version"`
					Dev     bool   `json:"dev"`
				} `json:"packages"`
			}
			if json.Unmarshal(data, &lock) != nil || len(lock.Packages) == 0 {
				return nil
			}
			var out []Dependency
			for key, info := range lock.Packages {
				if key == "" || info.Version == "" {
					continue
				}
				i := strings.LastIndex(key, "node_modules/")
				if i < 0 {
					continue
				}
				name := key[i+len("node_modules/"):]
				if name == "" || strings.Contains(name, "node_modules") {
					continue
				}
				out = append(out, Dependency{Ecosystem: "npm", Name: name, Version: info.Version, File: p, Dev: info.Dev, Exact: true})
				if len(out) >= maxDepsPerFile {
					break
				}
			}
			return out
		},
	},
	{ // requirements*.txt ---------------------------------------------- PyPI
		match: func(p string) bool {
			b := strings.ToLower(path.Base(p))
			return strings.HasPrefix(b, "requirements") && strings.HasSuffix(b, ".txt")
		},
		parse: func(p string, data []byte) []Dependency {
			re := regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*(==|>=|<=|~=|>|<)\s*([0-9][\w.\-+!]*)`)
			var out []Dependency
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
					continue
				}
				if m := re.FindStringSubmatch(line); m != nil {
					out = append(out, Dependency{Ecosystem: "PyPI", Name: strings.ToLower(m[1]), Version: m[3], File: p, Exact: m[2] == "=="})
				}
			}
			return out
		},
	},
	{ // pyproject.toml (PEP 621 + poetry, line-level best effort) ------ PyPI
		match: func(p string) bool { return path.Base(p) == "pyproject.toml" },
		parse: func(p string, data []byte) []Dependency {
			content := string(data)
			var out []Dependency
			// PEP 621 style: "name>=1.2.3" entries inside dependencies arrays
			reArr := regexp.MustCompile(`"([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:\[[^\]]*\])?\s*(==|>=|~=)\s*([0-9][\w.\-+!]*)`)
			for _, m := range reArr.FindAllStringSubmatch(content, maxDepsPerFile) {
				out = append(out, Dependency{Ecosystem: "PyPI", Name: strings.ToLower(m[1]), Version: m[3], File: p, Exact: m[2] == "=="})
			}
			// poetry style: name = "^1.2.3" under [tool.poetry.dependencies]
			if i := strings.Index(content, "[tool.poetry.dependencies]"); i >= 0 {
				section := content[i:]
				if j := strings.Index(section[1:], "\n["); j > 0 {
					section = section[:j+1]
				}
				rePoetry := regexp.MustCompile(`(?m)^([A-Za-z0-9][A-Za-z0-9._\-]*)\s*=\s*"([^"]+)"`)
				for _, m := range rePoetry.FindAllStringSubmatch(section, maxDepsPerFile) {
					if strings.EqualFold(m[1], "python") {
						continue
					}
					if v, exact := cleanVersion(m[2]); v != "" {
						out = append(out, Dependency{Ecosystem: "PyPI", Name: strings.ToLower(m[1]), Version: v, File: p, Exact: exact})
					}
				}
			}
			return out
		},
	},
	{ // go.mod ---------------------------------------------------------- Go
		match: func(p string) bool { return path.Base(p) == "go.mod" },
		parse: func(p string, data []byte) []Dependency {
			re := regexp.MustCompile(`(?m)^\s*(?:require\s+)?([\w.\-/]+\.[\w.\-/]+)\s+v([0-9][\w.\-+]*)\s*(//\s*indirect)?`)
			var out []Dependency
			for _, m := range re.FindAllStringSubmatch(string(data), maxDepsPerFile) {
				if m[3] != "" {
					continue // indirect
				}
				out = append(out, Dependency{Ecosystem: "Go", Name: m[1], Version: "v" + m[2], File: p, Exact: true})
			}
			return out
		},
	},
	{ // Cargo.toml -------------------------------------------------- crates.io
		match: func(p string) bool { return path.Base(p) == "Cargo.toml" },
		parse: func(p string, data []byte) []Dependency {
			content := string(data)
			i := strings.Index(content, "[dependencies]")
			if i < 0 {
				return nil
			}
			section := content[i:]
			if j := strings.Index(section[1:], "\n["); j > 0 {
				section = section[:j+1]
			}
			var out []Dependency
			reSimple := regexp.MustCompile(`(?m)^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"`)
			reTable := regexp.MustCompile(`(?m)^([A-Za-z0-9_\-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"`)
			for _, re := range []*regexp.Regexp{reSimple, reTable} {
				for _, m := range re.FindAllStringSubmatch(section, maxDepsPerFile) {
					if v, exact := cleanVersion(m[2]); v != "" {
						out = append(out, Dependency{Ecosystem: "crates.io", Name: m[1], Version: v, File: p, Exact: exact})
					}
				}
			}
			return out
		},
	},
	{ // Gemfile.lock (exact) + Gemfile (declared) -------------------- RubyGems
		match: func(p string) bool {
			b := path.Base(p)
			return b == "Gemfile" || b == "Gemfile.lock"
		},
		parse: func(p string, data []byte) []Dependency {
			var out []Dependency
			if path.Base(p) == "Gemfile.lock" {
				re := regexp.MustCompile(`(?m)^    ([A-Za-z0-9_\-]+) \(([0-9][\w.\-]*)\)`)
				for _, m := range re.FindAllStringSubmatch(string(data), maxDepsPerFile) {
					out = append(out, Dependency{Ecosystem: "RubyGems", Name: m[1], Version: m[2], File: p, Exact: true})
				}
				return out
			}
			re := regexp.MustCompile(`(?m)^\s*gem\s+['"]([A-Za-z0-9_\-]+)['"]\s*,\s*['"]([^'"]+)['"]`)
			for _, m := range re.FindAllStringSubmatch(string(data), maxDepsPerFile) {
				if v, exact := cleanVersion(m[2]); v != "" {
					out = append(out, Dependency{Ecosystem: "RubyGems", Name: m[1], Version: v, File: p, Exact: exact})
				}
			}
			return out
		},
	},
	{ // pom.xml ---------------------------------------------------------- Maven
		match: func(p string) bool { return path.Base(p) == "pom.xml" },
		parse: func(p string, data []byte) []Dependency {
			re := regexp.MustCompile(`(?s)<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([^<$]+)</version>`)
			var out []Dependency
			for _, m := range re.FindAllStringSubmatch(string(data), maxDepsPerFile) {
				ver := strings.TrimSpace(m[3])
				if ver == "" || strings.Contains(ver, "{") {
					continue // property-resolved
				}
				out = append(out, Dependency{Ecosystem: "Maven", Name: strings.TrimSpace(m[1]) + ":" + strings.TrimSpace(m[2]), Version: ver, File: p, Exact: true})
			}
			return out
		},
	},
	{ // build.gradle(.kts) ------------------------------------------------ Maven
		match: func(p string) bool {
			b := path.Base(p)
			return b == "build.gradle" || b == "build.gradle.kts"
		},
		parse: func(p string, data []byte) []Dependency {
			re := regexp.MustCompile(`(?m)(?:implementation|api|compile|runtimeOnly|testImplementation)\s*[\( ]\s*['"]([\w.\-]+):([\w.\-]+):([0-9][\w.\-]*)['"]`)
			var out []Dependency
			for _, m := range re.FindAllStringSubmatch(string(data), maxDepsPerFile) {
				out = append(out, Dependency{Ecosystem: "Maven", Name: m[1] + ":" + m[2], Version: m[3], File: p, Exact: true})
			}
			return out
		},
	},
	{ // composer.json -------------------------------------------------- Packagist
		match: func(p string) bool { return path.Base(p) == "composer.json" },
		parse: func(p string, data []byte) []Dependency {
			var pkg struct {
				Require    map[string]string `json:"require"`
				RequireDev map[string]string `json:"require-dev"`
			}
			if json.Unmarshal(data, &pkg) != nil {
				return nil
			}
			var out []Dependency
			add := func(m map[string]string, dev bool) {
				for name, ver := range m {
					if !strings.Contains(name, "/") {
						continue // skip "php", extensions
					}
					if v, exact := cleanVersion(ver); v != "" {
						out = append(out, Dependency{Ecosystem: "Packagist", Name: name, Version: v, File: p, Dev: dev, Exact: exact})
					}
				}
			}
			add(pkg.Require, false)
			add(pkg.RequireDev, true)
			return out
		},
	},
}

// extractDeps parses any recognized manifest, dropping duplicates
// (lockfile entries win over loose manifest declarations).
func extractDeps(files []InputFile) []Dependency {
	var all []Dependency
	for _, f := range files {
		if IsVendored(f.Path) {
			continue
		}
		for _, parser := range depParsers {
			if parser.match(f.Path) {
				all = append(all, parser.parse(f.Path, f.Data)...)
			}
		}
	}
	// Dedupe by ecosystem+name, preferring exact (lockfile) versions.
	seen := map[string]int{}
	var out []Dependency
	for _, d := range all {
		key := d.Ecosystem + "\x00" + strings.ToLower(d.Name)
		if i, ok := seen[key]; ok {
			if d.Exact && !out[i].Exact {
				out[i] = d
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, d)
	}
	return out
}
