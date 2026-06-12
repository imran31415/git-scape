package engine

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func scanOne(t *testing.T, path, content string) *Report {
	t.Helper()
	return Scan([]InputFile{{Path: path, Data: []byte(content)}}, Options{})
}

func findRule(r *Report, rule string) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

func TestAWSKeyDetectedAndMasked(t *testing.T) {
	r := scanOne(t, "config/prod.py", `AWS_KEY = "AKIAIOSFODNN7EXAMPL2"`+"\nx = 1\n")
	fs := findRule(r, "secret.aws-access-key")
	if len(fs) != 1 {
		t.Fatalf("expected 1 aws key finding, got %d (%v)", len(fs), r.Findings)
	}
	f := fs[0]
	if f.Line != 1 {
		t.Errorf("line = %d, want 1", f.Line)
	}
	if strings.Contains(f.Snippet, "AKIAIOSFODNN7EXAMPL2") {
		t.Errorf("snippet leaks the full secret: %q", f.Snippet)
	}
	if !strings.Contains(f.Snippet, "AKIA") || !strings.Contains(f.Snippet, "•") {
		t.Errorf("snippet should be partially masked: %q", f.Snippet)
	}
	if f.Severity != SevCritical {
		t.Errorf("severity = %s, want critical", f.Severity)
	}
}

func TestPlaceholderSecretsIgnored(t *testing.T) {
	r := scanOne(t, "docs/setup.md", `Set api_key = "YOUR_API_KEY_GOES_HERE_12345" and password = "changeme123"`)
	if n := len(findRule(r, "secret.generic-api-key")) + len(findRule(r, "secret.generic-password")); n != 0 {
		t.Fatalf("placeholders should not be findings, got %d", n)
	}
}

func TestGenericSecretRequiresEntropy(t *testing.T) {
	low := scanOne(t, "a.js", `const api_key = "aaaaaaaaaaaaaaaaaaaaaa";`)
	if len(findRule(low, "secret.generic-api-key")) != 0 {
		t.Fatal("low-entropy value should be rejected")
	}
	high := scanOne(t, "a.js", `const api_key = "9fJ2kX7qLmP4vR8tW3yZ6bN1cD5gH0sA";`)
	if len(findRule(high, "secret.generic-api-key")) != 1 {
		t.Fatal("high-entropy assignment should be flagged")
	}
}

func TestGitHubTokenAndPrivateKey(t *testing.T) {
	content := "token := \"ghp_x7K9mQ2pL4vR8tW3yZ6bN1cD5gH0sAfJkLmN\"\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n"
	r := scanOne(t, "cmd/deploy.go", content)
	if len(findRule(r, "secret.github-token")) != 1 {
		t.Error("github token not found")
	}
	if len(findRule(r, "secret.private-key")) != 1 {
		t.Error("private key not found")
	}
}

func TestConnectionString(t *testing.T) {
	r := scanOne(t, "settings.py", `DATABASE_URL = "postgres://admin:hunter2secret@db.internal:5432/prod"`)
	if len(findRule(r, "secret.connection-string")) != 1 {
		t.Fatalf("connection string not flagged: %+v", r.Findings)
	}
}

func TestTestPathDowngrade(t *testing.T) {
	prod := scanOne(t, "src/db.py", `c.execute(f"SELECT * FROM users WHERE id={uid}")`)
	test := scanOne(t, "tests/test_db.py", `c.execute(f"SELECT * FROM users WHERE id={uid}")`)
	pf, tf := findRule(prod, "py.sql-format"), findRule(test, "py.sql-format")
	if len(pf) != 1 || len(tf) != 1 {
		t.Fatalf("rule should fire in both, got %d/%d", len(pf), len(tf))
	}
	if SeverityRank(tf[0].Severity) >= SeverityRank(pf[0].Severity) {
		t.Errorf("test-path severity (%s) should be lower than prod (%s)", tf[0].Severity, pf[0].Severity)
	}
}

func TestJSRules(t *testing.T) {
	content := strings.Join([]string{
		`const out = eval(userInput);`,
		`el.innerHTML = data;`,
		`exec("ls " + dir);`,
		"db.query(`SELECT * FROM t WHERE id=${id}`);",
		`https.request({rejectUnauthorized: false});`,
		`crypto.createHash('md5').update(pw);`,
		`const resetToken = Math.random().toString(36);`,
	}, "\n")
	r := scanOne(t, "server/app.js", content)
	for _, rule := range []string{"js.eval", "js.inner-html", "js.child-process-concat", "js.sql-concat", "js.tls-reject-unauthorized", "js.weak-hash", "js.math-random-token"} {
		if len(findRule(r, rule)) == 0 {
			t.Errorf("rule %s did not fire", rule)
		}
	}
}

func TestJSRulesDontFireInPython(t *testing.T) {
	r := scanOne(t, "app.py", `el.innerHTML = data  # not actually possible in python`)
	if len(findRule(r, "js.inner-html")) != 0 {
		t.Error("JS rule fired on a Python file")
	}
}

func TestEvalNotMatchingSafeNames(t *testing.T) {
	r := scanOne(t, "lib.js", "model.eval();\nretrieval(x);\nmedieval(y);\n")
	if n := len(findRule(r, "js.eval")); n != 0 {
		t.Errorf("eval rule matched inside identifiers: %d findings", n)
	}
}

func TestPythonYAMLLoad(t *testing.T) {
	r := scanOne(t, "cfg.py", "a = yaml.load(f)\nb = yaml.load(f, Loader=yaml.SafeLoader)\nc = yaml.safe_load(f)\n")
	fs := findRule(r, "py.yaml-load")
	if len(fs) != 1 {
		t.Fatalf("expected exactly the unsafe yaml.load, got %d", len(fs))
	}
	if fs[0].Line != 1 {
		t.Errorf("line = %d, want 1", fs[0].Line)
	}
}

func TestDockerfileChecks(t *testing.T) {
	content := "FROM node:latest\nRUN curl -sL https://x.sh | bash\nENV API_TOKEN=zX9kQ2mP7vR4tY1w\nEXPOSE 22 8080\n"
	r := scanOne(t, "Dockerfile", content)
	for _, rule := range []string{"docker.root-user", "docker.unpinned-base", "docker.curl-pipe-sh", "docker.env-secret", "docker.expose-ssh"} {
		if len(findRule(r, rule)) == 0 {
			t.Errorf("rule %s did not fire", rule)
		}
	}
	clean := "FROM node:20.11@sha256:abc\nRUN npm ci\nUSER app\n"
	r2 := scanOne(t, "Dockerfile", clean)
	if len(findRule(r2, "docker.root-user")) != 0 || len(findRule(r2, "docker.unpinned-base")) != 0 {
		t.Error("clean dockerfile produced findings")
	}
}

func TestWorkflowChecks(t *testing.T) {
	content := "on:\n  pull_request_target:\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: someone/cool-action@v1\n"
	r := scanOne(t, ".github/workflows/ci.yml", content)
	if len(findRule(r, "gha.pull-request-target")) != 1 {
		t.Error("pull_request_target+checkout not flagged")
	}
	fs := findRule(r, "gha.unpinned-action")
	if len(fs) != 1 {
		t.Fatalf("expected 1 unpinned third-party action, got %d", len(fs))
	}
	if strings.Contains(fs[0].Snippet, "actions/checkout") {
		t.Error("first-party action should not be the unpinned finding")
	}
}

func TestK8sOnlyOnManifests(t *testing.T) {
	manifest := "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n  - securityContext:\n      privileged: true\n"
	r := scanOne(t, "deploy/pod.yaml", manifest)
	if len(findRule(r, "k8s.privileged")) != 1 || len(findRule(r, "k8s.host-network")) != 1 {
		t.Error("k8s rules did not fire on manifest")
	}
	other := "privileged: true\nname: not-k8s\n"
	r2 := scanOne(t, "config/settings.yaml", other)
	if len(findRule(r2, "k8s.privileged")) != 0 {
		t.Error("k8s rule fired on non-manifest yaml")
	}
}

func TestRepoHygiene(t *testing.T) {
	files := []InputFile{
		{Path: "package.json", Data: []byte(`{"dependencies":{"express":"^4.17.1"}}`)},
		{Path: "src/index.js", Data: []byte("console.log(1)\n")},
		{Path: ".env", Data: []byte("DB_PASSWORD=supersecret123\n")},
		{Path: "certs/server.pem", Data: []byte("-----BEGIN CERTIFICATE-----\n")},
		{Path: "README.md", Data: []byte("# hi\n")},
	}
	r := Scan(files, Options{})
	for _, rule := range []string{"repo.env-file", "repo.key-file", "repo.no-lockfile", "repo.no-license", "repo.no-gitignore"} {
		if len(findRule(r, rule)) == 0 {
			t.Errorf("rule %s did not fire", rule)
		}
	}
}

func TestDependencyExtraction(t *testing.T) {
	files := []InputFile{
		{Path: "package.json", Data: []byte(`{"dependencies":{"lodash":"^4.17.20","left-pad":"1.3.0"},"devDependencies":{"jest":"~29.0.0"}}`)},
		{Path: "requirements.txt", Data: []byte("Django==3.2.0\nrequests>=2.25.1  # comment\n-r other.txt\n")},
		{Path: "go.mod", Data: []byte("module x\n\ngo 1.21\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n\tgolang.org/x/text v0.3.7 // indirect\n)\n")},
		{Path: "Cargo.toml", Data: []byte("[package]\nname=\"x\"\n[dependencies]\nserde = \"1.0.130\"\ntokio = { version = \"1.8.0\", features = [\"full\"] }\n[dev-dependencies]\nquickcheck = \"1.0\"\n")},
		{Path: "Gemfile", Data: []byte("source 'https://rubygems.org'\ngem 'rails', '6.1.4'\n")},
		{Path: "pom.xml", Data: []byte("<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>")},
	}
	r := Scan(files, Options{})
	want := map[string]string{
		"npm/lodash":                                  "4.17.20",
		"npm/left-pad":                                "1.3.0",
		"npm/jest":                                    "29.0.0",
		"PyPI/django":                                 "3.2.0",
		"PyPI/requests":                               "2.25.1",
		"Go/github.com/gin-gonic/gin":                 "v1.9.0",
		"crates.io/serde":                             "1.0.130",
		"crates.io/tokio":                             "1.8.0",
		"RubyGems/rails":                              "6.1.4",
		"Maven/org.apache.logging.log4j:log4j-core":   "2.14.1",
	}
	got := map[string]string{}
	for _, d := range r.Dependencies {
		got[d.Ecosystem+"/"+d.Name] = d.Version
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("dependency %s = %q, want %q", k, got[k], v)
		}
	}
	if v, ok := got["Go/golang.org/x/text"]; ok {
		t.Errorf("indirect Go dep should be skipped, got %s", v)
	}
	if v, ok := got["crates.io/quickcheck"]; ok {
		t.Errorf("dev-dependencies section of Cargo.toml should be skipped, got %s", v)
	}
}

func TestLockfilePreferredOverManifest(t *testing.T) {
	files := []InputFile{
		{Path: "package.json", Data: []byte(`{"dependencies":{"lodash":"^4.17.0"}}`)},
		{Path: "package-lock.json", Data: []byte(`{"lockfileVersion":3,"packages":{"":{},"node_modules/lodash":{"version":"4.17.21"}}}`)},
	}
	r := Scan(files, Options{})
	for _, d := range r.Dependencies {
		if d.Name == "lodash" {
			if d.Version != "4.17.21" || !d.Exact {
				t.Errorf("lockfile version should win: got %s exact=%v", d.Version, d.Exact)
			}
			return
		}
	}
	t.Fatal("lodash not found in dependencies")
}

func TestVendoredAndBinarySkipped(t *testing.T) {
	files := []InputFile{
		{Path: "node_modules/evil/index.js", Data: []byte(`eval(input)`)},
		{Path: "assets/logo.png", Data: []byte{0x89, 0x50, 0x4E, 0x47, 0x00, 0x01}},
		{Path: "src/main.js", Data: []byte(`eval(input)`)},
	}
	r := Scan(files, Options{})
	evals := findRule(r, "js.eval")
	if len(evals) != 1 || evals[0].File != "src/main.js" {
		t.Fatalf("expected eval only in src/main.js, got %+v", evals)
	}
	if r.Stats.SkippedBinary != 1 || r.Stats.SkippedVendored != 1 {
		t.Errorf("stats wrong: %+v", r.Stats)
	}
}

func TestFileRollups(t *testing.T) {
	r := scanOne(t, "app.js", "eval(x)\nel.innerHTML = y\n")
	if len(r.Files) != 1 {
		t.Fatal("expected 1 file")
	}
	f := r.Files[0]
	if f.Findings < 2 {
		t.Errorf("rollup findings = %d, want >= 2", f.Findings)
	}
	if f.MaxSeverity != SevMedium {
		t.Errorf("maxSeverity = %s, want medium", f.MaxSeverity)
	}
	if f.Lang != "JavaScript" || f.Lines != 2 {
		t.Errorf("file info wrong: %+v", f)
	}
}

func TestPerRuleCap(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("eval(x)\n")
	}
	r := Scan([]InputFile{{Path: "a.js", Data: []byte(b.String())}}, Options{MaxPerRulePerFile: 5})
	if n := len(findRule(r, "js.eval")); n != 5 {
		t.Errorf("per-rule cap not applied: %d", n)
	}
}

func TestZipExtraction(t *testing.T) {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"repo-abc123/":               "",
		"repo-abc123/main.go":        "package main\n",
		"repo-abc123/sub/key.js":     `const api_key = "zX9kQ2mP7vR4tY1wQ8uJ5nB2";`,
		"repo-abc123/../escape.txt":  "nope",
	} {
		if strings.HasSuffix(name, "/") {
			continue
		}
		f, _ := w.Create(name)
		f.Write([]byte(content))
	}
	w.Close()
	files, err := FilesFromZip(buf.Bytes(), 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, f := range files {
		paths[f.Path] = true
	}
	if !paths["main.go"] || !paths["sub/key.js"] {
		t.Errorf("root prefix not stripped: %v", paths)
	}
	for p := range paths {
		if strings.Contains(p, "..") {
			t.Errorf("path traversal entry survived: %s", p)
		}
	}
}

func TestReportSerializes(t *testing.T) {
	r := scanOne(t, "a.js", "eval(x)\n")
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Findings) != len(r.Findings) {
		t.Error("round trip lost findings")
	}
}

func TestHTTPURLValidator(t *testing.T) {
	r := scanOne(t, "client.js", `fetch("http://api.payments-prod.io/v1/charge")`+"\n"+`const ns = "http://www.w3.org/2000/svg";`+"\n"+`dev("http://localhost:3000")`)
	fs := findRule(r, "gen.http-url")
	if len(fs) != 1 {
		t.Fatalf("expected 1 cleartext finding, got %d: %+v", len(fs), fs)
	}
	if fs[0].Line != 1 {
		t.Errorf("wrong line: %d", fs[0].Line)
	}
}

func TestCurlPipeShell(t *testing.T) {
	r := scanOne(t, "install.sh", "curl -fsSL https://get.example.io | sudo bash\n")
	if len(findRule(r, "sh.curl-pipe-sh")) != 1 {
		t.Error("curl|sh not flagged")
	}
}

func TestMinifiedSkipped(t *testing.T) {
	content := "var a=" + strings.Repeat("function(){return 1};var b=", 200) + "1;"
	r := scanOne(t, "static/app.js", content)
	if r.Stats.SkippedVendored != 1 {
		t.Errorf("minified bundle should be skipped, stats: %+v", r.Stats)
	}
}

func TestEmptyCollectionsMarshalAsArrays(t *testing.T) {
	// A repo with no deps/findings must still serialize [] (never null),
	// or the JS side crashes on .length.
	r := Scan([]InputFile{{Path: "README.md", Data: []byte("hi\n")}}, Options{})
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, key := range []string{`"dependencies":[`, `"findings":[`, `"files":[`} {
		if !strings.Contains(s, key) {
			t.Errorf("expected %s array in JSON, got: %s", key, s)
		}
	}
	if strings.Contains(s, `"dependencies":null`) {
		t.Error("dependencies marshaled as null")
	}
}
