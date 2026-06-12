package engine

import (
	"path"
	"regexp"
	"strings"
)

// configCheck inspects a whole file (rather than pattern-matching lines) so
// it can reason about absences — e.g. a Dockerfile that never drops root.
type configCheck struct {
	match func(p string) bool
	run   func(p string, content string, lines []string) []Finding
}

func mkFinding(rule, title string, cat Category, sev Severity, file string, line int, snippet, msg, rec, cwe, conf string) Finding {
	return Finding{
		RuleID: rule, Title: title, Category: cat, Severity: sev,
		File: file, Line: line, Snippet: strings.TrimSpace(snippet),
		Message: msg, Recommendation: rec, CWE: cwe, Confidence: conf,
	}
}

var (
	reDockerUser     = regexp.MustCompile(`(?im)^\s*USER\s+\S+`)
	reDockerRootUser = regexp.MustCompile(`(?im)^\s*USER\s+(?:root|0)\s*$`)
	reDockerFrom     = regexp.MustCompile(`(?im)^\s*FROM\s+([^\s]+)`)
	reDockerCurlSh   = regexp.MustCompile(`(?im)^\s*RUN\s+.*(?:curl|wget)[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b`)
	reDockerAddHTTP  = regexp.MustCompile(`(?im)^\s*ADD\s+https?://\S+`)
	reDockerEnvSec   = regexp.MustCompile(`(?im)^\s*(?:ENV|ARG)\s+([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|APIKEY|ACCESS_KEY)[A-Z0-9_]*)[= ]\s*(\S+)`)
	reDockerExpose22 = regexp.MustCompile(`(?im)^\s*EXPOSE\s+.*\b22\b`)

	reComposePriv    = regexp.MustCompile(`(?im)^\s*privileged\s*:\s*true`)
	reComposeHostNet = regexp.MustCompile(`(?im)^\s*network_mode\s*:\s*["']?host`)
	reComposeDockSock = regexp.MustCompile(`(?im)/var/run/docker\.sock`)

	rePRTarget    = regexp.MustCompile(`(?m)^\s*(?:on\s*:.*pull_request_target|pull_request_target\s*:|\s+-\s+pull_request_target\b)`)
	reCheckoutPR  = regexp.MustCompile(`uses\s*:\s*actions/checkout`)
	reUnpinned    = regexp.MustCompile(`(?m)uses\s*:\s*([\w.-]+/[\w./-]+)@(main|master|v\d+(?:\.\d+)*)\s*$`)
	reUnsecureCmd = regexp.MustCompile(`ACTIONS_ALLOW_UNSECURE_COMMANDS`)
	reRunSecretEcho = regexp.MustCompile(`(?i)echo\s+.{0,40}\$\{\{\s*secrets\.`)

	reK8sPriv      = regexp.MustCompile(`(?im)^\s*privileged\s*:\s*true`)
	reK8sRunAsRoot = regexp.MustCompile(`(?im)^\s*runAsUser\s*:\s*0\b`)
	reK8sPrivEsc   = regexp.MustCompile(`(?im)^\s*allowPrivilegeEscalation\s*:\s*true`)
	reK8sHostNet   = regexp.MustCompile(`(?im)^\s*hostNetwork\s*:\s*true`)
	reK8sHostPID   = regexp.MustCompile(`(?im)^\s*hostPID\s*:\s*true`)

	reTfOpenIngress = regexp.MustCompile(`(?m)cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"`)
	reTfPublicACL   = regexp.MustCompile(`(?m)acl\s*=\s*"public-read(?:-write)?"`)
	reTfNoEncrypt   = regexp.MustCompile(`(?m)encrypted\s*=\s*false`)
)

func lineNumberOf(content string, idx int) int {
	return strings.Count(content[:idx], "\n") + 1
}

func firstMatchLine(re *regexp.Regexp, content string) (int, string) {
	loc := re.FindStringIndex(content)
	if loc == nil {
		return 0, ""
	}
	ln := lineNumberOf(content, loc[0])
	return ln, lineAt(content, ln)
}

func lineAt(content string, ln int) string {
	lines := strings.Split(content, "\n")
	if ln-1 < 0 || ln-1 >= len(lines) {
		return ""
	}
	return lines[ln-1]
}

func isDockerfile(p string) bool {
	b := strings.ToLower(path.Base(p))
	return b == "dockerfile" || strings.HasPrefix(b, "dockerfile.") || strings.HasSuffix(b, ".dockerfile")
}

func isWorkflow(p string) bool {
	lp := strings.ToLower(p)
	return strings.Contains(lp, ".github/workflows/") && (strings.HasSuffix(lp, ".yml") || strings.HasSuffix(lp, ".yaml"))
}

func isCompose(p string) bool {
	b := strings.ToLower(path.Base(p))
	return strings.HasPrefix(b, "docker-compose") || strings.HasPrefix(b, "compose.y")
}

func isK8sManifest(content string) bool {
	return strings.Contains(content, "apiVersion:") && strings.Contains(content, "kind:")
}

var configChecks = []configCheck{
	{ // ------------------------------------------------------------ Dockerfile
		match: isDockerfile,
		run: func(p, content string, _ []string) []Finding {
			var out []Finding
			if !reDockerUser.MatchString(content) {
				out = append(out, mkFinding("docker.root-user", "Container runs as root",
					CatConfig, SevMedium, p, 1, "FROM …  (no USER directive)",
					"No USER directive: the container runs as root, so a process compromise owns the container and amplifies kernel-exploit impact.",
					"Create an unprivileged user and add a USER directive before the entrypoint.",
					"CWE-250", "high"))
			} else if reDockerRootUser.MatchString(content) {
				ln, snip := firstMatchLine(reDockerRootUser, content)
				out = append(out, mkFinding("docker.explicit-root", "Container explicitly runs as root",
					CatConfig, SevMedium, p, ln, snip,
					"The image explicitly switches to root for the final stage.",
					"Run the workload under a dedicated unprivileged user.",
					"CWE-250", "high"))
			}
			for _, m := range reDockerFrom.FindAllStringSubmatchIndex(content, 8) {
				img := content[m[2]:m[3]]
				if img == "scratch" || strings.HasPrefix(img, "$") {
					continue
				}
				if !strings.Contains(img, ":") || strings.HasSuffix(img, ":latest") {
					out = append(out, mkFinding("docker.unpinned-base", "Unpinned base image",
						CatConfig, SevLow, p, lineNumberOf(content, m[0]), content[m[0]:m[1]],
						"The base image floats on :latest (or no tag), so rebuilds silently pull different — possibly compromised — upstream content.",
						"Pin a version tag, ideally with a digest (image:1.2.3@sha256:…).",
						"CWE-1357", "high"))
				}
			}
			if ln, snip := firstMatchLine(reDockerCurlSh, content); ln > 0 {
				out = append(out, mkFinding("docker.curl-pipe-sh", "Build downloads and executes remote script",
					CatConfig, SevHigh, p, ln, snip,
					"The build pipes a downloaded script straight into a shell with no integrity check.",
					"Download, verify checksum/signature, then run.",
					"CWE-494", "high"))
			}
			if ln, snip := firstMatchLine(reDockerAddHTTP, content); ln > 0 {
				out = append(out, mkFinding("docker.add-remote", "ADD fetches a remote URL",
					CatConfig, SevLow, p, ln, snip,
					"ADD with a URL downloads content into the image without verification.",
					"Use COPY for local files; fetch remote artifacts with checksum verification.",
					"CWE-494", "high"))
			}
			for _, m := range reDockerEnvSec.FindAllStringSubmatchIndex(content, 8) {
				val := content[m[4]:m[5]]
				if looksPlaceholder(val) || strings.HasPrefix(val, "$") {
					continue
				}
				out = append(out, mkFinding("docker.env-secret", "Secret baked into image ENV/ARG",
					CatSecret, SevHigh, p, lineNumberOf(content, m[0]),
					content[m[2]:m[3]]+"="+maskValue(val),
					"Secrets in ENV/ARG persist in image layers and are visible via docker history.",
					"Inject secrets at runtime (orchestrator secrets, BuildKit --mount=type=secret).",
					"CWE-538", "medium"))
			}
			if ln, snip := firstMatchLine(reDockerExpose22, content); ln > 0 {
				out = append(out, mkFinding("docker.expose-ssh", "Container exposes SSH (port 22)",
					CatConfig, SevMedium, p, ln, snip,
					"Shipping SSH inside an application container expands the attack surface and bypasses orchestrator access control.",
					"Use docker exec / kubectl exec instead of in-container SSH.",
					"CWE-1327", "medium"))
			}
			return out
		},
	},
	{ // ------------------------------------------------------- docker-compose
		match: isCompose,
		run: func(p, content string, _ []string) []Finding {
			var out []Finding
			if ln, snip := firstMatchLine(reComposePriv, content); ln > 0 {
				out = append(out, mkFinding("compose.privileged", "Privileged container",
					CatConfig, SevHigh, p, ln, snip,
					"privileged:true grants every capability and device — a container escape is trivial from here.",
					"Drop privileged mode; grant specific cap_add entries if truly needed.",
					"CWE-250", "high"))
			}
			if ln, snip := firstMatchLine(reComposeHostNet, content); ln > 0 {
				out = append(out, mkFinding("compose.host-network", "Host network mode",
					CatConfig, SevMedium, p, ln, snip,
					"network_mode:host removes network isolation between the container and the host.",
					"Use the default bridge network and publish only needed ports.",
					"CWE-668", "high"))
			}
			if ln, snip := firstMatchLine(reComposeDockSock, content); ln > 0 {
				out = append(out, mkFinding("compose.docker-socket", "Docker socket mounted into container",
					CatConfig, SevHigh, p, ln, snip,
					"Mounting /var/run/docker.sock hands the container full control of the Docker daemon — effectively root on the host.",
					"Avoid socket mounts; use a constrained API proxy if the workload must talk to Docker.",
					"CWE-668", "high"))
			}
			return out
		},
	},
	{ // ------------------------------------------------------ GitHub Actions
		match: isWorkflow,
		run: func(p, content string, _ []string) []Finding {
			var out []Finding
			if rePRTarget.MatchString(content) && reCheckoutPR.MatchString(content) {
				ln, snip := firstMatchLine(rePRTarget, content)
				out = append(out, mkFinding("gha.pull-request-target", "pull_request_target + checkout (poisoned pipeline risk)",
					CatCICD, SevHigh, p, ln, snip,
					"Workflows triggered by pull_request_target run with write tokens and secrets; checking out PR code lets a fork execute code in that privileged context.",
					"Avoid checking out PR head refs under pull_request_target, or isolate to an unprivileged job.",
					"CWE-285", "medium"))
			}
			seen := 0
			for _, m := range reUnpinned.FindAllStringSubmatchIndex(content, -1) {
				action := content[m[2]:m[3]]
				if strings.HasPrefix(action, "actions/") || strings.HasPrefix(action, "github/") {
					continue // first-party actions are lower risk
				}
				if seen++; seen > 3 {
					break
				}
				out = append(out, mkFinding("gha.unpinned-action", "Third-party action not pinned to a commit SHA",
					CatCICD, SevLow, p, lineNumberOf(content, m[0]), strings.TrimSpace(content[m[0]:m[1]]),
					"Mutable tags like @v1/@main let the action's author (or a compromise of their repo) silently change the code your CI runs with your secrets.",
					"Pin third-party actions to a full commit SHA.",
					"CWE-829", "high"))
			}
			if ln, snip := firstMatchLine(reUnsecureCmd, content); ln > 0 {
				out = append(out, mkFinding("gha.unsecure-commands", "ACTIONS_ALLOW_UNSECURE_COMMANDS enabled",
					CatCICD, SevHigh, p, ln, snip,
					"This re-enables deprecated set-env/add-path commands, allowing log-injection to modify the runner environment.",
					"Remove the flag and use environment files instead.",
					"CWE-77", "high"))
			}
			if ln, snip := firstMatchLine(reRunSecretEcho, content); ln > 0 {
				out = append(out, mkFinding("gha.secret-echo", "Secret echoed in workflow step",
					CatCICD, SevMedium, p, ln, snip,
					"Echoing secrets risks leaking them into logs despite masking (e.g. via transformations).",
					"Pass secrets via env to the consuming process; never echo them.",
					"CWE-532", "medium"))
			}
			return out
		},
	},
	{ // ------------------------------------------------- Kubernetes manifests
		match: func(p string) bool {
			lp := strings.ToLower(p)
			return (strings.HasSuffix(lp, ".yml") || strings.HasSuffix(lp, ".yaml")) && !isWorkflow(p) && !isCompose(p)
		},
		run: func(p, content string, _ []string) []Finding {
			if !isK8sManifest(content) {
				return nil
			}
			var out []Finding
			add := func(re *regexp.Regexp, rule, title, msg, rec string, sev Severity) {
				if ln, snip := firstMatchLine(re, content); ln > 0 {
					out = append(out, mkFinding(rule, title, CatConfig, sev, p, ln, snip, msg, rec, "CWE-250", "high"))
				}
			}
			add(reK8sPriv, "k8s.privileged", "Privileged pod container",
				"privileged:true gives the container full host device and capability access.",
				"Remove privileged mode; use a restricted securityContext.", SevHigh)
			add(reK8sRunAsRoot, "k8s.run-as-root", "Pod runs as UID 0",
				"runAsUser:0 runs the workload as root inside the container.",
				"Set runAsNonRoot:true and a non-zero runAsUser.", SevMedium)
			add(reK8sPrivEsc, "k8s.priv-escalation", "allowPrivilegeEscalation enabled",
				"The container can gain more privileges than its parent process.",
				"Set allowPrivilegeEscalation:false.", SevMedium)
			add(reK8sHostNet, "k8s.host-network", "hostNetwork enabled",
				"The pod shares the node's network namespace, bypassing network policy isolation.",
				"Avoid hostNetwork unless the workload genuinely needs node networking.", SevMedium)
			add(reK8sHostPID, "k8s.host-pid", "hostPID enabled",
				"The pod can see and signal every process on the node.",
				"Remove hostPID.", SevMedium)
			return out
		},
	},
	{ // ----------------------------------------------------------- Terraform
		match: func(p string) bool { return strings.HasSuffix(strings.ToLower(p), ".tf") },
		run: func(p, content string, _ []string) []Finding {
			var out []Finding
			if ln, snip := firstMatchLine(reTfOpenIngress, content); ln > 0 {
				out = append(out, mkFinding("tf.open-ingress", "Security group open to 0.0.0.0/0",
					CatConfig, SevHigh, p, ln, snip,
					"An ingress rule admits the entire internet. If this fronts SSH/RDP/databases it will be found by scanners within minutes.",
					"Restrict CIDR ranges to known networks or a bastion/VPN.",
					"CWE-284", "medium"))
			}
			if ln, snip := firstMatchLine(reTfPublicACL, content); ln > 0 {
				out = append(out, mkFinding("tf.public-bucket", "Object storage bucket is public",
					CatConfig, SevHigh, p, ln, snip,
					"A public-read(-write) ACL exposes every object in the bucket to the internet.",
					"Make the bucket private; serve public assets through a CDN with explicit policies.",
					"CWE-284", "high"))
			}
			if ln, snip := firstMatchLine(reTfNoEncrypt, content); ln > 0 {
				out = append(out, mkFinding("tf.unencrypted-storage", "Storage encryption disabled",
					CatConfig, SevMedium, p, ln, snip,
					"encrypted=false leaves the volume/database unencrypted at rest.",
					"Enable encryption (it is free and transparent on all major clouds).",
					"CWE-311", "medium"))
			}
			return out
		},
	},
}

// repoChecks evaluate the repository as a whole (file presence/absence).
func repoChecks(files []InputFile) []Finding {
	var out []Finding
	names := make(map[string]bool, len(files))
	tops := make(map[string]bool)
	hasLockfile := false
	hasPkgJSON := false
	for _, f := range files {
		lp := strings.ToLower(f.Path)
		names[lp] = true
		if !strings.Contains(f.Path, "/") {
			tops[lp] = true
		}
		switch path.Base(lp) {
		case "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock":
			hasLockfile = true
		case "package.json":
			hasPkgJSON = true
		}
		base := path.Base(lp)
		if base == ".env" || (strings.HasPrefix(base, ".env.") && base != ".env.example" && base != ".env.sample" && base != ".env.template" && base != ".env.test") {
			out = append(out, mkFinding("repo.env-file", "Environment file committed",
				CatSecret, SevHigh, f.Path, 1, base,
				".env files typically hold live credentials; committing them shares those secrets with everyone who can read the repo — forever, via git history.",
				"Remove the file, add it to .gitignore, rotate every value it contains, and purge it from history.",
				"CWE-538", "high"))
		}
		if strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".p12") || strings.HasSuffix(base, ".pfx") ||
			strings.HasSuffix(base, ".keystore") || strings.HasSuffix(base, ".jks") ||
			base == "id_rsa" || base == "id_dsa" || base == "id_ecdsa" || base == "id_ed25519" {
			out = append(out, mkFinding("repo.key-file", "Key material file committed",
				CatSecret, SevHigh, f.Path, 1, base,
				"A key/certificate store is committed to the repository.",
				"Verify it holds no private material; if it does, rotate and purge from history.",
				"CWE-321", "medium"))
		}
	}
	if hasPkgJSON && !hasLockfile {
		out = append(out, mkFinding("repo.no-lockfile", "No dependency lockfile",
			CatHygiene, SevMedium, "package.json", 1, "package.json without lockfile",
			"Without a lockfile every install resolves ranges anew, so builds aren't reproducible and a hijacked minor release flows straight in.",
			"Commit package-lock.json / yarn.lock / pnpm-lock.yaml.",
			"CWE-1357", "high"))
	}
	if len(files) > 3 {
		if !names["license"] && !names["license.md"] && !names["license.txt"] && !names["copying"] && !names["license-mit"] {
			out = append(out, mkFinding("repo.no-license", "No license file",
				CatHygiene, SevInfo, "", 0, "",
				"The repository declares no license, leaving consumers without usage rights clarity.",
				"Add a LICENSE file.", "", "high"))
		}
		if !names["security.md"] && !names[".github/security.md"] && !names["docs/security.md"] {
			out = append(out, mkFinding("repo.no-security-policy", "No security policy",
				CatHygiene, SevInfo, "", 0, "",
				"There is no SECURITY.md, so researchers have no documented way to report vulnerabilities privately.",
				"Add SECURITY.md with a disclosure contact.", "", "high"))
		}
		if !tops[".gitignore"] {
			out = append(out, mkFinding("repo.no-gitignore", "No .gitignore",
				CatHygiene, SevLow, "", 0, "",
				"Without .gitignore, build artifacts and local secrets are one careless `git add .` away from being committed.",
				"Add a .gitignore for the project's toolchain.", "", "high"))
		}
		hasDependabot := names[".github/dependabot.yml"] || names[".github/dependabot.yaml"] || names[".github/renovate.json"] || names["renovate.json"]
		if (hasPkgJSON || names["requirements.txt"] || names["go.mod"] || names["cargo.toml"] || names["gemfile"]) && !hasDependabot {
			out = append(out, mkFinding("repo.no-dep-updates", "No automated dependency updates",
				CatHygiene, SevLow, "", 0, "",
				"No Dependabot/Renovate config: known-vulnerable dependencies will linger until someone updates them by hand.",
				"Enable Dependabot or Renovate.", "CWE-1104", "high"))
		}
	}
	return out
}
