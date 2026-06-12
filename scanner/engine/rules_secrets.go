package engine

import (
	"math"
	"regexp"
	"strings"
)

// Rule is a content-matching detection. Pre holds lowercase literal
// prefilters: the (expensive) regex only runs when one of them appears in
// the file, keeping whole-repo scans fast inside WASM.
type Rule struct {
	ID             string
	Title          string
	Message        string
	Recommendation string
	CWE            string
	Category       Category
	Severity       Severity
	Confidence     string
	Langs          []string       // nil = any text file
	PathRe         *regexp.Regexp // optional path scope
	Pre            []string
	Re             *regexp.Regexp
	ValueGroup     int  // capture group holding the sensitive value
	Mask           bool // redact the matched value in the snippet
	Validate       func(value, line string) bool
}

func (r *Rule) appliesTo(lang string) bool {
	if len(r.Langs) == 0 {
		return true
	}
	for _, l := range r.Langs {
		if l == lang {
			return true
		}
	}
	return false
}

// shannonEntropy measures bits of entropy per character.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	n := float64(len(s))
	e := 0.0
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

var placeholderHints = []string{
	"example", "sample", "dummy", "fake", "placeholder", "changeme",
	"change_me", "change-me", "your_", "your-", "yourkey", "yourtoken",
	"<", ">", "${", "{{", "%(", "xxxx", "****", "....", "todo", "fixme",
	"redacted", "insert", "replace", "abc123", "secret_here", "password123",
	"not_a_real", "notreal", "deadbeef", "01234567", "12345678", "aaaaaaaa",
	"path/to", "process.env", "os.environ", "getenv", "env(", "config(",
}

// looksPlaceholder rejects obvious documentation/example values so the city
// isn't littered with false credential thieves.
func looksPlaceholder(v string) bool {
	lv := strings.ToLower(v)
	for _, h := range placeholderHints {
		if strings.Contains(lv, h) {
			return true
		}
	}
	// All same character, or trivially short alphabetic "secrets".
	uniq := map[rune]bool{}
	for _, r := range lv {
		uniq[r] = true
	}
	return len(uniq) <= 2
}

func notPlaceholder(v, _ string) bool { return !looksPlaceholder(v) }

// secretAssignment requires both a non-placeholder value and moderate entropy.
func secretAssignment(v, line string) bool {
	if looksPlaceholder(v) {
		return false
	}
	return shannonEntropy(v) >= 3.0
}

// maskValue redacts a secret, keeping just enough to recognize it.
func maskValue(v string) string {
	if len(v) <= 8 {
		return strings.Repeat("•", len(v))
	}
	return v[:4] + strings.Repeat("•", min(len(v)-6, 24)) + v[len(v)-2:]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// secretRules detect credentials committed to the repository.
// All patterns are RE2-safe (no lookarounds).
var secretRules = []*Rule{
	{
		ID: "secret.aws-access-key", Title: "AWS access key ID",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "An AWS access key ID is committed to the repository. Paired with its secret key it grants direct API access to the AWS account.",
		Recommendation: "Revoke the key in IAM immediately, rotate credentials, and load them from environment variables or a secrets manager.",
		Pre:  []string{"akia", "asia", "agpa", "aroa", "aipa", "anpa", "anva", "a3t"},
		Re:   regexp.MustCompile(`\b((?:A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
	{
		ID: "secret.aws-secret-key", Title: "AWS secret access key",
		Category: CatSecret, Severity: SevCritical, Confidence: "medium",
		CWE:     "CWE-798",
		Message: "A value shaped like an AWS secret access key is assigned next to AWS-related configuration.",
		Recommendation: "Rotate the credential in IAM and move it to environment variables or a secrets manager.",
		Pre:  []string{"aws"},
		Re:   regexp.MustCompile(`(?i)aws[a-z0-9_\-. ]{0,24}(?:secret|private)[a-z0-9_\-. ]{0,24}['"=:\s]+['"]([0-9A-Za-z/+=]{40})['"]`),
		ValueGroup: 1, Mask: true, Validate: secretAssignment,
	},
	{
		ID: "secret.github-token", Title: "GitHub token",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "A GitHub personal access / OAuth / app token is committed to the repository. It can read or write every repo the owner can.",
		Recommendation: "Revoke it at github.com/settings/tokens and rotate. Use fine-grained tokens injected via CI secrets.",
		Pre:  []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"},
		Re:   regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
	{
		ID: "secret.gitlab-token", Title: "GitLab personal access token",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "A GitLab personal access token is committed to the repository.",
		Recommendation: "Revoke and rotate the token in GitLab, then load it from the environment.",
		Pre:  []string{"glpat-"},
		Re:   regexp.MustCompile(`\b(glpat-[0-9A-Za-z_\-]{20,})\b`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
	{
		ID: "secret.slack-token", Title: "Slack token",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "A Slack bot/user/app token is committed to the repository.",
		Recommendation: "Revoke the token from the Slack app dashboard and rotate.",
		Pre:  []string{"xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-"},
		Re:   regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z\-]{10,250})\b`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
	{
		ID: "secret.slack-webhook", Title: "Slack incoming webhook URL",
		Category: CatSecret, Severity: SevHigh, Confidence: "high",
		CWE:     "CWE-798",
		Message: "A Slack incoming-webhook URL is committed. Anyone with it can post into the workspace channel.",
		Recommendation: "Regenerate the webhook and store the URL outside the repository.",
		Pre:  []string{"hooks.slack.com"},
		Re:   regexp.MustCompile(`(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)`),
		ValueGroup: 1, Mask: true,
	},
	{
		ID: "secret.stripe-live-key", Title: "Stripe live secret key",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "A live-mode Stripe secret key is committed. It can charge cards and move money on the account.",
		Recommendation: "Roll the key in the Stripe dashboard immediately.",
		Pre:  []string{"sk_live_", "rk_live_"},
		Re:   regexp.MustCompile(`\b((?:sk|rk)_live_[0-9A-Za-z]{20,99})\b`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
	{
		ID: "secret.google-api-key", Title: "Google API key",
		Category: CatSecret, Severity: SevHigh, Confidence: "high",
		CWE:     "CWE-798",
		Message: "A Google API key is committed. Depending on restrictions it can bill the project's quota.",
		Recommendation: "Restrict the key (HTTP referrer / IP) or rotate it, and inject it at build time.",
		Pre:  []string{"aiza"},
		Re:   regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{35})\b`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
	{
		ID: "secret.openai-key", Title: "OpenAI API key",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "An OpenAI API key is committed to the repository.",
		Recommendation: "Revoke the key at platform.openai.com and rotate.",
		Pre:  []string{"t3blbkfj", "sk-proj-"},
		Re:   regexp.MustCompile(`\b(sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}|sk-proj-[A-Za-z0-9_\-]{40,})\b`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
	{
		ID: "secret.anthropic-key", Title: "Anthropic API key",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "An Anthropic API key is committed to the repository.",
		Recommendation: "Revoke the key in the Anthropic console and rotate.",
		Pre:  []string{"sk-ant-"},
		Re:   regexp.MustCompile(`\b(sk-ant-[A-Za-z0-9_\-]{32,})\b`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
	{
		ID: "secret.sendgrid-key", Title: "SendGrid API key",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "A SendGrid API key is committed. It can send mail as the organization.",
		Recommendation: "Revoke the key in SendGrid settings and rotate.",
		Pre:  []string{"sg."},
		Re:   regexp.MustCompile(`\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b`),
		ValueGroup: 1, Mask: true,
	},
	{
		ID: "secret.npm-token", Title: "npm access token",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "An npm access token is committed. It can publish packages as the owner — a supply-chain attack vector.",
		Recommendation: "Revoke the token (npm token revoke) and rotate.",
		Pre:  []string{"npm_"},
		Re:   regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
	{
		ID: "secret.telegram-bot-token", Title: "Telegram bot token",
		Category: CatSecret, Severity: SevHigh, Confidence: "high",
		CWE:     "CWE-798",
		Message: "A Telegram bot token is committed to the repository.",
		Recommendation: "Revoke via @BotFather and rotate.",
		Pre:  []string{":aa"},
		Re:   regexp.MustCompile(`\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})\b`),
		ValueGroup: 1, Mask: true,
	},
	{
		ID: "secret.azure-storage-key", Title: "Azure storage account key",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "An Azure storage AccountKey is committed in a connection string.",
		Recommendation: "Regenerate the storage key in the Azure portal and use managed identities instead.",
		Pre:  []string{"accountkey="},
		Re:   regexp.MustCompile(`(?i)AccountKey=([A-Za-z0-9+/=]{86,90})`),
		ValueGroup: 1, Mask: true,
	},
	{
		ID: "secret.private-key", Title: "Private key material",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-321",
		Message: "A PEM private key block is committed to the repository. Anyone with repo access can impersonate this identity.",
		Recommendation: "Remove the key, rotate the credential it protects, and purge it from git history (git filter-repo).",
		Pre:  []string{"private key"},
		Re:   regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----`),
	},
	{
		ID: "secret.connection-string", Title: "Database URL with embedded credentials",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "A database connection string with an inline username and password is committed.",
		Recommendation: "Move credentials to environment variables; rotate the database password.",
		Pre:  []string{"postgres://", "postgresql://", "mysql://", "mongodb://", "mongodb+srv://", "redis://", "amqp://", "mssql://"},
		Re:   regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:@/'"]{1,64}:([^\s@/'"]{3,128})@[^\s'"]+`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
	{
		ID: "secret.basic-auth-header", Title: "Hardcoded Basic auth header",
		Category: CatSecret, Severity: SevHigh, Confidence: "medium",
		CWE:     "CWE-798",
		Message: "A hardcoded HTTP Basic Authorization header embeds base64 credentials in source.",
		Recommendation: "Inject credentials from configuration at runtime and rotate the exposed pair.",
		Pre:  []string{"authorization"},
		Re:   regexp.MustCompile(`(?i)authorization['"]?\s*[:=,]\s*['"]Basic ([A-Za-z0-9+/=]{16,})['"]`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
	{
		ID: "secret.generic-api-key", Title: "Hardcoded API key / token",
		Category: CatSecret, Severity: SevHigh, Confidence: "medium",
		CWE:     "CWE-798",
		Message: "A variable named like an API credential is assigned a literal high-entropy value.",
		Recommendation: "Load secrets from environment variables or a vault; rotate the exposed value.",
		Pre:  []string{"api_key", "apikey", "api-key", "auth_token", "authtoken", "access_token", "client_secret", "secret_key", "secretkey", "private_token", "auth-token", "access-token"},
		Re:   regexp.MustCompile(`(?i)\b(?:api[_\-]?key|auth[_\-]?token|access[_\-]?token|client[_\-]?secret|secret[_\-]?key|private[_\-]?token)\b['"]?\s*[:=]\s*['"]([A-Za-z0-9_\-/+.=]{16,})['"]`),
		ValueGroup: 1, Mask: true, Validate: secretAssignment,
	},
	{
		ID: "secret.generic-password", Title: "Hardcoded password",
		Category: CatSecret, Severity: SevMedium, Confidence: "low",
		CWE:     "CWE-259",
		Message: "A password appears to be hardcoded in source or configuration.",
		Recommendation: "Move passwords to environment variables or a secrets manager and rotate them.",
		Pre:  []string{"password", "passwd"},
		Re:   regexp.MustCompile(`(?i)\b(?:password|passwd|db_pass|dbpassword|db_password|root_password|admin_password)\b['"]?\s*[:=]\s*['"]([^'"\s]{6,64})['"]`),
		ValueGroup: 1, Mask: true, Validate: secretAssignment,
	},
	{
		ID: "secret.jwt-token", Title: "Hardcoded JWT",
		Category: CatSecret, Severity: SevMedium, Confidence: "medium",
		CWE:     "CWE-798",
		Message: "A signed JWT is committed to the repository. It may still be valid or reveal claims and signing context.",
		Recommendation: "Invalidate the token server-side and avoid committing real tokens, even expired ones.",
		Pre:  []string{"eyj"},
		Re:   regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{16,})\b`),
		ValueGroup: 1, Mask: true,
	},
	{
		ID: "secret.npmrc-token", Title: "npm registry token in .npmrc",
		Category: CatSecret, Severity: SevCritical, Confidence: "high",
		CWE:     "CWE-798",
		Message: "An _authToken is committed in .npmrc, granting registry publish/install rights.",
		Recommendation: "Revoke the token and reference it as ${NPM_TOKEN} from the environment instead.",
		PathRe: regexp.MustCompile(`(^|/)\.npmrc$`),
		Pre:  []string{"_authtoken"},
		Re:   regexp.MustCompile(`(?i)_authToken\s*=\s*([^\s$]{8,})`),
		ValueGroup: 1, Mask: true, Validate: notPlaceholder,
	},
}
