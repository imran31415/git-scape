package engine

import (
	"regexp"
	"strings"
)

var jsLangs = []string{"JavaScript", "TypeScript", "Vue", "Svelte", "HTML"}

// codeRules are language-aware static-analysis patterns. They intentionally
// favor precision over recall: each match must be explainable to the user
// standing in front of a glowing building.
var codeRules = []*Rule{
	// ---------------------------------------------------------------- JS/TS
	{
		ID: "js.eval", Title: "eval() — dynamic code execution",
		Category: CatInjection, Severity: SevMedium, Confidence: "medium", CWE: "CWE-95",
		Message: "eval() executes arbitrary strings as code. If any part of the input is attacker-influenced this is remote code execution.",
		Recommendation: "Replace eval with JSON.parse, lookup tables, or explicit logic.",
		Langs: jsLangs, Pre: []string{"eval("},
		Re: regexp.MustCompile(`(?m)(?:^|[^.\w])eval\s*\(`),
	},
	{
		ID: "js.new-function", Title: "new Function() — dynamic code execution",
		Category: CatInjection, Severity: SevMedium, Confidence: "medium", CWE: "CWE-95",
		Message: "The Function constructor compiles strings into executable code, an eval-equivalent injection sink.",
		Recommendation: "Avoid constructing code from strings; use first-class functions.",
		Langs: jsLangs, Pre: []string{"new function"},
		Re: regexp.MustCompile(`new\s+Function\s*\(\s*['"\x60]`),
	},
	{
		ID: "js.child-process-concat", Title: "Shell command built from variables",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-78",
		Message: "A child_process exec call builds its shell command via concatenation or template interpolation — a command-injection sink.",
		Recommendation: "Use execFile/spawn with an argument array, and validate inputs.",
		Langs: jsLangs, Pre: []string{"exec"},
		Re: regexp.MustCompile(`\b(?:exec|execSync)\s*\(\s*(?:[\x60][^\x60]*\$\{|['"][^'"]*['"]\s*\+|\w+\s*\+)`),
	},
	{
		ID: "js.inner-html", Title: "innerHTML assignment — XSS sink",
		Category: CatXSS, Severity: SevMedium, Confidence: "medium", CWE: "CWE-79",
		Message: "Assigning to innerHTML/outerHTML renders markup from strings; with attacker-influenced data this is DOM XSS.",
		Recommendation: "Use textContent, or sanitize with DOMPurify before inserting HTML.",
		Langs: jsLangs, Pre: []string{".innerhtml", ".outerhtml", "insertadjacenthtml"},
		Re: regexp.MustCompile(`\.(?:innerHTML|outerHTML)\s*[+]?=[^=]|insertAdjacentHTML\s*\(`),
	},
	{
		ID: "js.document-write", Title: "document.write() — XSS sink",
		Category: CatXSS, Severity: SevMedium, Confidence: "medium", CWE: "CWE-79",
		Message: "document.write injects markup directly into the document and is a classic DOM-XSS sink.",
		Recommendation: "Build DOM nodes programmatically or sanitize input.",
		Langs: jsLangs, Pre: []string{"document.write"},
		Re: regexp.MustCompile(`document\.write(?:ln)?\s*\(`),
	},
	{
		ID: "js.dangerously-set-html", Title: "dangerouslySetInnerHTML",
		Category: CatXSS, Severity: SevMedium, Confidence: "medium", CWE: "CWE-79",
		Message: "React's dangerouslySetInnerHTML bypasses JSX escaping; unsanitized data here is XSS.",
		Recommendation: "Sanitize with DOMPurify, or render data as text.",
		Langs: jsLangs, Pre: []string{"dangerouslysetinnerhtml"},
		Re: regexp.MustCompile(`dangerouslySetInnerHTML\s*[:=]`),
	},
	{
		ID: "js.sql-concat", Title: "SQL built by string concatenation",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-89",
		Message: "A SQL statement is assembled with + or template interpolation — the textbook SQL-injection pattern.",
		Recommendation: "Use parameterized queries / prepared statements.",
		Langs: jsLangs, Pre: []string{"select ", "insert into", "update ", "delete from"},
		Re: regexp.MustCompile(`(?i)['"\x60]\s*(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^'"\x60]*(?:['"]\s*\+|\$\{)`),
	},
	{
		ID: "js.tls-reject-unauthorized", Title: "TLS certificate validation disabled",
		Category: CatNetwork, Severity: SevHigh, Confidence: "high", CWE: "CWE-295",
		Message: "rejectUnauthorized:false (or NODE_TLS_REJECT_UNAUTHORIZED=0) disables TLS certificate checks, enabling man-in-the-middle attacks.",
		Recommendation: "Trust the proper CA bundle instead of disabling verification.",
		Langs: nil, Pre: []string{"rejectunauthorized", "node_tls_reject_unauthorized"},
		Re: regexp.MustCompile(`(?i)rejectUnauthorized['"]?\s*[:=]\s*false|NODE_TLS_REJECT_UNAUTHORIZED['"]?\s*[:=]?\s*['"]?0`),
	},
	{
		ID: "js.weak-hash", Title: "Weak hash algorithm (MD5/SHA-1)",
		Category: CatCrypto, Severity: SevMedium, Confidence: "high", CWE: "CWE-328",
		Message: "MD5 and SHA-1 are broken for collision resistance and unsuitable for passwords or signatures.",
		Recommendation: "Use SHA-256+ for integrity and bcrypt/scrypt/argon2 for passwords.",
		Langs: jsLangs, Pre: []string{"createhash"},
		Re: regexp.MustCompile(`createHash\s*\(\s*['"](?:md5|sha1)['"]`),
	},
	{
		ID: "js.math-random-token", Title: "Math.random() used for a secret value",
		Category: CatCrypto, Severity: SevMedium, Confidence: "medium", CWE: "CWE-338",
		Message: "Math.random() is predictable; using it for tokens, OTPs or session IDs lets attackers guess them.",
		Recommendation: "Use crypto.randomBytes / crypto.getRandomValues.",
		Langs: jsLangs, Pre: []string{"math.random"},
		Re: regexp.MustCompile(`(?i)(?:token|secret|otp|nonce|session|password|reset|apikey|api_key)[^\n]{0,60}Math\.random|Math\.random[^\n]{0,60}(?:token|secret|otp|nonce|session|password)`),
	},
	{
		ID: "js.localstorage-token", Title: "Sensitive token stored in localStorage",
		Category: CatConfig, Severity: SevLow, Confidence: "medium", CWE: "CWE-922",
		Message: "Tokens in localStorage are readable by any XSS payload; unlike httpOnly cookies they have no script isolation.",
		Recommendation: "Prefer httpOnly secure cookies or in-memory storage for session tokens.",
		Langs: jsLangs, Pre: []string{"localstorage.setitem"},
		Re: regexp.MustCompile(`(?i)localStorage\.setItem\s*\(\s*['"][^'"]*(?:token|jwt|auth|secret|password)[^'"]*['"]`),
	},
	{
		ID: "js.postmessage-wildcard", Title: "postMessage with wildcard origin",
		Category: CatConfig, Severity: SevMedium, Confidence: "high", CWE: "CWE-345",
		Message: "postMessage(…, '*') sends data to any origin that holds a window reference.",
		Recommendation: "Pass the exact target origin instead of '*'.",
		Langs: jsLangs, Pre: []string{"postmessage"},
		Re: regexp.MustCompile(`postMessage\s*\([^)]{0,160},\s*['"]\*['"]\s*\)`),
	},
	{
		ID: "js.proto-pollution", Title: "__proto__ manipulation",
		Category: CatInjection, Severity: SevMedium, Confidence: "low", CWE: "CWE-1321",
		Message: "Direct __proto__ writes are the core primitive of prototype-pollution attacks.",
		Recommendation: "Use Object.create(null) maps or block __proto__ keys when merging objects.",
		Langs: jsLangs, Pre: []string{"__proto__"},
		Re: regexp.MustCompile(`(?:\[['"]__proto__['"]\]|\.__proto__)\s*=`),
	},

	// ---------------------------------------------------------------- Python
	{
		ID: "py.eval-exec", Title: "eval()/exec() — dynamic code execution",
		Category: CatInjection, Severity: SevMedium, Confidence: "medium", CWE: "CWE-95",
		Message: "eval/exec on strings executes arbitrary Python; with attacker-influenced input this is code injection.",
		Recommendation: "Use ast.literal_eval for data, or restructure to avoid dynamic code.",
		Langs: []string{"Python"}, Pre: []string{"eval(", "exec("},
		Re: regexp.MustCompile(`(?m)(?:^|[^.\w])(?:eval|exec)\s*\(\s*[^)\s]`),
	},
	{
		ID: "py.pickle-load", Title: "pickle deserialization of untrusted data",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-502",
		Message: "pickle.load(s) executes arbitrary code during deserialization — never feed it untrusted bytes.",
		Recommendation: "Use JSON or another data-only format for untrusted input.",
		Langs: []string{"Python"}, Pre: []string{"pickle.load"},
		Re: regexp.MustCompile(`\bpickle\.loads?\s*\(`),
	},
	{
		ID: "py.yaml-load", Title: "yaml.load without SafeLoader",
		Category: CatInjection, Severity: SevHigh, Confidence: "high", CWE: "CWE-502",
		Message: "yaml.load with the default loader can instantiate arbitrary Python objects from a document.",
		Recommendation: "Use yaml.safe_load, or pass Loader=yaml.SafeLoader.",
		Langs: []string{"Python"}, Pre: []string{"yaml.load"},
		Re: regexp.MustCompile(`yaml\.load\s*\((?:[^)\n]*)?\)`),
		Validate: func(_, line string) bool {
			return !regexp.MustCompile(`(?i)safeloader|safe_load|csafeloader`).MatchString(line)
		},
	},
	{
		ID: "py.subprocess-shell", Title: "subprocess with shell=True",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-78",
		Message: "shell=True routes the command line through /bin/sh; interpolated input becomes command injection.",
		Recommendation: "Pass an argument list with shell=False (the default).",
		Langs: []string{"Python"}, Pre: []string{"shell=true"},
		Re: regexp.MustCompile(`(?i)\bshell\s*=\s*True\b`),
	},
	{
		ID: "py.os-system", Title: "os.system() command execution",
		Category: CatInjection, Severity: SevMedium, Confidence: "medium", CWE: "CWE-78",
		Message: "os.system passes its string to the shell; any interpolated input is a command-injection risk.",
		Recommendation: "Use subprocess.run with an argument list.",
		Langs: []string{"Python"}, Pre: []string{"os.system"},
		Re: regexp.MustCompile(`\bos\.system\s*\(`),
	},
	{
		ID: "py.sql-format", Title: "SQL built with f-string / % / + ",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-89",
		Message: "A cursor.execute call assembles SQL with f-strings, % formatting or concatenation instead of bound parameters.",
		Recommendation: "Use parameterized queries: cursor.execute('… WHERE id=%s', (id,)).",
		Langs: []string{"Python"}, Pre: []string{".execute"},
		Re: regexp.MustCompile(`(?i)\.execute(?:many)?\s*\(\s*(?:f['"]|['"][^'"]*['"]\s*(?:%|\+|\.format\())`),
	},
	{
		ID: "py.requests-verify-false", Title: "TLS verification disabled (verify=False)",
		Category: CatNetwork, Severity: SevHigh, Confidence: "high", CWE: "CWE-295",
		Message: "requests(…, verify=False) disables certificate validation, enabling man-in-the-middle interception.",
		Recommendation: "Point verify= at the proper CA bundle instead of disabling it.",
		Langs: []string{"Python"}, Pre: []string{"verify=false"},
		Re: regexp.MustCompile(`(?i)\bverify\s*=\s*False\b`),
	},
	{
		ID: "py.weak-hash", Title: "Weak hash algorithm (MD5/SHA-1)",
		Category: CatCrypto, Severity: SevMedium, Confidence: "high", CWE: "CWE-328",
		Message: "hashlib.md5/sha1 are collision-broken; unsafe for passwords, signatures, or integrity of untrusted data.",
		Recommendation: "Use hashlib.sha256+, and bcrypt/scrypt/argon2 for passwords.",
		Langs: []string{"Python"}, Pre: []string{"hashlib.md5", "hashlib.sha1"},
		Re: regexp.MustCompile(`hashlib\.(?:md5|sha1)\s*\(`),
	},
	{
		ID: "py.flask-debug", Title: "Flask app run with debug=True",
		Category: CatConfig, Severity: SevMedium, Confidence: "high", CWE: "CWE-489",
		Message: "Flask debug mode exposes the Werkzeug debugger — interactive code execution — if reachable in production.",
		Recommendation: "Drive debug mode from an environment flag; never enable it in production.",
		Langs: []string{"Python"}, Pre: []string{"debug=true"},
		Re: regexp.MustCompile(`\.run\s*\([^)]*debug\s*=\s*True`),
	},
	{
		ID: "py.django-debug", Title: "Django DEBUG = True",
		Category: CatConfig, Severity: SevMedium, Confidence: "low", CWE: "CWE-489",
		Message: "Django DEBUG mode leaks settings, stack traces and environment details on errors.",
		Recommendation: "Set DEBUG via environment configuration; keep it False in production.",
		Langs: []string{"Python"}, PathRe: regexp.MustCompile(`(?i)settings[^/]*\.py$`), Pre: []string{"debug = true", "debug=true"},
		Re: regexp.MustCompile(`(?m)^\s*DEBUG\s*=\s*True\b`),
	},
	{
		ID: "py.tempfile-mktemp", Title: "Insecure tempfile.mktemp()",
		Category: CatConfig, Severity: SevMedium, Confidence: "high", CWE: "CWE-377",
		Message: "tempfile.mktemp is race-prone: the name can be hijacked between creation and use.",
		Recommendation: "Use tempfile.NamedTemporaryFile / mkstemp.",
		Langs: []string{"Python"}, Pre: []string{"mktemp"},
		Re: regexp.MustCompile(`tempfile\.mktemp\s*\(`),
	},
	{
		ID: "py.paramiko-autoadd", Title: "SSH host keys auto-accepted",
		Category: CatNetwork, Severity: SevMedium, Confidence: "high", CWE: "CWE-295",
		Message: "paramiko AutoAddPolicy accepts any SSH host key, defeating MITM protection.",
		Recommendation: "Pin known_hosts entries or verify fingerprints.",
		Langs: []string{"Python"}, Pre: []string{"autoaddpolicy"},
		Re: regexp.MustCompile(`AutoAddPolicy\s*\(`),
	},

	// ---------------------------------------------------------------- Go
	{
		ID: "go.insecure-skip-verify", Title: "TLS InsecureSkipVerify enabled",
		Category: CatNetwork, Severity: SevHigh, Confidence: "high", CWE: "CWE-295",
		Message: "InsecureSkipVerify:true disables TLS certificate validation for this client.",
		Recommendation: "Install the proper CA roots; only skip verification in tests.",
		Langs: []string{"Go"}, Pre: []string{"insecureskipverify"},
		Re: regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`),
	},
	{
		ID: "go.weak-hash", Title: "Weak hash algorithm (MD5/SHA-1)",
		Category: CatCrypto, Severity: SevMedium, Confidence: "medium", CWE: "CWE-328",
		Message: "crypto/md5 and crypto/sha1 are collision-broken; unsafe for signatures or password storage.",
		Recommendation: "Use crypto/sha256+, and bcrypt/argon2 for passwords.",
		Langs: []string{"Go"}, Pre: []string{"md5.", "sha1."},
		Re: regexp.MustCompile(`\b(?:md5|sha1)\.(?:New|Sum)\b`),
	},
	{
		ID: "go.sql-sprintf", Title: "SQL built with fmt.Sprintf / concatenation",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-89",
		Message: "Query/Exec receives SQL assembled from variables rather than bound parameters.",
		Recommendation: "Use placeholder parameters: db.Query(\"… WHERE id = $1\", id).",
		Langs: []string{"Go"}, Pre: []string{".query", ".exec"},
		Re: regexp.MustCompile(`\.(?:Query|QueryRow|Exec)(?:Context)?\s*\(\s*(?:fmt\.Sprintf\s*\(|"[^"]*"\s*\+)`),
	},
	{
		ID: "go.exec-shell", Title: "Shell invocation via exec.Command",
		Category: CatInjection, Severity: SevMedium, Confidence: "medium", CWE: "CWE-78",
		Message: "exec.Command(\"sh\", \"-c\", …) routes through a shell; interpolated input becomes command injection.",
		Recommendation: "Invoke the target binary directly with discrete arguments.",
		Langs: []string{"Go"}, Pre: []string{"exec.command"},
		Re: regexp.MustCompile(`exec\.Command(?:Context)?\s*\(\s*[^,)]*"(?:sh|bash|cmd)"\s*,\s*[^,)]*"-c"`),
	},
	{
		ID: "go.math-rand-secret", Title: "math/rand used for a secret value",
		Category: CatCrypto, Severity: SevMedium, Confidence: "medium", CWE: "CWE-338",
		Message: "math/rand is deterministic; tokens or keys derived from it are predictable.",
		Recommendation: "Use crypto/rand for any security-relevant randomness.",
		Langs: []string{"Go"}, Pre: []string{"rand."},
		Re: regexp.MustCompile(`(?i)(?:token|secret|password|nonce|key|otp)[^\n]{0,50}\brand\.(?:Int|Intn|Read|Float)|\brand\.(?:Int|Intn|Read)[^\n]{0,50}(?:token|secret|password|nonce|otp)`),
	},

	// ---------------------------------------------------------------- Java / Kotlin
	{
		ID: "java.runtime-exec", Title: "Runtime.exec() command execution",
		Category: CatInjection, Severity: SevMedium, Confidence: "medium", CWE: "CWE-78",
		Message: "Runtime.getRuntime().exec with assembled strings is a command-injection sink.",
		Recommendation: "Use ProcessBuilder with discrete arguments and validate inputs.",
		Langs: []string{"Java", "Kotlin", "Scala"}, Pre: []string{"runtime.getruntime"},
		Re: regexp.MustCompile(`Runtime\.getRuntime\s*\(\s*\)\s*\.exec\s*\(`),
	},
	{
		ID: "java.weak-digest", Title: "Weak MessageDigest (MD5/SHA-1)",
		Category: CatCrypto, Severity: SevMedium, Confidence: "high", CWE: "CWE-328",
		Message: "MessageDigest MD5/SHA-1 are collision-broken and unsuitable for security use.",
		Recommendation: "Use SHA-256+, and bcrypt/argon2 for passwords.",
		Langs: []string{"Java", "Kotlin", "Scala"}, Pre: []string{"messagedigest.getinstance"},
		Re: regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"`),
	},
	{
		ID: "java.weak-cipher", Title: "Weak cipher mode (DES/ECB/RC4)",
		Category: CatCrypto, Severity: SevHigh, Confidence: "high", CWE: "CWE-327",
		Message: "DES, RC4 and AES-ECB leak structure or are outright broken.",
		Recommendation: "Use AES-GCM (or ChaCha20-Poly1305) with random nonces.",
		Langs: []string{"Java", "Kotlin", "Scala"}, Pre: []string{"cipher.getinstance"},
		Re: regexp.MustCompile(`Cipher\.getInstance\s*\(\s*"(?:DES|DESede|RC4|Blowfish|AES/ECB)[^"]*"`),
	},
	{
		ID: "java.sql-concat", Title: "SQL built by string concatenation",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-89",
		Message: "executeQuery/execute receives SQL concatenated from variables instead of a PreparedStatement.",
		Recommendation: "Use PreparedStatement with bound parameters.",
		Langs: []string{"Java", "Kotlin", "Scala"}, Pre: []string{"executequery", "executeupdate"},
		Re: regexp.MustCompile(`(?:executeQuery|executeUpdate|execute)\s*\(\s*"[^"]*"\s*\+`),
	},
	{
		ID: "java.trust-all", Title: "Trust-all TLS configuration",
		Category: CatNetwork, Severity: SevHigh, Confidence: "medium", CWE: "CWE-295",
		Message: "A trust-all TrustManager or allow-all hostname verifier disables TLS authentication.",
		Recommendation: "Trust the proper CA chain; never ship trust-all code.",
		Langs: []string{"Java", "Kotlin", "Scala"}, Pre: []string{"allow_all", "trustall", "allowall"},
		Re: regexp.MustCompile(`(?i)ALLOW_ALL_HOSTNAME_VERIFIER|TrustAll(?:Certs|Manager)?|AllowAllHostnameVerifier`),
	},
	{
		ID: "java.object-deserialize", Title: "Java native deserialization",
		Category: CatInjection, Severity: SevMedium, Confidence: "low", CWE: "CWE-502",
		Message: "ObjectInputStream.readObject on untrusted data enables gadget-chain remote code execution.",
		Recommendation: "Avoid native serialization across trust boundaries; use JSON with strict typing.",
		Langs: []string{"Java", "Kotlin", "Scala"}, Pre: []string{"objectinputstream"},
		Re: regexp.MustCompile(`new\s+ObjectInputStream\s*\(`),
	},

	// ---------------------------------------------------------------- PHP
	{
		ID: "php.eval", Title: "eval() — dynamic code execution",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-95",
		Message: "eval on strings executes arbitrary PHP — with request data this is remote code execution.",
		Recommendation: "Remove eval; use data structures or dispatch tables.",
		Langs: []string{"PHP"}, Pre: []string{"eval("},
		Re: regexp.MustCompile(`(?m)(?:^|[^\w$])eval\s*\(`),
	},
	{
		ID: "php.command-exec", Title: "Shell execution with interpolated variables",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-78",
		Message: "system/exec/shell_exec/passthru with a $variable in the command string is a command-injection sink.",
		Recommendation: "Use escapeshellarg/escapeshellcmd, or avoid shelling out.",
		Langs: []string{"PHP"}, Pre: []string{"system(", "shell_exec(", "passthru(", "exec("},
		Re: regexp.MustCompile(`\b(?:system|exec|shell_exec|passthru|popen)\s*\(\s*(?:"[^"]*\$|\$|'[^']*'\s*\.\s*\$)`),
	},
	{
		ID: "php.sql-interpolation", Title: "SQL with interpolated variables",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-89",
		Message: "A query embeds $variables directly inside the SQL string.",
		Recommendation: "Use PDO prepared statements with bound parameters.",
		Langs: []string{"PHP"}, Pre: []string{"select ", "insert into", "update ", "delete from"},
		Re: regexp.MustCompile(`(?i)"(?:SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^"]*\$\w+`),
	},
	{
		ID: "php.echo-request", Title: "Request data echoed unescaped",
		Category: CatXSS, Severity: SevHigh, Confidence: "medium", CWE: "CWE-79",
		Message: "echo/print of $_GET/$_POST/$_REQUEST without htmlspecialchars is reflected XSS.",
		Recommendation: "Wrap output in htmlspecialchars(…, ENT_QUOTES).",
		Langs: []string{"PHP"}, Pre: []string{"$_get", "$_post", "$_request"},
		Re: regexp.MustCompile(`(?i)(?:echo|print)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b`),
	},
	{
		ID: "php.unserialize", Title: "unserialize() of request data",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-502",
		Message: "unserialize on attacker-controlled strings enables PHP object-injection gadget chains.",
		Recommendation: "Use json_decode for untrusted data.",
		Langs: []string{"PHP"}, Pre: []string{"unserialize"},
		Re: regexp.MustCompile(`unserialize\s*\(\s*\$`),
	},
	{
		ID: "php.include-variable", Title: "include/require with variable path",
		Category: CatInjection, Severity: SevHigh, Confidence: "low", CWE: "CWE-98",
		Message: "Including a file whose path comes from a variable risks local/remote file inclusion.",
		Recommendation: "Whitelist includable files; never derive paths from request input.",
		Langs: []string{"PHP"}, Pre: []string{"include", "require"},
		Re: regexp.MustCompile(`\b(?:include|include_once|require|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)`),
	},

	// ---------------------------------------------------------------- Ruby
	{
		ID: "rb.eval", Title: "eval / class_eval — dynamic code execution",
		Category: CatInjection, Severity: SevMedium, Confidence: "medium", CWE: "CWE-95",
		Message: "eval-family methods execute strings as Ruby; interpolating input is code injection.",
		Recommendation: "Use send with whitelisted symbols or restructure the logic.",
		Langs: []string{"Ruby"}, Pre: []string{"eval"},
		Re: regexp.MustCompile(`(?m)(?:^|[^\w.])(?:eval|class_eval|instance_eval|module_eval)\s*[\( ]\s*["']?[#$\w]`),
	},
	{
		ID: "rb.command-interpolation", Title: "Shell command with interpolation",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-78",
		Message: "system/backtick commands with #{…} interpolation are command-injection sinks.",
		Recommendation: "Pass argument arrays: system('cmd', arg1, arg2).",
		Langs: []string{"Ruby"}, Pre: []string{"system(", "%x", "\x60"},
		Re: regexp.MustCompile("(?:system|exec|popen)\\s*\\(\\s*\"[^\"]*#\\{|\x60[^\x60]*#\\{"),
	},
	{
		ID: "rb.marshal-load", Title: "Marshal.load of untrusted data",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-502",
		Message: "Marshal.load can instantiate arbitrary objects — remote code execution with untrusted bytes.",
		Recommendation: "Use JSON for untrusted data.",
		Langs: []string{"Ruby"}, Pre: []string{"marshal.load"},
		Re: regexp.MustCompile(`Marshal\.load\s*\(`),
	},
	{
		ID: "rb.send-params", Title: "send() driven by request params",
		Category: CatInjection, Severity: SevHigh, Confidence: "medium", CWE: "CWE-470",
		Message: "Calling send with params lets attackers invoke arbitrary methods on the object.",
		Recommendation: "Use public_send against an explicit whitelist.",
		Langs: []string{"Ruby"}, Pre: []string{"send(params", "send(:"},
		Re: regexp.MustCompile(`\.send\s*\(\s*params\b`),
	},
	{
		ID: "rb.html-safe", Title: "html_safe on dynamic content",
		Category: CatXSS, Severity: SevMedium, Confidence: "low", CWE: "CWE-79",
		Message: "html_safe disables Rails auto-escaping for this string; with user data it becomes XSS.",
		Recommendation: "Use sanitize/strip_tags, or build markup with helpers.",
		Langs: []string{"Ruby"}, Pre: []string{"html_safe"},
		Re: regexp.MustCompile(`\.html_safe\b`),
	},

	// ---------------------------------------------------------------- C / C++
	{
		ID: "c.gets", Title: "gets() — unbounded read",
		Category: CatInjection, Severity: SevHigh, Confidence: "high", CWE: "CWE-242",
		Message: "gets() cannot bound its read and is a guaranteed buffer overflow with long input; removed from C11 for this reason.",
		Recommendation: "Use fgets with an explicit buffer size.",
		Langs: []string{"C", "C++"}, Pre: []string{"gets("},
		Re: regexp.MustCompile(`(?m)(?:^|[^\w.>])gets\s*\(`),
	},
	{
		ID: "c.unsafe-string-fns", Title: "Unbounded string copy (strcpy/strcat/sprintf)",
		Category: CatInjection, Severity: SevMedium, Confidence: "medium", CWE: "CWE-120",
		Message: "strcpy/strcat/sprintf write without bounds checks — classic buffer-overflow primitives.",
		Recommendation: "Use strncpy/strlcpy/snprintf with explicit sizes.",
		Langs: []string{"C", "C++"}, Pre: []string{"strcpy(", "strcat(", "sprintf("},
		Re: regexp.MustCompile(`(?m)(?:^|[^\w.>])(?:strcpy|strcat|sprintf)\s*\(`),
	},
	{
		ID: "c.system", Title: "system() command execution",
		Category: CatInjection, Severity: SevMedium, Confidence: "medium", CWE: "CWE-78",
		Message: "system() routes through the shell; assembled commands risk injection.",
		Recommendation: "Use exec-family calls with discrete arguments.",
		Langs: []string{"C", "C++"}, Pre: []string{"system("},
		Re: regexp.MustCompile(`(?m)(?:^|[^\w.:>])system\s*\(\s*[^")]`),
	},

	// ---------------------------------------------------------------- Shell
	{
		ID: "sh.curl-pipe-sh", Title: "Remote script piped into shell",
		Category: CatInjection, Severity: SevHigh, Confidence: "high", CWE: "CWE-494",
		Message: "curl|sh executes whatever the server (or a man-in-the-middle) returns, with no integrity check.",
		Recommendation: "Download, verify a checksum/signature, then execute.",
		Langs: nil, Pre: []string{"curl", "wget"},
		Re: regexp.MustCompile(`(?:curl|wget)[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b`),
	},
	{
		ID: "sh.chmod-777", Title: "World-writable permissions (chmod 777)",
		Category: CatConfig, Severity: SevMedium, Confidence: "high", CWE: "CWE-732",
		Message: "chmod 777 lets every local user modify and execute the target.",
		Recommendation: "Grant the minimum mode needed (e.g. 750 / 640).",
		Langs: nil, Pre: []string{"chmod 777", "chmod -r 777"},
		Re: regexp.MustCompile(`chmod\s+(?:-R\s+)?777\b`),
	},

	// ---------------------------------------------------------------- generic
	{
		ID: "gen.cors-wildcard", Title: "CORS allows any origin",
		Category: CatConfig, Severity: SevMedium, Confidence: "medium", CWE: "CWE-942",
		Message: "Access-Control-Allow-Origin:* exposes responses to every website; combined with credentials it leaks data cross-origin.",
		Recommendation: "Reflect a vetted origin allowlist instead of '*'.",
		Langs: nil, Pre: []string{"access-control-allow-origin"},
		Re: regexp.MustCompile(`(?i)Access-Control-Allow-Origin['"]?\s*[:=,]\s*['"]?\*`),
	},
	{
		ID: "gen.http-url", Title: "Cleartext http:// endpoint",
		Category: CatNetwork, Severity: SevLow, Confidence: "low", CWE: "CWE-319",
		Message: "Traffic to this http:// endpoint travels unencrypted and can be read or modified in transit.",
		Recommendation: "Use https:// (the endpoint almost certainly supports it).",
		// Code files only: cleartext URLs in docs/changelogs are not a transport risk.
		Langs: []string{"JavaScript", "TypeScript", "Python", "Go", "Ruby", "Java", "Kotlin", "PHP", "C#", "C", "C++", "Rust", "Shell", "Swift", "Scala", "DotEnv", "Docker", "Terraform"},
		Pre:   []string{"http://"},
		Re: regexp.MustCompile(`['"\x60(=\s](http://[a-z0-9][a-z0-9.\-]+\.[a-z]{2,}[^\s'"\x60<>)]*)`),
		ValueGroup: 1,
		Validate: func(v, _ string) bool {
			for _, allow := range []string{"localhost", "127.0.0.1", "0.0.0.0", "example.", "w3.org", "schemas.", "schema.org", "xmlns", "apache.org", "openxmlformats", "maven.apache", "json-schema.org", "purl.org", "ns.adobe", "sun.com", "android.com/apk", "mozilla.org", "test", "internal", "local"} {
				if containsFold(v, allow) {
					return false
				}
			}
			return true
		},
	},
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
