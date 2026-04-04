use regex::bytes::Regex;
use std::sync::OnceLock;

// ─── Source map extensions ────────────────────────────────────────────────────

pub const SOURCE_MAP_EXTENSIONS: &[&str] = &[
    ".map", ".js.map", ".css.map", ".ts.map", ".mjs.map", ".cjs.map",
];

pub const SOURCE_MAP_URL_EXTENSIONS: &[&str] = &[".js", ".mjs", ".cjs", ".css"];

// ─── Glob patterns ───────────────────────────────────────────────────────────

pub const DEBUG_PATTERNS: &[&str] = &[
    "*.map", "*.pdb", "*.dSYM", "*.dwarf", "*.debug",
    "*.dbg", "*.sym", "*.sourcemap", "**/src.zip", "**/.debug/",
];

pub const SENSITIVE_FILE_PATTERNS: &[&str] = &[
    ".env", ".env.*", "*.env", ".npmrc", ".pypirc",
    ".cargo/credentials", ".cargo/credentials.toml",
    "**/.git-credentials", "**/id_rsa", "**/id_ed25519", "**/id_ecdsa",
    "**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx", "**/*.jks", "**/*.keystore",
    "**/credentials.json", "**/service-account*.json", "**/.htpasswd", "**/.netrc",
    "**/token.json", "**/secrets.yaml", "**/secrets.yml", "**/secrets.json",
    "**/.docker/config.json", "**/kubeconfig",
];

pub const INTERNAL_PATTERNS: &[&str] = &[
    "**/.claude/**", "**/CLAUDE.md", "**/.cursor/**", "**/.vscode/settings.json",
    "**/.idea/**", "**/tsconfig.tsbuildinfo", "**/.eslintcache", "**/coverage/**",
    "**/__pycache__/**", "**/*.pyc", "**/node_modules/**", "**/.git/**",
    "**/Thumbs.db", "**/.DS_Store", "**/.internal/**", "**/.internal.*",
    "**/TODO.internal*", "**/NOTES.internal*",
];

// ─── Secret regex patterns ────────────────────────────────────────────────────
// All use regex::bytes — DFA/NFA, linear time, no ReDoS possible.
// \s is not available without unicode-perl feature in byte-mode; use [ \t\r\n] instead.

pub struct SecretPattern {
    pub regex: &'static OnceLock<Regex>,
    pub raw: &'static str,
    pub description: &'static str,
}

macro_rules! secret_patterns {
    ( $( ($lock:ident, $raw:expr, $desc:expr) ),* $(,)? ) => {
        $(
            static $lock: OnceLock<Regex> = OnceLock::new();
        )*

        pub fn secret_patterns() -> &'static [SecretPattern] {
            static PATTERNS: OnceLock<Vec<SecretPattern>> = OnceLock::new();
            PATTERNS.get_or_init(|| {
                vec![
                    $(
                        SecretPattern {
                            regex: &$lock,
                            raw: $raw,
                            description: $desc,
                        },
                    )*
                ]
            })
        }
    };
}

secret_patterns!(
    (RE_AWS_KEY,
     r"AKIA[0-9A-Z]{16}",
     "AWS Access Key ID"),
    // \s -> [ \t\r\n] for byte-string regex engine
    (RE_AWS_SECRET,
     r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[ \t\r\n]*[=:][ \t\r\n]*[A-Za-z0-9/+=]{20,}",
     "AWS Secret Key"),
    (RE_GHP,
     r"ghp_[a-zA-Z0-9]{36,}",
     "GitHub Personal Access Token"),
    (RE_GHO,
     r"gho_[a-zA-Z0-9]{36}",
     "GitHub OAuth Token"),
    (RE_GH_PAT,
     r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
     "GitHub Fine-Grained PAT"),
    (RE_OPENAI,
     r"sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}",
     "OpenAI API Key"),
    (RE_ANTHROPIC,
     r"sk-ant-api[0-9]{2}-[a-zA-Z0-9\-_]{80,}",
     "Anthropic API Key"),
    (RE_SLACK,
     r"xox[boaprs]-[0-9]{10,}-[a-zA-Z0-9\-]+",
     "Slack Token"),
    (RE_PRIVKEY,
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
     "Private Key"),
    (RE_NPM,
     r"npm_[a-zA-Z0-9]{36}",
     "npm Access Token"),
    (RE_PYPI,
     r"pypi-[a-zA-Z0-9\-_]{100,}",
     "PyPI API Token"),
    // (?i) flag works in byte mode; ['"'] for quote chars; [^\x27\x22] avoids \s issues
    (RE_PASSWORD,
     r"(?i)(?:password|passwd|pwd)[ \t\r\n]*[=:][ \t\r\n]*[\x27\x22][^\x27\x22]{8,}[\x27\x22]",
     "Hardcoded Password"),
    (RE_APIKEY,
     r"(?i)(?:api_key|apikey|api-key)[ \t\r\n]*[=:][ \t\r\n]*[\x27\x22][^\x27\x22]{16,}[\x27\x22]",
     "Hardcoded API Key"),
    (RE_BEARER,
     r"Bearer[ \t]+[a-zA-Z0-9\-_.~+/]{20,}",
     "Bearer Token"),
);

pub fn source_map_url_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)//[#@][ \t]*sourceMappingURL[ \t]*=[ \t]*(\S+)").unwrap()
    })
}

pub fn compile_pattern(raw: &str) -> Result<Regex, regex::Error> {
    Regex::new(raw)
}
