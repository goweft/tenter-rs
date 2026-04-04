mod check;
mod config;
mod finding;
mod glob;
mod output;
mod rules;
mod scanner;

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use is_terminal::IsTerminal;
use std::path::PathBuf;

use config::load_config;
use finding::{Severity, VERSION};
use scanner::{detect_package_type, Scanner};

// ─── CLI types ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Human,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FailOn {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl From<FailOn> for Severity {
    fn from(f: FailOn) -> Self {
        match f {
            FailOn::Critical => Severity::Critical,
            FailOn::High => Severity::High,
            FailOn::Medium => Severity::Medium,
            FailOn::Low => Severity::Low,
            FailOn::Info => Severity::Info,
        }
    }
}

#[derive(Debug, Parser)]
#[command(
    name = "tenter",
    version = VERSION,
    about = "Pre-publish artifact integrity scanner.",
    long_about = "Detects source maps, debug artifacts, secrets, and sensitive files \
                  before they ship in your package.\n\n\
                  Born from the Claude Code npm source map leak (2026-03-31).",
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan a package artifact or directory
    Scan {
        /// Path to scan (directory, tarball .tgz, wheel .whl, or .crate)
        target: PathBuf,

        /// Package type override (default: auto-detect)
        #[arg(short = 't', long, default_value = "auto")]
        r#type: String,

        /// Output format
        #[arg(short, long, default_value = "human")]
        format: OutputFormat,

        /// Config file path (default: .tenter.json in cwd)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Disable coloured output
        #[arg(long)]
        no_color: bool,

        /// Minimum severity that causes exit code 2
        #[arg(long, default_value = "high")]
        fail_on: FailOn,
    },

    /// Run npm pack --dry-run and scan the reported file list
    NpmCheck {
        /// Path to npm project directory
        #[arg(default_value = ".")]
        project_dir: PathBuf,

        #[arg(short, long, default_value = "human")]
        format: OutputFormat,

        #[arg(short, long)]
        config: Option<PathBuf>,

        #[arg(long)]
        no_color: bool,

        #[arg(long, default_value = "high")]
        fail_on: FailOn,
    },

    /// Create a default .tenter.json config file
    Init,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("tenter: {e:#}");
            1
        }
    };
    std::process::exit(code);
}

fn run(cli: Cli) -> Result<i32> {
    match cli.command {
        Commands::Init => cmd_init(),

        Commands::Scan { target, r#type, format, config, no_color, fail_on } => {
            let cfg = load_config(config.as_deref())?;
            let scanner = Scanner::new(cfg);

            let pkg_type = if r#type == "auto" {
                detect_package_type(&target).to_owned()
            } else {
                r#type
            };

            let result = if target.is_dir() {
                scanner.scan_directory(&target, &pkg_type)
            } else {
                let name = target
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase();
                if name.ends_with(".whl") {
                    scanner.scan_zip(&target, "pip")
                } else {
                    scanner.scan_tarball(&target, &pkg_type)
                }
            };

            emit(&result, format, no_color);
            Ok(exit_code(&result, fail_on.into()))
        }

        Commands::NpmCheck { project_dir, format, config, no_color, fail_on } => {
            let cfg = load_config(config.as_deref())?;
            let scanner = Scanner::new(cfg);
            let result = scanner.scan_npm_dry_run(&project_dir);
            emit(&result, format, no_color);
            Ok(exit_code(&result, fail_on.into()))
        }
    }
}

fn cmd_init() -> Result<i32> {
    let out = std::path::Path::new(".tenter.json");
    if out.exists() {
        eprintln!("Config already exists at .tenter.json");
        return Ok(1);
    }
    let val: serde_json::Value = serde_json::from_str(&config::Config::default_json())?;
    let json = serde_json::to_string_pretty(&val)?;
    std::fs::write(out, format!("{json}\n"))?;
    println!("Created .tenter.json");
    Ok(0)
}

fn emit(result: &finding::ScanResult, format: OutputFormat, no_color: bool) {
    match format {
        OutputFormat::Human => {
            let color = !no_color && std::io::stdout().is_terminal();
            print!("{}", output::human::format(result, color));
        }
        OutputFormat::Json => println!("{}", output::json::format(result)),
        OutputFormat::Sarif => println!("{}", output::sarif::format(result)),
    }
}

fn exit_code(result: &finding::ScanResult, threshold: Severity) -> i32 {
    if result.has_finding_at_or_above(threshold) { 2 } else { 0 }
}
