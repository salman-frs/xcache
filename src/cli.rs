use std::ffi::OsString;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};

use crate::run::{self, RunOptions};
use crate::store::Store;

/// Exit status when xcache itself fails, kept apart from the command's own statuses.
const INTERNAL_ERROR: i32 = 125;

#[derive(Parser)]
#[command(name = "xcache", version, about = "Skip commands whose inputs have not changed, with no configuration")]
struct Cli {
    /// Cache directory [default: $XDG_CACHE_HOME/xcache or ~/.cache/xcache]
    #[arg(long, env = "XCACHE_DIR", global = true, value_name = "DIR")]
    store: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a command, or restore its result if nothing it depends on has changed
    Run {
        /// Run the command even on a hit and report whether the cached result matches
        #[arg(long)]
        shadow: bool,

        /// Write a JSON report of what happened to FILE
        #[arg(long, value_name = "FILE")]
        report: Option<PathBuf>,

        /// Only print xcache messages for errors and false hits
        #[arg(short, long)]
        quiet: bool,

        #[command(flatten)]
        command: CommandLine,
    },
    /// Show why a command would or would not hit the cache
    Explain {
        #[command(flatten)]
        command: CommandLine,
    },
    /// Shrink the cache to a size budget, dropping least recently used results
    Gc {
        /// Size budget, such as 500M or 5G
        #[arg(long, value_parser = parse_size, value_name = "SIZE")]
        max_size: u64,
    },
}

#[derive(Args)]
struct CommandLine {
    /// Pass a variable that xcache removes by default (such as GITHUB_SHA) to the command
    #[arg(long = "pass-env", value_name = "NAME")]
    pass_env: Vec<String>,

    /// The command to run
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true, value_name = "COMMAND")]
    argv: Vec<OsString>,
}

pub fn main() -> i32 {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("xcache: {error:#}");
            INTERNAL_ERROR
        }
    }
}

fn dispatch(cli: Cli) -> Result<i32> {
    let store_dir = match cli.store {
        Some(dir) => dir,
        None => default_store_dir()?,
    };
    match cli.command {
        Commands::Run { shadow, report, quiet, command } => {
            run::run(RunOptions { argv: command.argv, pass_env: command.pass_env, store_dir, shadow, report, quiet })
        }
        Commands::Explain { command } => run::explain(command.argv, &command.pass_env, store_dir).map(|()| 0),
        Commands::Gc { max_size } => {
            let stats = Store::open(store_dir)?.gc(max_size)?;
            println!(
                "removed {} entries and {} blobs; {} bytes of results kept",
                stats.entries_removed, stats.blobs_removed, stats.bytes_kept
            );
            Ok(0)
        }
    }
}

fn default_store_dir() -> Result<PathBuf> {
    let cache_home = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))
        .context("set XCACHE_DIR, XDG_CACHE_HOME or HOME to choose a cache directory")?;
    Ok(cache_home.join("xcache"))
}

fn parse_size(text: &str) -> Result<u64> {
    let text = text.trim();
    let split = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let number: u64 = number.parse().with_context(|| format!("invalid size {text:?}"))?;
    let multiplier: u64 = match unit.to_ascii_uppercase().as_str() {
        "" | "B" => 1,
        "K" | "KB" => 1 << 10,
        "M" | "MB" => 1 << 20,
        "G" | "GB" => 1 << 30,
        "T" | "TB" => 1 << 40,
        _ => bail!("unknown size unit in {text:?}"),
    };
    number.checked_mul(multiplier).context("size is too large")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sizes() {
        assert_eq!(parse_size("512").unwrap(), 512);
        assert_eq!(parse_size("5G").unwrap(), 5 << 30);
        assert_eq!(parse_size("300mb").unwrap(), 300 << 20);
        assert!(parse_size("5X").is_err());
    }

    #[test]
    fn cli_definition_is_valid() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
