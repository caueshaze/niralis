use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::sessions::desktop_entry::CanonicalSessionEntry;
use crate::{DiscoveryError, ResolvedSessionLaunchSpec};

pub const MAX_DESKTOP_ENTRY_BYTES: usize = 64 * 1024;
pub const MAX_EXEC_BYTES: usize = 8 * 1024;
pub const MAX_ARGC: usize = 64;
pub const MAX_ARG_BYTES: usize = 4 * 1024;
pub const MAX_ARGV_BYTES: usize = 16 * 1024;

pub(super) fn resolve(
    entry: CanonicalSessionEntry,
    search_path: &[PathBuf],
) -> Result<ResolvedSessionLaunchSpec, DiscoveryError> {
    let argv = parse_exec(&entry.exec)?;
    let executable = resolve_executable(Path::new(&argv[0]), search_path)?;
    if let Some(try_exec) = entry.try_exec.as_deref() {
        if !try_exec_is_available(try_exec, search_path) {
            return Err(DiscoveryError::InvalidLaunchSpec);
        }
    }
    Ok(ResolvedSessionLaunchSpec {
        session: entry.session,
        source_path: entry.source_path,
        executable,
        argv: argv.into_iter().map(OsString::from).collect(),
    })
}

pub(super) fn try_exec_is_eligible(entry: &CanonicalSessionEntry, search_path: &[PathBuf]) -> bool {
    entry
        .try_exec
        .as_deref()
        .map(|value| try_exec_is_available(value, search_path))
        .unwrap_or(true)
}

fn parse_exec(value: &str) -> Result<Vec<String>, DiscoveryError> {
    if value.is_empty() || value.len() > MAX_EXEC_BYTES || value.as_bytes().contains(&0) {
        return Err(DiscoveryError::InvalidLaunchSpec);
    }
    let mut argv = Vec::new();
    let mut token = String::new();
    let mut quoted = false;
    let mut token_started = false;
    let mut chars = value.chars().peekable();
    while let Some(character) = chars.next() {
        if character.is_control() {
            return Err(DiscoveryError::InvalidLaunchSpec);
        }
        if quoted {
            match character {
                '"' => quoted = false,
                '\\' => match chars.next() {
                    Some(escaped @ ('"' | '`' | '$' | '\\')) => token.push(escaped),
                    _ => return Err(DiscoveryError::InvalidLaunchSpec),
                },
                '%' => expand_percent(&mut token, &mut chars, true)?,
                other => token.push(other),
            }
            token_started = true;
            continue;
        }
        match character {
            ' ' | '\t' => {
                if token_started {
                    push_token(&mut argv, std::mem::take(&mut token))?;
                    token_started = false;
                }
            }
            '"' => {
                quoted = true;
                token_started = true;
            }
            '%' => {
                expand_percent(&mut token, &mut chars, false)?;
                token_started = true;
            }
            '\\' => return Err(DiscoveryError::InvalidLaunchSpec),
            other => {
                token.push(other);
                token_started = true;
            }
        }
    }
    if quoted || !token_started && argv.is_empty() {
        return Err(DiscoveryError::InvalidLaunchSpec);
    }
    if token_started {
        push_token(&mut argv, token)?;
    }
    if argv.is_empty() {
        return Err(DiscoveryError::InvalidLaunchSpec);
    }
    let total = argv
        .iter()
        .try_fold(0usize, |sum, arg| sum.checked_add(arg.len() + 1))
        .ok_or(DiscoveryError::InvalidLaunchSpec)?;
    if total > MAX_ARGV_BYTES {
        return Err(DiscoveryError::InvalidLaunchSpec);
    }
    Ok(argv)
}

fn expand_percent(
    token: &mut String,
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    quoted: bool,
) -> Result<(), DiscoveryError> {
    let code = chars.next().ok_or(DiscoveryError::InvalidLaunchSpec)?;
    if code == '%' {
        token.push('%');
        return Ok(());
    }
    let _ = quoted;
    Err(DiscoveryError::InvalidLaunchSpec)
}

fn push_token(argv: &mut Vec<String>, token: String) -> Result<(), DiscoveryError> {
    if token.len() > MAX_ARG_BYTES || argv.len() >= MAX_ARGC {
        return Err(DiscoveryError::InvalidLaunchSpec);
    }
    argv.push(token);
    Ok(())
}

pub(super) fn try_exec_is_available(value: &str, search_path: &[PathBuf]) -> bool {
    if value.is_empty()
        || value.len() > MAX_ARG_BYTES
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_whitespace())
    {
        return false;
    }
    resolve_executable(Path::new(value), search_path).is_ok()
}

pub(super) fn resolve_executable(
    command: &Path,
    search_path: &[PathBuf],
) -> Result<PathBuf, DiscoveryError> {
    let candidate = if command.is_absolute() {
        command.to_path_buf()
    } else {
        if command.components().count() != 1 || command.as_os_str().is_empty() {
            return Err(DiscoveryError::InvalidLaunchSpec);
        }
        search_path
            .iter()
            .map(|directory| directory.join(command))
            .find(|path| is_executable(path))
            .ok_or(DiscoveryError::InvalidLaunchSpec)?
    };
    if !is_executable(&candidate) {
        return Err(DiscoveryError::InvalidLaunchSpec);
    }
    fs::canonicalize(candidate).map_err(|_| DiscoveryError::InvalidLaunchSpec)
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exec_tokens_are_not_shell() {
        assert_eq!(
            parse_exec("example $HOME && rm").unwrap(),
            ["example", "$HOME", "&&", "rm"]
        );
    }
    #[test]
    fn literal_percent_is_supported() {
        assert_eq!(parse_exec("example %%").unwrap(), ["example", "%"]);
    }
    #[test]
    fn field_codes_fail_closed() {
        for code in ["%f", "%F", "%u", "%U", "%i", "%c", "%k", "%z"] {
            assert!(parse_exec(&format!("example {code}")).is_err());
        }
    }
    #[test]
    fn malformed_quotes_fail() {
        assert!(parse_exec("example \"unterminated").is_err());
    }
}
