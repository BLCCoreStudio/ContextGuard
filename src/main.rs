use std::{
    env, fs,
    io::{self, Read},
    process,
};

const REDACTED: &str = "[REDACTED]";

fn is_sensitive_key(key: &str) -> bool {
    let trimmed = key
        .trim()
        .trim_matches(|ch| matches!(ch, '"' | '\''));
    let candidate = trimmed.strip_prefix("export ").unwrap_or(trimmed);
    let normalized: String = candidate
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();

    const KEYS: [&str; 12] = [
        "API_KEY",
        "APIKEY",
        "TOKEN",
        "AUTH_TOKEN",
        "AUTHORIZATION",
        "SECRET",
        "CLIENT_SECRET",
        "PASSWORD",
        "PASSWD",
        "ACCESS_KEY",
        "SECRET_KEY",
        "PRIVATE_KEY",
    ];

    KEYS.iter().any(|key| normalized.ends_with(key))
}

fn redact_assignment(line: &str) -> Option<String> {
    for separator in ['=', ':'] {
        if let Some(index) = line.find(separator) {
            let (left, right_with_separator) = line.split_at(index);
            let right = &right_with_separator[separator.len_utf8()..];
            if is_sensitive_key(left) && !right.trim().is_empty() {
                return Some(format!("{}{separator}{REDACTED}", left.trim_end()));
            }
        }
    }
    None
}

fn redact_bearer(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let index = lower.find("bearer ")?;
    let token_start = index + "bearer ".len();
    if line[token_start..].trim().is_empty() {
        return None;
    }
    Some(format!("{}{REDACTED}", &line[..token_start]))
}

fn redact_prefixed_token(input: &str, prefix: &str, minimum_len: usize) -> (String, usize) {
    let mut output = input.to_owned();
    let mut cursor = 0;
    let mut count = 0;

    loop {
        let Some(relative) = output[cursor..].find(prefix) else {
            break;
        };
        let start = cursor + relative;
        let mut end = start;
        for (offset, ch) in output[start..].char_indices() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-') {
                end = start + offset + ch.len_utf8();
            } else {
                break;
            }
        }

        if end.saturating_sub(start) >= minimum_len {
            output.replace_range(start..end, REDACTED);
            cursor = start + REDACTED.len();
            count += 1;
        } else {
            cursor = start + prefix.len();
        }
    }

    (output, count)
}

fn redact_home_paths(input: &str, prefix: &str) -> (String, usize) {
    let mut output = input.to_owned();
    let mut cursor = 0;
    let mut count = 0;

    loop {
        let Some(relative) = output[cursor..].find(prefix) else {
            break;
        };
        let start = cursor + relative;
        let user_start = start + prefix.len();
        let Some(relative_end) = output[user_start..].find('/') else {
            break;
        };
        let end = user_start + relative_end;
        if end == user_start {
            cursor = user_start;
            continue;
        }
        output.replace_range(start..end, "<HOME>");
        cursor = start + "<HOME>".len();
        count += 1;
    }

    (output, count)
}

fn redact_text(input: &str) -> (String, usize) {
    let mut output = Vec::new();
    let mut findings = 0;
    let mut in_private_key = false;

    for line in input.lines() {
        if in_private_key {
            if line.contains("-----END ") && line.contains("PRIVATE KEY-----") {
                in_private_key = false;
            }
            continue;
        }

        if line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----") {
            output.push("[REDACTED PRIVATE KEY BLOCK]".to_owned());
            findings += 1;
            in_private_key = true;
            continue;
        }

        let mut current = if let Some(redacted) = redact_assignment(line) {
            findings += 1;
            redacted
        } else if let Some(redacted) = redact_bearer(line) {
            findings += 1;
            redacted
        } else {
            line.to_owned()
        };

        for (prefix, minimum_len) in [("github_pat_", 20), ("ghp_", 20), ("sk-", 20), ("AKIA", 16)]
        {
            let (next, count) = redact_prefixed_token(&current, prefix, minimum_len);
            current = next;
            findings += count;
        }

        for prefix in ["/home/", "/Users/"] {
            let (next, count) = redact_home_paths(&current, prefix);
            current = next;
            findings += count;
        }

        output.push(current);
    }

    let mut text = output.join("\n");
    if input.ends_with('\n') {
        text.push('\n');
    }
    (text, findings)
}

fn read_input(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut input = String::new();
        io::stdin()
            .read_to_string(&mut input)
            .map_err(|error| format!("failed to read stdin: {error}"))?;
        Ok(input)
    } else {
        fs::read_to_string(path).map_err(|error| format!("failed to read '{path}': {error}"))
    }
}

fn print_help() {
    println!(
        "ContextGuard 0.1.0-dev\n\nUSAGE:\n  contextguard redact <FILE|->\n  contextguard check <FILE|->\n\nThe current preview is read-only: it never modifies the source file."
    );
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "--help" | "-h") {
        print_help();
        return;
    }
    if matches!(args[0].as_str(), "--version" | "-V") {
        println!("contextguard 0.1.0-dev");
        return;
    }
    if args.len() != 2 || !matches!(args[0].as_str(), "redact" | "check") {
        eprintln!("contextguard: expected 'redact <FILE|->' or 'check <FILE|->'");
        process::exit(2);
    }

    let input = match read_input(&args[1]) {
        Ok(input) => input,
        Err(error) => {
            eprintln!("contextguard: {error}");
            process::exit(2);
        }
    };
    let (redacted, findings) = redact_text(&input);

    if args[0] == "redact" {
        print!("{redacted}");
        return;
    }

    if findings == 0 {
        println!("OK: no current ContextGuard rule matched");
    } else {
        println!("FOUND: {findings} potential sensitive item(s)");
        process::exit(3);
    }
}

#[cfg(test)]
mod tests {
    use super::redact_text;

    #[test]
    fn redacts_api_key_assignment() {
        let (output, count) = redact_text("API_KEY=super-secret-value\n");
        assert_eq!(output, "API_KEY=[REDACTED]\n");
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_bearer_token() {
        let (output, count) = redact_text("Authorization header: Bearer abcdef1234567890\n");
        assert_eq!(output, "Authorization header: Bearer [REDACTED]\n");
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_github_token_prefix() {
        let (output, count) = redact_text("token ghp_1234567890abcdefghijklmnop\n");
        assert_eq!(output, "token [REDACTED]\n");
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_private_key_block() {
        let input =
            "before\n-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\nafter\n";
        let (output, count) = redact_text(input);
        assert_eq!(output, "before\n[REDACTED PRIVATE KEY BLOCK]\nafter\n");
        assert_eq!(count, 1);
    }

    #[test]
    fn redacts_home_directory_identity() {
        let (output, count) = redact_text("path=/home/alice/project/src/main.rs\n");
        assert_eq!(output, "path=<HOME>/project/src/main.rs\n");
        assert_eq!(count, 1);
    }

    #[test]
    fn leaves_safe_text_unchanged() {
        let input = "cargo test --all-targets\n";
        let (output, count) = redact_text(input);
        assert_eq!(output, input);
        assert_eq!(count, 0);
    }
}
