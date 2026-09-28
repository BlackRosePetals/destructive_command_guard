//! Regression tests for issue #498: a match that policy lets run (warn, log,
//! or ask) hid every later finding on the same line.
//!
//! The evaluator stops at its first match and leaves policy to the caller, so
//! `git stash drop && git reset --hard` resolved to the warn of
//! `core.git:stash-drop` and the `reset-hard` deny behind it was never looked
//! at. Any rule a user downgraded to warn became a prefix that disarmed the
//! rules evaluated after it. These tests pin the strictest-finding-wins
//! answer through the bare Claude hook, the `dcg hook --batch` subcommand,
//! and `dcg test`, plus the planted negatives that keep the warn a warn when
//! nothing stricter is present.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn dcg_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_dcg"))
}

struct Lab {
    dir: tempfile::TempDir,
    config_path: PathBuf,
}

impl Lab {
    fn new(config_toml: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(dir.path().join("home")).unwrap();
        std::fs::create_dir_all(dir.path().join("xdg")).unwrap();
        let config_path = dir.path().join("policy.toml");
        std::fs::write(&config_path, config_toml).unwrap();
        Self { dir, config_path }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(dcg_binary());
        cmd.args(args)
            .env_clear()
            .env("HOME", self.dir.path().join("home"))
            .env("USERPROFILE", self.dir.path().join("home"))
            .env("XDG_CONFIG_HOME", self.dir.path().join("xdg"))
            .env("DCG_ALLOWLIST_SYSTEM_PATH", "")
            .env("DCG_CONFIG", &self.config_path)
            .env("DCG_HOOK_TIMEOUT_MS", "5000")
            .current_dir(self.dir.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        cmd
    }

    fn run_with_stdin(&self, args: &[&str], stdin_text: &str) -> (String, String) {
        let mut child = self
            .command(args)
            .stdin(Stdio::piped())
            .spawn()
            .expect("spawn dcg");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(stdin_text.as_bytes())
            .unwrap();
        let output = child.wait_with_output().expect("wait dcg");
        (
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        )
    }

    /// The bare Claude Code `PreToolUse` hook, exactly as the report drove it.
    fn claude_hook_denies(&self, shell_command: &str) -> bool {
        let payload = serde_json::json!({
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": { "command": shell_command },
            "cwd": self.dir.path(),
        });
        let (stdout, _) = self.run_with_stdin(&[], &format!("{payload}\n"));
        stdout.contains("\"deny\"")
    }

    /// The `dcg hook --batch` JSONL decision.
    fn batch_decision(&self, shell_command: &str) -> (String, String) {
        let payload = serde_json::json!({
            "tool_name": "Bash",
            "tool_input": { "command": shell_command },
            "cwd": self.dir.path(),
        });
        let (stdout, stderr) = self.run_with_stdin(&["hook", "--batch"], &format!("{payload}\n"));
        let line = stdout
            .lines()
            .find(|line| !line.trim().is_empty())
            .unwrap_or_else(|| panic!("no batch output\nstderr:\n{stderr}"));
        let json: serde_json::Value = serde_json::from_str(line).expect("batch JSON");
        (
            json["decision"].as_str().unwrap_or("<missing>").to_string(),
            json["rule_id"].as_str().unwrap_or("<none>").to_string(),
        )
    }

    /// The `Result:` line of `dcg test`.
    fn test_result_line(&self, shell_command: &str) -> String {
        let output = self
            .command(&["test", shell_command])
            .stdin(Stdio::null())
            .output()
            .expect("run dcg test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        stdout
            .lines()
            .chain(stderr.lines())
            .find(|line| line.trim_start().starts_with("Result:"))
            .map(|line| line.trim().to_string())
            .unwrap_or_else(|| panic!("no Result line\nstdout:\n{stdout}\nstderr:\n{stderr}"))
    }
}

const DEFAULTS: &str = "[general]\ncolor = \"never\"\n";

/// A warn-severity first finding followed by a deny, in every separator and
/// wrapper shape an agent could chain them with.
const MASKED_DENIES: &[&str] = &[
    "git stash drop && git reset --hard",
    "git stash drop; git reset --hard",
    "git stash drop || git reset --hard",
    "git stash drop | git reset --hard",
    "git stash drop\ngit reset --hard",
    "git stash drop & git reset --hard",
    "git stash drop && git clean -fd",
    "git stash drop stash@{0} && git reset --hard HEAD~3",
    "git stash drop && git reset --hard && git stash drop",
    "(git stash drop; git reset --hard)",
    "{ git stash drop; git reset --hard; }",
    "sh -c 'git stash drop && git reset --hard'",
    "bash -c \"git stash drop; git reset --hard\"",
    "GIT_DIR=.git git stash drop && GIT_DIR=.git git reset --hard",
    "/usr/bin/git stash drop && /usr/bin/git reset --hard",
    "git -C . stash drop && git -C . reset --hard",
    "git stash drop && sudo git reset --hard",
    "git stash drop && env git reset --hard",
    "git stash drop && git push --force origin main",
    "git stash drop && git branch -D feature",
    "git stash drop 2>/dev/null && git reset --hard",
    "git stash drop >/dev/null; git reset --hard",
    "time git stash drop; git reset --hard",
    "nohup git stash drop; git reset --hard",
    "eval 'git stash drop; git reset --hard'",
    "bash <<'EOF'\ngit stash drop\ngit reset --hard\nEOF",
    "GIT_STASH=1 git stash drop; FOO=bar git reset --hard",
    "git stash drop; git stash drop; git reset --hard",
    "git stash clear; git stash drop; git reset --hard",
];

#[test]
fn warn_first_match_no_longer_hides_a_later_deny() {
    let lab = Lab::new(DEFAULTS);
    for command in MASKED_DENIES {
        assert!(
            lab.claude_hook_denies(command),
            "Claude hook must deny {command:?}: the warn of its first half must not hide the rest"
        );
    }
}

#[test]
fn batch_hook_and_dcg_test_agree_on_the_deny() {
    let lab = Lab::new(DEFAULTS);
    let (decision, rule) = lab.batch_decision("git stash drop && git reset --hard");
    assert_eq!(decision, "deny", "dcg hook --batch");
    assert_eq!(
        rule, "core.git:reset-hard",
        "the deny names the rule that denies"
    );
    let line = lab.test_result_line("git stash drop && git reset --hard");
    assert!(line.contains("BLOCKED"), "dcg test: {line}");
}

#[test]
fn warn_stays_warn_when_nothing_stricter_follows() {
    // Planted negatives: the escalation must not turn a lone warn, or two
    // warns, into a deny.
    let lab = Lab::new(DEFAULTS);
    for command in [
        "git stash drop",
        "git stash drop && git status",
        "git stash drop; git stash drop",
        "git status && git stash drop",
    ] {
        assert!(
            !lab.claude_hook_denies(command),
            "Claude hook must not deny {command:?}"
        );
        let (decision, rule) = lab.batch_decision(command);
        assert_eq!(decision, "allow", "{command:?}");
        assert_eq!(
            rule, "core.git:stash-drop",
            "{command:?} keeps its warn rule"
        );
    }
    // Looking past the warn must not turn inert text behind it into a finding.
    for command in [
        "git stash drop && echo 'git reset --hard'",
        "git stash drop && git commit -m 'undo git reset --hard'",
        "git stash drop && grep -r 'rm -rf' docs/",
        "git stash drop && git log --grep='reset --hard'",
    ] {
        assert!(
            !lab.claude_hook_denies(command),
            "{command:?}: data behind a warn is not a command"
        );
    }
    for command in ["git status", "ls -la && git log --oneline", "cargo test"] {
        assert!(!lab.claude_hook_denies(command), "{command:?}");
    }
}

#[test]
fn user_downgraded_rule_no_longer_disarms_later_rules() {
    // The report's second form: a rule the user set to warn.
    let lab = Lab::new(
        "[general]\ncolor = \"never\"\n\n[policy.rules]\n\"core.git:branch-force-delete\" = \"warn\"\n",
    );
    assert!(!lab.claude_hook_denies("git branch -D x"));
    assert!(lab.claude_hook_denies("git branch -D x && git reset --hard"));
    assert!(lab.claude_hook_denies("git branch -D x; rm -rf ~/Developer"));
}

#[test]
fn log_and_ask_first_matches_do_not_hide_a_deny_either() {
    let lab = Lab::new(
        "[general]\ncolor = \"never\"\n\n[policy.rules]\n\"core.git:branch-force-delete\" = \"log\"\n\"core.git:stash-drop\" = \"ask\"\n",
    );
    assert!(!lab.claude_hook_denies("git branch -D x"));
    assert!(lab.claude_hook_denies("git branch -D x && git reset --hard"));
    let (decision, rule) = lab.batch_decision("git stash drop && git reset --hard");
    assert_eq!(decision, "deny");
    assert_eq!(rule, "core.git:reset-hard");
}

#[test]
fn a_whole_pack_downgraded_to_warn_still_lets_other_packs_deny() {
    // Downgrading core.git as a pack must not disarm core.filesystem behind
    // it. (A pack-level warn never relaxes a critical rule, so `reset-hard`
    // itself stays a deny either way.)
    let lab = Lab::new("[general]\ncolor = \"never\"\n\n[policy.packs]\n\"core.git\" = \"warn\"\n");
    assert!(!lab.claude_hook_denies("git stash drop"));
    assert!(lab.claude_hook_denies("git stash drop && git reset --hard"));
    assert!(lab.claude_hook_denies("git stash drop && rm -rf ~/Developer"));
    assert!(lab.claude_hook_denies("git stash drop; rm -rf /"));
}

/// Found in review of the #498 fix: the look-past grants the warn rule, and
/// three nested evaluations (a resolved `$d` invocation, the `$IFS`
/// expansion, an alias body) returned an allowlisted nested result as the
/// answer for the whole line. So with the default config
/// `alias x='git stash drop'; rm -rf /` and `d=git; $d stash drop;
/// git reset --hard` were still allowed — and so was any such line whose
/// nested rule the user had allowlisted.
#[test]
fn a_warn_inside_a_nested_piece_does_not_hide_a_later_deny() {
    let lab = Lab::new(DEFAULTS);
    for command in [
        "alias x=\"git stash drop\"; git reset --hard",
        "alias x=\"git stash drop\"; rm -rf /",
        "alias x='git stash drop'\nrm -rf ~/",
        "alias x=\"git stash drop\"; alias y=\"git reset --hard\"",
        "d=git; $d stash drop; git reset --hard",
        "d=git; $d stash drop; rm -rf /",
        "git${IFS}stash${IFS}drop; git reset --hard",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    for command in ["alias x=\"git stash drop\"", "d=git; $d stash drop"] {
        assert!(!lab.claude_hook_denies(command), "{command:?} stays a warn");
    }
}

#[test]
fn an_allowlisted_rule_in_a_nested_piece_covers_only_that_rule() {
    let lab = Lab::new(DEFAULTS);
    let allowlist = "[[allow]]\nrule = \"core.filesystem:rm-rf-general\"\nreason = \"test\"\n";
    for dir in ["xdg/dcg", "home/.config/dcg"] {
        let dir = lab.dir.path().join(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("allowlist.toml"), allowlist).unwrap();
    }
    assert!(!lab.claude_hook_denies("alias x=\"rm -rf ./build\""));
    assert!(!lab.claude_hook_denies("rm -rf ./build"));
    for command in [
        "alias x=\"rm -rf ./build\"; git reset --hard",
        "d=rm; $d -rf ./build; git reset --hard",
        "rm -rf ./build; git reset --hard",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
}

/// With confidence scoring on, the first occurrence of a rule can be in doubt
/// (`watch …`, a function body) and downgrade to warn, while the same rule
/// fires again directly later on the line. The evaluator reports only the
/// first occurrence, and the look-past grants the rule for the whole line, so
/// the direct repeat was never judged.
#[test]
fn a_confidence_downgrade_does_not_hide_a_confident_repeat_of_the_rule() {
    let lab = Lab::new(
        "[general]\ncolor = \"never\"\n\n[confidence]\nenabled = true\nwarn_threshold = 0.7\n",
    );
    for command in ["watch rm -rf ./build", "f() { git branch -D main; }"] {
        assert!(
            !lab.claude_hook_denies(command),
            "premise: {command:?} is downgraded on its own"
        );
    }
    for command in [
        "watch rm -rf ./build; rm -rf ./build",
        "f() { rm -rf ./build; }; rm -rf ./build",
        "f() { git branch -D main; }; git branch -D main",
        "case a in a) git branch -D main;; esac; git branch -D main",
    ] {
        assert!(lab.claude_hook_denies(command), "{command:?}");
    }
    // Two doubtful occurrences stay doubtful.
    assert!(!lab.claude_hook_denies("watch rm -rf ./build; f() { rm -rf ./build; }"));
}
