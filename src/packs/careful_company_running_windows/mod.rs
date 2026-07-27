//! `careful_company_running_windows` — a preset for organizations that run AI
//! coding agents on Windows workstations with tool-permission prompts turned off.
//!
//! Every other pack in dcg answers "will this command destroy something?".
//! This preset also answers a second question that matters once an agent runs
//! unattended in a regulated or IP-sensitive environment: **"is this command
//! sending our data somewhere, or switching off the controls that watch it?"**
//! Nothing else in dcg covers that — before this pack there was no rule anywhere
//! in the tree matching `Send-MailMessage`, `hooks.slack.com`, `curl -T`, or
//! `Invoke-RestMethod -InFile`.
//!
//! ## What is in scope
//!
//! Six sub-packs, each a separate switch so a team can drop one dimension
//! without losing the rest:
//!
//! | Sub-pack | Channel it closes |
//! |----------|-------------------|
//! | [`email`] | Sending mail from the workstation (cmdlet, .NET, Outlook COM, SMTP CLI, mail APIs) |
//! | [`chat`] | Chat and webhook posts (Slack, Teams, Discord, Telegram, SMS, request catchers) |
//! | [`upload`] | HTTP uploads: file-attachment primitives, file-drop/paste services, gists, clipboard |
//! | [`transfer`] | File-transfer and cloud-storage egress (scp/sftp/ftp, rclone, S3/Blob/GCS uploads) |
//! | [`tunnel`] | Tunnels, reverse forwards, raw sockets, and DNS channels that expose data outward |
//! | [`guardrails`] | Turning off the safety net: AV/firewall/EDR, audit logs, and dcg itself |
//!
//! ## One line enables the whole posture
//!
//! ```toml
//! [packs]
//! enabled = ["careful_company_running_windows"]
//! ```
//!
//! That turns on the six sub-packs *and* the existing destruction coverage the
//! same posture needs: the `windows.*`, `database.*` (including Snowflake),
//! `storage.*`, `remote.*`, `backup.*`, `secrets.*`, and `cloud.*` packs. This
//! pack does not re-implement those rules — it pulls them in, via the pinned
//! `CAREFUL_COMPANY_PRESET_MEMBERS` list in [`crate::packs`]. Membership is
//! explicit rather than prefix-based, so a future `database.*` pack has to be
//! added deliberately; and any member can be dropped individually with
//! `disabled = ["remote.rsync"]`.
//!
//! ## What is deliberately NOT in scope
//!
//! This is **not** an EDR. It matches command lines an agent asks a shell to
//! run; it cannot see what a program does after it starts, and a determined
//! human can still open a second terminal. Nor does it cover container,
//! Kubernetes, or CI/CD tooling — those are a different posture, and a preset
//! that quietly enabled everything would be indistinguishable from `enabled =
//! ["*"]`.
//!
//! ## False positives are the product risk, so:
//!
//! 1. **Positive evidence of egress is required.** A rule fires on the thing
//!    that carries data out — an attached file, a mutating method, a known
//!    egress host — never on merely touching the network. Plain `GET`s,
//!    downloads (`-OutFile`, `curl -o`), and every package-manager install
//!    (`npm install`, `pip install`, `cargo build`, `winget install`, …) pass
//!    through untouched because they cannot match an upload rule.
//! 2. **Ambiguity warns instead of blocking.** A `POST` with an inline body to
//!    an unknown host is a GraphQL query as often as it is an exfiltration, so
//!    those rules are `Medium` (warn + audit, execution continues). Only
//!    unambiguous egress blocks. Promote them with a `[policy]` entry if your
//!    posture calls for it.
//! 3. **Internal destinations are allowed.** Loopback, RFC1918, `host.docker.internal`,
//!    and `*.internal`/`*.corp`/`*.local`/`*.lan`/`*.intranet` hosts are development
//!    traffic. The cloud metadata endpoints (`169.254.169.254`,
//!    `metadata.google.internal`) are explicitly excluded from that allowance —
//!    they are a credential-theft target, not a private host.
//! 4. **Tokens in data position are not execution.** `Select-String "Send-MailMessage" *.ps1`
//!    and `rg "hooks.slack.com" src/` are searches, and `dcg explain "<command>"`
//!    is dcg inspecting itself. Both are whitelisted in every sub-pack by
//!    [`shared_safe_patterns`].
//! 5. **`git push` to a named remote is untouched**, and SMB/UNC copies to a
//!    corporate file share are out of scope — those are inside the perimeter.
//!
//! First-party internal tooling that legitimately uploads is handled by
//! allowlisting it, not by loosening a rule:
//!
//! ```bash
//! dcg allowlist add-command "mytool publish --to https://artifacts.corp.internal" \
//!   -r "First-party internal publisher" --user
//! ```
//!
//! ## Conventions
//!
//! Patterns follow the Windows-pack conventions (see [`crate::packs::windows`]):
//! every regex carries an inline `(?i)` because Windows commands and PowerShell
//! cmdlets are case-insensitive, and the pack keyword arrays enumerate realistic
//! casings because the keyword quick-reject is a case-sensitive substring match.
//! Safe patterns are anchored at the command word and confined to a single
//! `[^|&;<>\r\n]*` segment so a benign first command can never shield a
//! destructive later one.
//!
//! The preset is **opt-in on every platform**, including Windows. It encodes a
//! policy choice about what an agent may communicate, not a universal
//! "this will destroy your data" judgement, so it is never enabled by default.

pub mod chat;
pub mod email;
pub mod guardrails;
pub mod transfer;
pub mod tunnel;
pub mod upload;

use crate::packs::SafePattern;
use crate::safe_pattern;

/// Safe patterns shared by every sub-pack in this preset.
///
/// Both entries exist to keep the preset usable rather than to make it
/// permissive, and both are anchored at the command word and to a single
/// command segment:
///
/// - `read-only-data-context`: the egress token is an *argument* to a search,
///   read, help, or editor command (`Select-String "Send-MailMessage" *.ps1`,
///   `rg "hooks.slack.com" src/`, `git log --grep=webhook`, `code .\mailer.ts`,
///   `Get-Help Send-MailMessage`). Searching for a string, or reading its
///   documentation, is not sending one.
/// - `dcg-self-inspection`: `dcg explain "<blocked command>"` and friends embed
///   the very command being investigated. Without this, asking dcg why
///   something is blocked would itself be blocked. Only **read-only**
///   subcommands are listed — `dcg allowlist add`, `dcg allow`, and
///   `dcg allow-once` grant permission, so whitelisting them here would hand
///   an agent the ability to clear its own path one command in advance.
///
/// Each sub-pack extends this list with its own domain-specific allowances.
#[must_use]
pub fn shared_safe_patterns() -> Vec<SafePattern> {
    vec![
        // `code` is excluded when followed by `tunnel`/`serve-web`: those are
        // not editor invocations, they are remote-access channels owned by
        // `tunnel:devtunnel-or-code-tunnel`.
        safe_pattern!(
            "read-only-data-context",
            r"(?i)^\s*(?:sudo\s+)?(?:select-string|sls|findstr|rg|ripgrep|grep|egrep|fgrep|ack|ag|get-content|gc|cat|type|more|head|tail|bat|code(?!\s+(?:tunnel|serve-web|serve)\b)|notepad|notepad\+\+|vim|nvim|nano|less|get-help|help|man|get-command|gcm|git\s+(?:log|grep|show|diff|blame|config|status))\b[^|&;<>\r\n]*$"
        ),
        // Read-only subcommands only. `dcg allowlist add`, `dcg allow`, and
        // `dcg allow-once` are deliberately absent: those grant permission, and
        // whitelisting them would let an agent clear its own path. They are
        // blocked by `guardrails:dcg-policy-self-weakening`.
        safe_pattern!(
            "dcg-self-inspection",
            r"(?i)^\s*(?:[a-z]:[\\/][^\s|&;<>]*[\\/])?dcg(?:\.exe)?\s+(?:test|explain|scan|simulate|corpus|packs|doctor|history|stats|suggest-allowlist|allowlist\s+(?:list|validate))\b[^|&;<>\r\n]*$"
        ),
    ]
}
