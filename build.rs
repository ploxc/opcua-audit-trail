//! Puts the git commit in the version (`0.1.0 (8568bbc)`, `-dirty` with
//! uncommitted changes), so the UI, the API and the `gateway_started`
//! record show which build runs, not only which release.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=GATEWAY_COMMIT");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    println!("cargo:rerun-if-changed=src");
    let version = env!("CARGO_PKG_VERSION");
    // Set by a build without .git (e.g. a container build); else from git.
    let commit = std::env::var("GATEWAY_COMMIT")
        .ok()
        .filter(|c| !c.trim().is_empty())
        .or_else(git_commit);
    let full = match commit {
        Some(c) => format!("{version} ({})", c.trim()),
        None => version.to_string(),
    };
    println!("cargo:rustc-env=GATEWAY_VERSION={full}");
}

/// The short commit of HEAD, with `-dirty` when tracked files changed.
fn git_commit() -> Option<String> {
    let git = |args: &[&str]| {
        let out = Command::new("git").args(args).output().ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let commit = git(&["rev-parse", "--short=7", "HEAD"])?;
    let dirty =
        git(&["status", "--porcelain", "--untracked-files=no"]).is_some_and(|s| !s.is_empty());
    Some(if dirty {
        format!("{commit}-dirty")
    } else {
        commit
    })
}
