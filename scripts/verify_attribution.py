#!/usr/bin/env python3
"""Check publication metadata without scanning source or third-party notices."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

AUTHOR_NAME = "Nick Seal"
AUTHOR_EMAIL = "32712898+blisspixel@users.noreply.github.com"
TOOLS = r"(?:codex|claude(?:\s+code)?|chatgpt|openai|anthropic|copilot|gemini|cursor|ai|assistant|agent|tool)"
BRANDS = re.compile(r"(?i)\b(?:codex|claude|chatgpt|openai|anthropic|copilot|gemini)\b")
CREDITS = (
    re.compile(r"(?im)^\s*(?:co[- ]?authored|assisted|generated|written|created|reviewed)[- ]by\s*:"),
    re.compile(r"(?i)\b(?:generated|authored|written|created|co[- ]?authored|assisted)\s+(?:by|with)\b"),
    re.compile(r"(?i)\b(?:by|with|thanks\s+to|credit(?:s)?\s+to)\s+(?:\[)?" + TOOLS + r"\b"),
    re.compile(r"(?i)\b" + TOOLS + r"[- ](?:generated|authored|written|assisted)\b"),
)
EMOJI = re.compile("[\U0001f000-\U0001faff\u2600-\u27bf\ufe0f\u20e3\u200d]")


class Violation(ValueError):
    pass


def check_identity(name: str, email: str, label: str) -> None:
    if name != AUTHOR_NAME or email != AUTHOR_EMAIL:
        raise Violation(f"{label}: author must be {AUTHOR_NAME} <{AUTHOR_EMAIL}>")


def check_text(value: str, label: str) -> None:
    if not isinstance(value, str):
        raise Violation(f"{label}: metadata must be text")
    if "\u2014" in value:
        raise Violation(f"{label}: em dashes are not permitted")
    if EMOJI.search(value):
        raise Violation(f"{label}: emojis are not permitted")
    if BRANDS.search(value) or any(pattern.search(value) for pattern in CREDITS):
        raise Violation(f"{label}: assistant, tool, or coauthor credit is not permitted")


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, timeout=30,
        encoding="utf-8", errors="strict", check=False,
    )
    if result.returncode:
        raise Violation("Git metadata could not be read")
    if len(result.stdout) > 16 * 1024 * 1024:
        raise Violation("Git metadata exceeds the inspection bound")
    return result.stdout


def check_event(event: object) -> str | None:
    if not isinstance(event, dict):
        raise Violation("GitHub event must be an object")
    if "pull_request" in event:
        pr = event["pull_request"]
        if not isinstance(pr, dict) or not isinstance(pr.get("head"), dict):
            raise Violation("pull request metadata is incomplete")
        check_text(pr.get("title"), "pull request title")
        check_text("" if pr.get("body") is None else pr["body"], "pull request body")
        revision = pr["head"].get("sha")
    elif "release" in event:
        release = event["release"]
        if not isinstance(release, dict):
            raise Violation("release metadata is incomplete")
        check_text("" if release.get("name") is None else release["name"], "release title")
        check_text("" if release.get("body") is None else release["body"], "release notes")
        revision = event.get("after")
    else:
        revision = event.get("after")
    if revision is not None and not re.fullmatch(r"[0-9a-f]{40}", str(revision)):
        raise Violation("event commit must be a full Git object id")
    return revision


def check_notes(root: Path, staged: bool = False) -> None:
    if staged:
        paths = git(root, "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z", "--", "docs/releases").split("\0")
        for path in filter(None, paths):
            if path.endswith(".md"):
                check_text(git(root, "show", f":{path}"), f"staged release notes {path}")
    else:
        for path in sorted((root / "docs/releases").glob("*.md")):
            check_text(path.read_text(encoding="utf-8"), f"release notes {path.name}")


def check_pending(root: Path, message: Path) -> None:
    identity = git(root, "var", "GIT_AUTHOR_IDENT").strip()
    match = re.fullmatch(r"(.+) <([^<>]+)> \d+ [+-]\d{4}", identity)
    if not match:
        raise Violation("pending author identity is malformed")
    check_identity(match[1], match[2], "pending commit")
    check_text(message.read_text(encoding="utf-8"), "pending commit message")
    check_notes(root, staged=True)


def check_repository(root: Path, revision: str = "HEAD") -> None:
    commits = git(root, "rev-list", "--max-count=10001", revision, "--tags", "--").splitlines()
    if not commits or len(commits) > 10000:
        raise Violation("commit history is empty or exceeds 10000 commits")
    for commit in commits:
        fields = git(root, "show", "-s", "--format=%an%x00%ae%x00%B", commit, "--").split("\0", 2)
        if len(fields) != 3:
            raise Violation("commit metadata is malformed")
        check_identity(fields[0], fields[1], f"commit {commit[:12]}")
        check_text(fields[2], f"commit {commit[:12]}")
    for ref in git(root, "for-each-ref", "--format=%(refname)", "refs/tags").splitlines():
        kind = git(root, "cat-file", "-t", ref).strip()
        if kind == "tag":
            fields = git(root, "for-each-ref", "--format=%(taggername)%00%(taggeremail)%00%(contents)", ref).split("\0", 2)
            if len(fields) != 3:
                raise Violation("tag metadata is malformed")
            check_identity(fields[0], fields[1].strip("<>"), f"tag {ref}")
            check_text(fields[2], f"tag {ref}")
    check_notes(root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--ci", action="store_true", help="check Git history, tags, release notes, and the GitHub event")
    parser.add_argument("--commit-msg", type=Path, help="check a pending Git commit and staged release notes")
    parser.add_argument("--text-file", type=Path, help="check a prepared PR, release, or tag text file")
    parser.add_argument("--event-file", type=Path, default=os.environ.get("GITHUB_EVENT_PATH"))
    args = parser.parse_args(argv)
    try:
        if args.commit_msg:
            check_pending(args.repo, args.commit_msg)
        elif args.text_file:
            check_text(args.text_file.read_text(encoding="utf-8"), "prepared publication metadata")
        else:
            revision = None
            if args.event_file:
                revision = check_event(json.loads(Path(args.event_file).read_text(encoding="utf-8")))
            check_repository(args.repo, revision or "HEAD")
    except (Violation, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f"attribution check failed: {error}", file=sys.stderr)
        return 1
    print("attribution metadata verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
