#!/usr/bin/env python3
"""Generate the six test fixture repositories under tests/fixtures/.

The fixtures are generated, never committed: tests/fixtures/ is in
.gitignore, and this script is the only source of truth for their
content. Planted secrets are dummy values (AWS documentation example
keys and random base64 blobs), safe to write to disk locally.

Layout:
    leaky_aws_config    AWS access key in config.ini; removed from the
                        working tree in a later commit (history-only).
    leaky_private_key   OPENSSH private key block committed and still
                        present in the working tree (history + tree).
    leaky_env_file      .env with API key and password committed, then
                        removed (history-only).
    clean_docs          plain documentation repository.
    clean_high_entropy  lockfile hashes and base64 image data that
                        naive entropy scanners flag.
    clean_placeholders  documented example keys that must not alert.

Usage: python3 tests/make_fixtures.py [--force]
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures")

# Deterministic but secret-looking dummy values. Derived from a fixed
# seed so repeated runs reproduce the same fixtures (and therefore the
# same fingerprints).
RNG = random.Random(20240917)


def dummy_aws_key() -> str:
    """A syntactically valid AWS access key id that is not real."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    body = "".join(RNG.choice(alphabet) for _ in range(16))
    return "AKIA" + body


def dummy_secret(len_chars: int = 40) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(RNG.choice(alphabet) for _ in range(len_chars))


def dummy_openssh_block() -> tuple:
    """A fake OPENSSH PRIVATE KEY block. Content is random noise.

    Returns (block, body_line) where body_line is one distinctive
    base64 body line used by the redaction test to prove the key
    material never appears in scanner output.
    """
    payload = bytes(RNG.randrange(256) for _ in range(96))
    b64 = base64.b64encode(payload).decode("ascii")
    lines = [b64[i : i + 70] for i in range(0, len(b64), 70)]
    begin = "-----BEGIN " + "OPENSSH PRIVATE KEY" + "-----"
    end = "-----END " + "OPENSSH PRIVATE KEY" + "-----"
    return "\n".join([begin] + lines + [end]) + "\n", lines[1]


def tiny_png_b64() -> str:
    """A real 4x4 PNG, base64 encoded, as high-entropy non-secret data."""

    def chunk(tag: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data))
        )

    ihdr = struct.pack(">IIBBBBB", 4, 4, 8, 2, 0, 0, 0)
    raw = b"".join(b"\x00" + bytes((x * 37) % 256 for x in range(12)) for _ in range(4))
    png = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
    return base64.b64encode(png).decode("ascii")


def git(repo: str, *args: str) -> None:
    proc = subprocess.run(
        ["git", "-C", repo, *args], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {args} failed: {proc.stderr.strip()}")


def init_repo(name: str) -> str:
    path = os.path.join(FIXTURES, name)
    if os.path.exists(path):
        shutil.rmtree(path)
    os.makedirs(path)
    git(path, "init", "-q", "-b", "main")
    git(path, "config", "user.email", "fixture@repo-guardian.test")
    git(path, "config", "user.name", "Fixture Generator")
    return path


def commit_all(repo: str, message: str) -> str:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)
    out = subprocess.run(
        ["git", "-C", repo, "rev-parse", "HEAD"], capture_output=True, text=True
    )
    return out.stdout.strip()


def write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)


def make_leaky_aws_config() -> dict:
    repo = init_repo("leaky_aws_config")
    key = dummy_aws_key()
    secret = dummy_secret(40)
    write(
        os.path.join(repo, "config.ini"),
        "[aws]\n"
        "aws_access_key_id = "
        + key
        + "\n"
        "aws_secret_access_key = "
        + secret
        + "\n",
    )
    write(os.path.join(repo, "README.md"), "# Service\n\nConfig lives in config.ini.\n")
    commit_all(repo, "add service config")
    # Remove the secret from the working tree; it stays in history.
    os.remove(os.path.join(repo, "config.ini"))
    write(os.path.join(repo, "config.ini"), "[aws]\nregion = us-east-1\n")
    commit_all(repo, "move credentials out of the repo")
    return {"repo": repo, "planted": [key, secret], "expect_rules": ["aws-access-token"]}


def make_leaky_private_key() -> dict:
    repo = init_repo("leaky_private_key")
    block, body_line = dummy_openssh_block()
    write(os.path.join(repo, "deploy", "id_ed25519"), block)
    write(os.path.join(repo, "README.md"), "# Deploy\n\nUses deploy/id_ed25519.\n")
    commit_all(repo, "add deploy tooling")
    # Key file is still present in the working tree.
    return {"repo": repo, "planted": [body_line], "expect_rules": ["private-key"]}


def make_leaky_env_file() -> dict:
    repo = init_repo("leaky_env_file")
    token = dummy_secret(32)
    password = dummy_secret(18)
    write(
        os.path.join(repo, ".env"),
        "APP_ENV=production\n"
        "API_KEY=" + token + "\n"
        "DB_PASSWORD=" + password + "\n",
    )
    write(os.path.join(repo, "app.py"), "import os\n\nprint(os.environ.get('APP_ENV'))\n")
    commit_all(repo, "add environment configuration")
    os.remove(os.path.join(repo, ".env"))
    write(os.path.join(repo, ".env.example"), "APP_ENV=development\nAPI_KEY=\nDB_PASSWORD=\n")
    commit_all(repo, "stop tracking .env, ship an example instead")
    return {"repo": repo, "planted": [token, password], "expect_rules": ["generic-api-key"]}


def make_clean_docs() -> dict:
    repo = init_repo("clean_docs")
    write(
        os.path.join(repo, "README.md"),
        "# Docs\n\nA plain documentation repository with no credentials.\n",
    )
    write(os.path.join(repo, "docs", "guide.md"), "## Guide\n\n1. Read.\n2. Write.\n")
    commit_all(repo, "initial docs")
    return {"repo": repo, "planted": [], "expect_rules": []}


def make_clean_high_entropy() -> dict:
    repo = init_repo("clean_high_entropy")
    hashes = "\n".join(
        "  sha512-"
        + base64.b64encode(
            hashlib.sha512(f"package-{i}".encode()).digest()
        ).decode("ascii")
        for i in range(12)
    )
    write(
        os.path.join(repo, "package-lock.json"),
        '{\n  "lockfileVersion": 3,\n  "packages": {\n'
        + "".join(f'    "node_modules/pkg{i}": {{\n      "integrity": "'
                  + h.strip().replace("\n", "") + '"\n    }},\n'
                  for i, h in enumerate(hashes.splitlines()))
        + '    "": {}\n  }\n}\n',
    )
    write(
        os.path.join(repo, "assets", "icon.b64.txt"),
        "data:image/png;base64," + tiny_png_b64() + "\n",
    )
    write(os.path.join(repo, "README.md"), "# Assets\n\nLockfile and embedded image data.\n")
    commit_all(repo, "add lockfile and assets")
    return {"repo": repo, "planted": [], "expect_rules": []}


def make_clean_placeholders() -> dict:
    repo = init_repo("clean_placeholders")
    write(
        os.path.join(repo, "docs", "credentials.md"),
        "# Credentials\n\n"
        "Example configuration only. Replace every value before use.\n\n"
        "    aws_access_key_id = "
        + "AKIA"
        + "IOSFODNN7EXAMPLE\n"
        "    api_key = your-api-key-here\n"
        '    password = "changeme-placeholder"\n',
    )
    write(
        os.path.join(repo, "config", "sample.yaml"),
        "# Sample values, not real credentials.\n"
        "api:\n"
        "  key: your-api-key-here\n",
    )
    commit_all(repo, "add credential documentation")
    return {"repo": repo, "planted": [], "expect_rules": []}


MAKERS = (
    make_leaky_aws_config,
    make_leaky_private_key,
    make_leaky_env_file,
    make_clean_docs,
    make_clean_high_entropy,
    make_clean_placeholders,
)


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the six Repo Guardian test fixture repositories."
    )
    parser.add_argument(
        "--force", action="store_true", help="regenerate even if fixtures exist"
    )
    args = parser.parse_args(argv)

    if os.path.isdir(FIXTURES) and os.listdir(FIXTURES) and not args.force:
        print(f"fixtures already exist at {FIXTURES}; use --force to regenerate")
        return 0

    os.makedirs(FIXTURES, exist_ok=True)
    manifest = []
    for maker in MAKERS:
        info = maker()
        manifest.append(
            {
                "name": os.path.basename(info["repo"]),
                "expect_rules": info["expect_rules"],
                "planted_values": info["planted"],
            }
        )
        print(f"built {os.path.basename(info['repo'])}")

    # The manifest records which dummy values were planted so the
    # acceptance test can prove they never appear in scanner output.
    with open(os.path.join(FIXTURES, "manifest.json"), "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
