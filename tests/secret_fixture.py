"""A small project with fake credentials, written at test time.

The tokens are assembled from pieces here, so this file does not itself look
like a leak to a secret scanner or to a code host's push protection. None of
the values is a real credential.
"""
from __future__ import annotations

from pathlib import Path

_ALNUM = "Zq3Xv9Lm2Pw8Rt5Ky7Hn4Bc6Df1Gs0Jj"


def _repeat(text: str, length: int) -> str:
    return (text * (length // len(text) + 1))[:length]


def fake_tokens() -> dict[str, str]:
    return {
        "github": "gh" + "p_" + _repeat(_ALNUM, 36),
        "aws_id": "AK" + "IA" + "Q4ZT" + "EST7X3M9KL2W",
        "aws_secret": _repeat("wJal" + "rXUtnFEMI/K7MDENG/bPxRfiCY" + "zq9Lm2", 40),
        "slack": "xo" + "xb-" + "1234567890123-1234567890123-" + _repeat(_ALNUM, 24),
        "stripe": "sk" + "_live_" + _repeat(_ALNUM, 24),
    }


def secret_project(root: Path) -> Path:
    tokens = fake_tokens()
    root.mkdir(parents=True, exist_ok=True)
    (root / "config.py").write_text(
        "# Fake credentials for scanner tests. None of them is real.\n"
        f'GITHUB_TOKEN = "{tokens["github"]}"\n'
        f'STRIPE_KEY = "{tokens["stripe"]}"\n',
        encoding="utf-8",
    )
    (root / "deploy.env").write_text(
        f"AWS_ACCESS_KEY_ID={tokens['aws_id']}\n"
        f"AWS_SECRET_ACCESS_KEY={tokens['aws_secret']}\n"
        f"SLACK_BOT_TOKEN={tokens['slack']}\n",
        encoding="utf-8",
    )
    (root / "README.md").write_text("Nothing secret here.\n", encoding="utf-8")
    return root
