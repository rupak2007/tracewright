"""Hand-written verification playbooks (K-PB-DET-*) addressed by key, never by similarity search."""

from pathlib import Path

from app.core.errors import ConfigError

PLAYBOOK_TYPES = ("SCAN", "BRUTE", "DNSTUN", "BEACON", "EXFIL")


def playbook_id(finding_type: str) -> str:
    return f"K-PB-DET-{finding_type}"


def load_playbooks(knowledge_dir: Path) -> dict[str, str]:
    """`knowledge/playbooks/DET-<TYPE>.md` for every detector; a missing one is a config error."""
    out: dict[str, str] = {}
    for kind in PLAYBOOK_TYPES:
        path = knowledge_dir / "playbooks" / f"DET-{kind}.md"
        try:
            out[playbook_id(kind)] = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"missing verification playbook {path}: {exc}") from exc
    return out
