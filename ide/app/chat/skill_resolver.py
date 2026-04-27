"""Skill resolver — loads SkillEntry from DB and converts to ResolvedSkill.

Used by ChatPage to wire skill selection into the agent run config.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from app.chat.models import ResolvedSkill

if TYPE_CHECKING:
    from shared.database import DatabaseStore

logger = logging.getLogger(__name__)


class SkillResolver:
    """Resolve persisted SkillEntry rows into runtime ResolvedSkill objects."""

    def __init__(self, db: DatabaseStore) -> None:
        self._db = db

    def resolve(self, skill_id: int) -> ResolvedSkill | None:
        """Load a single skill by id and return a ResolvedSkill.

        Returns None if the skill doesn't exist or isn't enabled.
        """
        from supervisor.models import SkillEntry

        rows = self._db.load_rows("skills")
        for row in rows:
            if row.get("id") == skill_id and row.get("enabled"):
                return self._to_resolved(SkillEntry.from_dict(row))
        return None

    def list_available(self) -> list[dict]:
        """Return all enabled skills as lightweight dicts for the selector UI.

        Each dict contains: id, name, description.
        """
        rows = self._db.load_rows("skills")
        result: list[dict] = []
        for row in rows:
            if row.get("enabled"):
                result.append({
                    "id": row["id"],
                    "name": row.get("name", ""),
                    "description": row.get("description", ""),
                })
        return result

    @staticmethod
    def _to_resolved(entry: "SkillEntry") -> ResolvedSkill:
        """Convert a SkillEntry into a runtime ResolvedSkill."""
        allowlist: set[str] | None = None
        denylist: set[str] | None = None

        if entry.tool_allowlist_json:
            try:
                allowlist = set(json.loads(entry.tool_allowlist_json))
            except (json.JSONDecodeError, TypeError):
                logger.warning("Invalid tool_allowlist_json for skill %s", entry.name)

        if entry.tool_denylist_json:
            try:
                denylist = set(json.loads(entry.tool_denylist_json))
            except (json.JSONDecodeError, TypeError):
                logger.warning("Invalid tool_denylist_json for skill %s", entry.name)

        return ResolvedSkill(
            id=entry.id,
            name=entry.name,
            system_prompt_suffix=entry.system_prompt_template,
            tool_allowlist=allowlist,
            tool_denylist=denylist,
            preferred_model_name=entry.model_override or None,
            temperature_override=entry.temperature_override,
        )
