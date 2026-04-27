"""Lightweight dict-based i18n for the IDE MVP."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


SUPPORTED_LANGUAGES = ("en", "zh")


def normalize_language(language: str | None) -> str:
    if not language:
        return "en"
    value = language.strip().lower()
    return value if value in SUPPORTED_LANGUAGES else "en"


_I18N_DIR = Path(__file__).resolve().parent.parent / "resources" / "i18n"


def _load_translations() -> dict[str, dict[str, str]]:
    """Load all translation files from the i18n resource directory."""
    translations: dict[str, dict[str, str]] = {}
    if not _I18N_DIR.is_dir():
        return translations
    for path in _I18N_DIR.glob("*.json"):
        lang = path.stem
        if lang in SUPPORTED_LANGUAGES:
            translations[lang] = json.loads(path.read_text(encoding="utf-8"))
    return translations


_TRANSLATIONS: dict[str, dict[str, str]] = _load_translations()


@dataclass(slots=True)
class I18n:
    language: str

    def __post_init__(self) -> None:
        self.language = normalize_language(self.language)

    def set_language(self, language: str | None) -> None:
        self.language = normalize_language(language)

    def t(self, key: str, **kwargs: object) -> str:
        text = _TRANSLATIONS.get(self.language, {}).get(
            key, _TRANSLATIONS["en"].get(key, key)
        )
        if kwargs:
            return text.format(**kwargs)
        return text
