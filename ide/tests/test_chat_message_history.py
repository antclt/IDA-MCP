from __future__ import annotations

from langchain_core.messages.utils import convert_to_messages

from app.chat.chat_service import ChatServiceWorker
from app.chat.models import ChatMessage


def test_build_input_messages_preserves_tool_call_id_for_tool_messages() -> None:
    history = [
        ChatMessage(
            role="tool",
            content='{"args":{"value":1},"result":"ok"}',
            tool_name="demo_tool",
            tool_call_id="call_123",
        )
    ]

    messages = ChatServiceWorker._build_input_messages(history, "next step")
    converted = convert_to_messages(messages)

    assert converted[0].type == "tool"
    assert converted[0].tool_call_id == "call_123"
    assert converted[0].name == "demo_tool"


def test_build_input_messages_degrades_legacy_tool_messages_without_id() -> None:
    history = [
        ChatMessage(
            role="tool",
            content='{"args":{"query":"x"},"result":"done"}',
            tool_name="legacy_tool",
            tool_call_id="",
        )
    ]

    messages = ChatServiceWorker._build_input_messages(history, "continue")
    converted = convert_to_messages(messages)

    assert converted[0].type == "ai"
    assert "legacy_tool" in converted[0].content
    assert "done" in converted[0].content
