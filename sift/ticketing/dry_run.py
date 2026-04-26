"""DryRunProvider — prints ticket JSON without sending to any external system."""

from __future__ import annotations

import json
from pathlib import Path

from sift.ticketing.protocol import TicketDraft, TicketResult


class DryRunProvider:
    """Serialises a TicketDraft to JSON (stdout or file).

    Used for previewing the ticket payload and as the foundation for
    Shadow-Mode in v1.5 (actions computed and logged but not executed).
    """

    name = "dry-run"

    def __init__(self, output_path: Path | None = None) -> None:
        self._output_path = output_path

    def send(self, draft: TicketDraft) -> TicketResult:
        payload = draft.model_dump(mode="json")
        serialized = json.dumps(payload, indent=2, default=str)
        if self._output_path is not None:
            self._output_path.write_text(serialized, encoding="utf-8")
            url = self._output_path.resolve().as_uri()
        else:
            print(serialized)
            url = None
        return TicketResult(
            provider=self.name,
            ticket_id=None,
            ticket_url=url,
            raw_response=payload,
        )

    def healthcheck(self) -> tuple[bool, str]:
        return True, "dry-run always available"
