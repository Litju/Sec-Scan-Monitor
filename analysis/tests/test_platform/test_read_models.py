from __future__ import annotations

import pytest

from secscan.platform.api import AppState
from secscan.platform.read_models import InMemoryReadModelService, ReadModelError


def test_preview_read_models_are_bounded_and_deterministic() -> None:
    state = AppState()
    for index in range(101):
        state.clients[f"CLI-{index:03d}"] = {"client_id": f"CLI-{index:03d}", "name": "synthetic"}

    service = InMemoryReadModelService(state)
    first = service.list_clients(limit=100)
    second = service.list_clients(cursor=first.next_cursor, limit=100)

    assert len(first.items) == 100
    assert len(second.items) == 1
    assert first.items[0].client_id == "CLI-000"
    assert service.firm_summary().data_mode == "SYNTHETIC / NON-PERSONAL / NON-CLIENT / QUALIFICATION_ONLY"

    with pytest.raises(ReadModelError):
        service.list_clients(limit=101)
