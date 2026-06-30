import os

import pytest

from earned_autonomy.storage.sql import SqlStore
from earned_autonomy.core.models import AgentIdentity


@pytest.mark.sql
def test_sql_store_roundtrip_from_env():
    url = os.getenv("EAL_DATABASE_URL")
    if not url or url == "memory":
        pytest.skip("EAL_DATABASE_URL not set for SQL integration test")
    store = SqlStore(url)
    agent = AgentIdentity(agent_id="sql_agent", name="SQL Agent", owner_id="owner", purpose="roundtrip")
    store.add_agent(agent)
    loaded = store.get_agent("sql_agent")
    assert loaded is not None
    assert loaded.agent_id == "sql_agent"
