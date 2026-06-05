"""Tests for AnalysisDB and the DB-related MCP tool functions."""
from __future__ import annotations

import os
import pytest

from androguard_mcp.db import AnalysisDB


# ---------------------------------------------------------------------------
# AnalysisDB unit tests (no singletons, each test gets a fresh instance)
# ---------------------------------------------------------------------------

class TestAnalysisDB:
    def test_initial_state(self):
        d = AnalysisDB()
        assert not d.loaded
        assert d.path == ""

    def test_open_creates_file(self, tmp_path):
        d = AnalysisDB()
        p = str(tmp_path / "test.sqlite")
        d.open(p, create_if_missing=True)
        assert d.loaded
        assert os.path.exists(p)

    def test_open_existing_file(self, tmp_path):
        p = str(tmp_path / "test.sqlite")
        d1 = AnalysisDB()
        d1.open(p, create_if_missing=True)
        d2 = AnalysisDB()
        d2.open(p, create_if_missing=False)
        assert d2.loaded

    def test_open_fails_if_missing_no_create(self, tmp_path):
        d = AnalysisDB()
        with pytest.raises(FileNotFoundError):
            d.open(str(tmp_path / "nonexistent.sqlite"), create_if_missing=False)

    def test_double_open_raises(self, tmp_path):
        d = AnalysisDB()
        p = str(tmp_path / "test.sqlite")
        d.open(p, create_if_missing=True)
        with pytest.raises(RuntimeError, match="already loaded"):
            d.open(p, create_if_missing=True)

    def test_set_get_alias(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        d.set_alias("Lcom/a/b/c;", "UserAuthManager")
        result = d.get_alias("Lcom/a/b/c;")
        assert result == ("UserAuthManager", "")

    def test_set_get_alias_with_note(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        d.set_alias("Lcom/a/b/c;->a()V", "validateToken", note="handles JWT")
        result = d.get_alias("Lcom/a/b/c;->a()V")
        assert result == ("validateToken", "handles JWT")

    def test_get_alias_missing(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        assert d.get_alias("Lnot/exist;") is None

    def test_set_alias_overwrites(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        d.set_alias("Lcom/a;", "First")
        d.set_alias("Lcom/a;", "Second", note="updated")
        result = d.get_alias("Lcom/a;")
        assert result == ("Second", "updated")

    def test_delete_alias(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        d.set_alias("Lcom/a;", "Foo")
        assert d.delete_alias("Lcom/a;") is True
        assert d.get_alias("Lcom/a;") is None

    def test_delete_alias_missing(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        assert d.delete_alias("Lnot/exist;") is False

    def test_list_aliases_empty(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        assert d.list_aliases() == []

    def test_list_aliases_all(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        d.set_alias("Lcom/a;", "Alpha")
        d.set_alias("Lcom/b;", "Beta")
        rows = d.list_aliases()
        assert len(rows) == 2
        originals = {r["original"] for r in rows}
        assert originals == {"Lcom/a;", "Lcom/b;"}

    def test_list_aliases_pattern(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        d.set_alias("Lcom/auth/Manager;", "AuthManager")
        d.set_alias("Lcom/net/Client;", "NetClient")
        rows = d.list_aliases("auth")
        assert len(rows) == 1
        assert rows[0]["original"] == "Lcom/auth/Manager;"

    def test_list_aliases_pattern_matches_alias(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        d.set_alias("Lcom/a;", "TokenValidator")
        d.set_alias("Lcom/b;", "NetClient")
        rows = d.list_aliases("Token")
        assert len(rows) == 1
        assert rows[0]["alias"] == "TokenValidator"

    def test_get_all_aliases(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        d.set_alias("Lcom/a;", "Alpha")
        d.set_alias("Lcom/b;", "Beta")
        aliases = d.get_all_aliases()
        assert aliases == {"Lcom/a;": "Alpha", "Lcom/b;": "Beta"}

    def test_alias_count(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        assert d.alias_count() == 0
        d.set_alias("Lcom/a;", "Alpha")
        d.set_alias("Lcom/b;", "Beta")
        assert d.alias_count() == 2

    def test_count_aliases_no_pattern(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        d.set_alias("Lcom/a;", "Alpha")
        d.set_alias("Lcom/b;", "Beta")
        d.set_alias("Lcom/c;", "Gamma")
        assert d.count_aliases() == 3

    def test_count_aliases_with_pattern(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        d.set_alias("Lcom/auth/Manager;", "AuthManager")
        d.set_alias("Lcom/net/Client;", "NetClient")
        assert d.count_aliases("auth") == 1
        assert d.count_aliases("net") == 1
        assert d.count_aliases("Manager") == 1  # matches alias
        assert d.count_aliases("xyz") == 0

    def test_list_aliases_pagination(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        for i in range(5):
            d.set_alias(f"Lcom/{i};", f"Class{i}")
        page1 = d.list_aliases(offset=0, limit=3)
        page2 = d.list_aliases(offset=3, limit=3)
        assert len(page1) == 3
        assert len(page2) == 2
        all_originals = {r["original"] for r in page1 + page2}
        assert len(all_originals) == 5

    def test_list_aliases_pagination_with_pattern(self, tmp_path):
        d = AnalysisDB()
        d.open(str(tmp_path / "test.sqlite"), create_if_missing=True)
        for i in range(4):
            d.set_alias(f"Lcom/auth/{i};", f"Auth{i}")
        d.set_alias("Lcom/net/x;", "NetX")
        page1 = d.list_aliases(pattern="auth", offset=0, limit=2)
        page2 = d.list_aliases(pattern="auth", offset=2, limit=2)
        assert len(page1) == 2
        assert len(page2) == 2
        assert d.count_aliases("auth") == 4

    def test_persistence(self, tmp_path):
        p = str(tmp_path / "test.sqlite")
        d1 = AnalysisDB()
        d1.open(p, create_if_missing=True)
        d1.set_alias("Lcom/a;", "Alpha")
        d2 = AnalysisDB()
        d2.open(p)
        assert d2.get_alias("Lcom/a;") == ("Alpha", "")


# ---------------------------------------------------------------------------
# _apply_aliases + DB tool functions (using db singleton with isolation)
# ---------------------------------------------------------------------------

@pytest.fixture()
def isolated_db(tmp_path):
    """Reset the db singleton before and after each test."""
    from androguard_mcp import db as db_module
    d = db_module.db
    saved_conn = d._conn
    saved_path = d.path
    d._conn = None
    d.path = ""
    yield tmp_path
    if d._conn is not None:
        d._conn.close()
    d._conn = saved_conn
    d.path = saved_path


class TestApplyAliases:
    def test_no_db_passthrough(self):
        from androguard_mcp.server import _apply_aliases
        text = "Lcom/a/b/c; is a class"
        assert _apply_aliases(text) == text

    def test_replaces_alias(self, isolated_db):
        from androguard_mcp.db import db
        from androguard_mcp.server import _apply_aliases
        db.open(str(isolated_db / "t.sqlite"), create_if_missing=True)
        db.set_alias("Lcom/a/b/c;", "AuthManager")
        result = _apply_aliases("class Lcom/a/b/c; found")
        assert "[AuthManager] Lcom/a/b/c;" in result

    def test_longer_match_wins(self, isolated_db):
        from androguard_mcp.db import db
        from androguard_mcp.server import _apply_aliases
        db.open(str(isolated_db / "t.sqlite"), create_if_missing=True)
        db.set_alias("Lcom/a;", "ShortClass")
        db.set_alias("Lcom/a;->doThing()V", "doThing")
        result = _apply_aliases("Lcom/a;->doThing()V and Lcom/a;")
        # method signature should be substituted as a whole, not split
        assert "[doThing] Lcom/a;->doThing()V" in result
        assert "[ShortClass] Lcom/a;" in result

    def test_empty_aliases_passthrough(self, isolated_db):
        from androguard_mcp.db import db
        from androguard_mcp.server import _apply_aliases
        db.open(str(isolated_db / "t.sqlite"), create_if_missing=True)
        text = "Lcom/a/b/c; no aliases"
        assert _apply_aliases(text) == text


class TestServerDBTools:
    @pytest.fixture(autouse=True)
    def _isolate_analyzer(self):
        from androguard_mcp import analyzer
        saved = analyzer.analysis
        analyzer.analysis = None
        yield
        analyzer.analysis = saved

    @pytest.mark.asyncio
    async def test_load_db_no_apk_no_path(self, isolated_db):
        from androguard_mcp.server import tool_load_db
        result = await tool_load_db()
        assert "Error" in result
        assert "load_apk" in result

    @pytest.mark.asyncio
    async def test_load_db_explicit_path_creates(self, isolated_db):
        from androguard_mcp.server import tool_load_db
        p = str(isolated_db / "new.sqlite")
        result = await tool_load_db(path=p, create_if_missing=True)
        assert "Loaded DB" in result
        assert "0 aliases" in result

    @pytest.mark.asyncio
    async def test_load_db_already_loaded(self, isolated_db):
        from androguard_mcp.server import tool_load_db
        p = str(isolated_db / "new.sqlite")
        await tool_load_db(path=p, create_if_missing=True)
        result = await tool_load_db(path=p, create_if_missing=True)
        assert "Error" in result
        assert "already loaded" in result

    @pytest.mark.asyncio
    async def test_load_db_missing_no_create(self, isolated_db):
        from androguard_mcp.server import tool_load_db
        p = str(isolated_db / "nonexistent.sqlite")
        result = await tool_load_db(path=p, create_if_missing=False)
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_set_alias_no_db(self, isolated_db):
        from androguard_mcp.server import tool_set_alias
        result = await tool_set_alias("Lcom/a;", "Foo")
        assert "Error" in result

    @pytest.mark.asyncio
    async def test_set_get_alias_roundtrip(self, isolated_db):
        from androguard_mcp.server import tool_load_db, tool_set_alias, tool_get_alias
        p = str(isolated_db / "t.sqlite")
        await tool_load_db(path=p, create_if_missing=True)
        set_result = await tool_set_alias("Lcom/a;", "MyClass", note="important")
        assert "[MyClass] Lcom/a;" in set_result
        assert "important" in set_result
        get_result = await tool_get_alias("Lcom/a;")
        assert "[MyClass] Lcom/a;" in get_result
        assert "important" in get_result

    @pytest.mark.asyncio
    async def test_get_alias_missing(self, isolated_db):
        from androguard_mcp.server import tool_load_db, tool_get_alias
        await tool_load_db(path=str(isolated_db / "t.sqlite"), create_if_missing=True)
        result = await tool_get_alias("Lnot/exist;")
        assert "No alias" in result

    @pytest.mark.asyncio
    async def test_list_aliases_empty(self, isolated_db):
        from androguard_mcp.server import tool_load_db, tool_list_aliases
        await tool_load_db(path=str(isolated_db / "t.sqlite"), create_if_missing=True)
        result = await tool_list_aliases()
        assert "No aliases" in result

    @pytest.mark.asyncio
    async def test_list_aliases_shows_entries(self, isolated_db):
        from androguard_mcp.server import tool_load_db, tool_set_alias, tool_list_aliases
        await tool_load_db(path=str(isolated_db / "t.sqlite"), create_if_missing=True)
        await tool_set_alias("Lcom/a;", "Alpha")
        await tool_set_alias("Lcom/b;", "Beta")
        result = await tool_list_aliases()
        assert "[Alpha] Lcom/a;" in result
        assert "[Beta] Lcom/b;" in result

    @pytest.mark.asyncio
    async def test_list_aliases_pagination(self, isolated_db):
        from androguard_mcp.server import tool_load_db, tool_set_alias, tool_list_aliases
        await tool_load_db(path=str(isolated_db / "t.sqlite"), create_if_missing=True)
        for i in range(5):
            await tool_set_alias(f"Lcom/{i};", f"Class{i}")
        page1 = await tool_list_aliases(limit=3)
        page2 = await tool_list_aliases(offset=3, limit=3)
        assert "offset=3" in page1 or "next page" in page1
        assert "Class" in page1
        assert "Class" in page2

    def test_all_new_tools_registered(self):
        from androguard_mcp.server import TOOL_MAP
        for name in ("load_db", "set_alias", "get_alias", "list_aliases", "delete_alias"):
            assert name in TOOL_MAP, f"Tool '{name}' not in TOOL_MAP"

    @pytest.mark.asyncio
    async def test_delete_alias(self, isolated_db):
        from androguard_mcp.server import tool_load_db, tool_set_alias, tool_delete_alias, tool_get_alias
        await tool_load_db(path=str(isolated_db / "t.sqlite"), create_if_missing=True)
        await tool_set_alias("Lcom/a;", "Alpha")
        del_result = await tool_delete_alias("Lcom/a;")
        assert "Deleted" in del_result
        get_result = await tool_get_alias("Lcom/a;")
        assert "No alias" in get_result

    @pytest.mark.asyncio
    async def test_delete_alias_missing(self, isolated_db):
        from androguard_mcp.server import tool_load_db, tool_delete_alias
        await tool_load_db(path=str(isolated_db / "t.sqlite"), create_if_missing=True)
        result = await tool_delete_alias("Lnot/exist;")
        assert "No alias found" in result

    def test_all_new_tools_registered(self):
        from androguard_mcp.server import TOOL_MAP
        for name in ("load_db", "set_alias", "get_alias", "list_aliases", "delete_alias"):
            assert name in TOOL_MAP, f"Tool '{name}' not in TOOL_MAP"
