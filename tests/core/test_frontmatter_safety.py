"""Regression tests for the frontmatter-corruption bug chain.

The bug, found by running the HTTP API against a real workspace:

  1. A hunt was created with the title `SCAN: 198.51.100.7`. The template
     wrote it unquoted, producing `title: SCAN: 198.51.100.7` — not valid
     YAML ("mapping values are not allowed here").
  2. `HuntManager.list_hunts()` swallows per-file parse errors, so that hunt
     silently vanished from the register.
  3. `get_next_hunt_id()` was driven by `list_hunts()`, so it never saw the
     missing id and handed **the same id out again**. Two files, one hunt_id,
     one of them permanently invisible.

Each numbered link gets a test here, because the failure was silent at every
step: nothing raised, nothing logged, and the register just quietly under-
reported.
"""

from pathlib import Path

import pytest
import yaml

from athf.core.hunt_manager import HuntManager
from athf.core.template_engine import render_hunt_template, yaml_flow_list, yaml_scalar


def _frontmatter(markdown: str) -> dict:
    """Parse the frontmatter block, as every consumer of a hunt file does."""
    return yaml.safe_load(markdown.split("---")[1])


@pytest.mark.unit
class TestYamlScalar:
    """Link 1 — values must survive a YAML round-trip unchanged."""

    # Each of these was either the original bug or something a fuzzer found
    # against the first (hand-rolled) version of the fix.
    @pytest.mark.parametrize("value", [
        "SCAN: 198.51.100.7",   # the original corruption
        "plain title",
        "#leading hash",
        "- leading dash",
        "*star", "&anchor", "!bang", "%directive", "@at", "`tick",
        "[bracket]", "{brace}", "|pipe", ">gt", "?question",
        "true", "false", "null", "no", "off", "NULL", "~",
        "1.0", "0x1f", "0o17", "1e5", "12:30:45", "2026-08-18",
        'has "double" quotes', "Marauder's Map",
        "  padded  ", "trailing ",
        "multi\nline", "tab\there", "\r\ncrlf", "\x0cformfeed",
        "é accent", "emoji 🛰", "back\\slash",
        "",
    ])
    def test_round_trips_unchanged(self, value):
        doc = f"title: {yaml_scalar(value)}\nother: x\n"
        assert yaml.safe_load(doc)["title"] == value

    def test_plain_values_stay_unquoted(self):
        """Readability matters — don't quote what doesn't need quoting."""
        assert yaml_scalar("credential access hunt") == "credential access hunt"

    def test_flow_list_quotes_items_and_drops_empties(self):
        rendered = yaml_flow_list(["Splunk: prod", None, "", "EDR"])
        assert yaml.safe_load(f"ds: {rendered}")["ds"] == ["Splunk: prod", "EDR"]

    def test_flow_list_empty(self):
        assert yaml.safe_load(f"ds: {yaml_flow_list([])}")["ds"] == []


@pytest.mark.unit
class TestRenderedHuntIsParseable:
    """Link 1, end to end — the exact hunt that corrupted the register."""

    def test_colon_title_produces_valid_frontmatter(self):
        md = render_hunt_template(
            hunt_id="H-0099", title="SCAN: 198.51.100.7", technique="T1595.002",
            platform=["network"], tactics=["reconnaissance"],
            data_sources=["VirusTotal"], hunter="Marauder's Map")
        fm = _frontmatter(md)
        assert fm["hunt_id"] == "H-0099"
        assert fm["title"] == "SCAN: 198.51.100.7"
        assert fm["hunter"] == "Marauder's Map"
        assert fm["techniques"] == ["T1595.002"]
        assert fm["data_sources"] == ["VirusTotal"]

    def test_markdown_body_still_reads_naturally(self):
        """The H1 and prose take the RAW title — quoting belongs to the
        frontmatter only. The body also indexes the lists (`techniques[0]`,
        `data_sources[0]`), so they must reach it as lists, not as a preformatted
        string: passing a string rendered `[, T, 1, 5, ...]`, one char per item."""
        md = render_hunt_template(
            hunt_id="H-0099", title="SCAN: 198.51.100.7", technique="T1595.002",
            data_sources=["VirusTotal"])
        assert "# H-0099: SCAN: 198.51.100.7" in md
        assert "- **MITRE ATT&CK:** T1595.002" in md
        assert "- **Index/Data Source:** VirusTotal" in md


@pytest.mark.unit
class TestHuntIdNeverCollides:
    """Links 2 and 3 — allocation must be driven by what EXISTS on disk."""

    def _write(self, d: Path, rel: str, body: str) -> None:
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    def test_unparseable_hunt_still_reserves_its_id(self, tmp_path):
        hunts = tmp_path / "hunts"
        self._write(hunts, "production/2026/Q1/H-0001.md",
                    "---\nhunt_id: H-0001\ntitle: fine\nstatus: planning\n"
                    "date: 2026-01-01\n---\n")
        # The corrupted file: valid name, unparseable frontmatter.
        self._write(hunts, "production/2026/Q2/H-0002.md",
                    "---\nhunt_id: H-0002\ntitle: SCAN: 1.2.3.4\nstatus: planning\n"
                    "date: 2026-04-17\n---\n")

        mgr = HuntManager(hunts_dir=hunts)
        # Link 2: the broken file is invisible to the register...
        assert [h["hunt_id"] for h in mgr.list_hunts()] == ["H-0001"]
        # Link 3: ...but must NOT have its id recycled. Before the fix this
        # returned H-0002 and overwrote the register's view of that hunt.
        assert mgr.get_next_hunt_id() == "H-0003"

    def test_allocation_ignores_non_hunt_files(self, tmp_path):
        hunts = tmp_path / "hunts"
        self._write(hunts, "README.md", "# not a hunt\n")
        self._write(hunts, "production/notes.md", "# scratch\n")
        assert HuntManager(hunts_dir=hunts).get_next_hunt_id() == "H-0001"

    def test_round_trip_created_hunt_is_listed(self, tmp_path):
        """A hunt written by the template must be readable by the register —
        the property that actually failed in production."""
        hunts = tmp_path / "hunts"
        md = render_hunt_template(hunt_id="H-0001", title="SCAN: 5.6.7.8",
                                  technique="T1595.002")
        self._write(hunts, "production/2026/Q3/H-0001.md", md)
        mgr = HuntManager(hunts_dir=hunts)
        assert [h["hunt_id"] for h in mgr.list_hunts()] == ["H-0001"]
        assert mgr.get_next_hunt_id() == "H-0002"
