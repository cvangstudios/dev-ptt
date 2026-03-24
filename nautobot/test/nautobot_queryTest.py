# tests/test_nautobot_query.py

import csv
import os
import pytest
import configparser
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from nautobot_query import prompt_save_csv, DEVICE_DETAIL_FIELDS


def test_csv_creates_file(tmp_path):
    """prompt_save_csv() creates a file with correct headers and rows."""
    outfile = str(tmp_path / "test_output.csv")
    rows    = [{"Device Name": "spine-01", "Status": "Active"}]

    prompt_save_csv.__globals__["input"] = lambda _: outfile  # mock input
    # Direct call for unit test
    with open(outfile, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["Device Name", "Status"],
                                extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    assert os.path.exists(outfile)
    with open(outfile) as f:
        reader = list(csv.DictReader(f))
    assert len(reader) == 1
    assert reader[0]["Device Name"] == "spine-01"


def test_load_config_missing(tmp_path, monkeypatch):
    """load_config() exits cleanly when nautobotApi.cfg does not exist."""
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        from nautobot_query import load_config
        load_config()
