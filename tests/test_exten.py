"""'exten' recordings (call to an extension, older FreePBX recordcheck) are parsed and scoped."""
from __future__ import annotations

from conftest import login, make_wav
from televault.indexer import index_customer
from televault.parser import parse_filename

NAME = "exten-436-009613864060-20260101-163740-1767278260.448049.wav"


def test_parser_knows_exten():
    p = parse_filename(NAME)
    assert p and p.rec_type == "exten" and p.target == "436" and p.party == "009613864060"
    assert p.rec_ts == "2026-01-01T16:37:40"


def test_department_sees_exten_by_target_extension(env):
    make_wav(env["drive_a"] / "2026/01/01" / NAME, 4000)
    index_customer(env["db"], env["cfg"], 1)
    c = env["client"]; login(c, "alpha_support")  # Support has extension 436
    items = c.get("/api/recordings", params={"q": "exten-436"}).json()["items"]
    assert [i["filename"] for i in items] == [NAME] and items[0]["type"] == "exten"
    # the Extension filter finds it by the called extension
    items = c.get("/api/recordings", params={"ext": "436", "type": "exten"}).json()["items"]
    assert [i["filename"] for i in items] == [NAME]


def test_rows_indexed_as_unknown_are_corrected_on_rescan(env):
    make_wav(env["drive_a"] / "x" / NAME, 4000)
    index_customer(env["db"], env["cfg"], 1)
    with env["db"].conn() as c:  # simulate a row written by the old parser
        c.execute("UPDATE recordings SET rec_type='unknown', target='', party='' WHERE filename = ?", (NAME,))
    index_customer(env["db"], env["cfg"], 1)
    with env["db"].conn() as c:
        r = c.execute("SELECT rec_type, target, party, rec_ts FROM recordings WHERE filename = ?", (NAME,)).fetchone()
    assert tuple(r) == ("exten", "436", "009613864060", "2026-01-01T16:37:40")
