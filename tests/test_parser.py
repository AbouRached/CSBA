from televault.parser import parse_filename, fallback_from_mtime


def test_worked_examples_from_idm_findings():
    cases = {
        "in-3282-27972203-20260820-092903-1787207343.370894.wav": ("in", "3282", "27972203", "2026-08-20T09:29:03", "1787207343.370894"),
        "out-3281883752-436-20260820-115255-1787215975.372897.wav": ("out", "3281883752", "436", "2026-08-20T11:52:55", "1787215975.372897"),
        "q-131-01644655-20260820-082243-1787203363.370306.wav": ("q", "131", "01644655", "2026-08-20T08:22:43", "1787203363.370306"),
        "q-126-437-20260820-102616-1787210776.371575.wav": ("q", "126", "437", "2026-08-20T10:26:16", "1787210776.371575"),
        "external-851-01263358-20260820-105325-1787212405.371995.wav": ("external", "851", "01263358", "2026-08-20T10:53:25", "1787212405.371995"),
        "internal-548-525-20260820-093910-1787207950.370959.wav": ("internal", "548", "525", "2026-08-20T09:39:10", "1787207950.370959"),
    }
    for name, (t, target, party, ts, uid) in cases.items():
        p = parse_filename(name)
        assert p is not None, name
        assert (p.rec_type, p.target, p.party, p.rec_ts, p.uniqueid) == (t, target, party, ts, uid)
        assert p.parsed


def test_uppercase_extension_and_mp3():
    p = parse_filename("IN-3282-1-20260820-092903-1787207343.1.WAV")
    assert p and p.rec_type == "in"
    p = parse_filename("out-1-2-20260820-092903-1787207343.1.mp3")
    assert p and p.rec_type == "out"


def test_rejects_garbage():
    assert parse_filename("notes.wav") is None
    assert parse_filename("in-3282-20260820-092903-1787207343.1.wav") is None  # missing party
    assert parse_filename("weird-1-2-20260820-092903-1787207343.1.wav") is None  # unknown type
    assert parse_filename("in-1-2-20261399-092903-1787207343.1.wav") is None  # bad date
    assert parse_filename("in-1-2-20260820-092903-nouid.wav") is None


def test_fallback_uses_mtime():
    p = fallback_from_mtime(1_700_000_000)
    assert p.rec_type == "unknown" and not p.parsed and p.rec_ts.startswith("2023-11-1")
