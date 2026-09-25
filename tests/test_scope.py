from televault.scope import DeptRule, department_predicate, scope_sql, Principal


def _rows(env, where, params):
    with env["db"].conn() as c:
        return [r["filename"] for r in c.execute(f"SELECT filename FROM recordings r WHERE {where} ORDER BY filename", params)]


def test_predicate_empty_rules_matches_nothing():
    assert department_predicate([]) == ("0", [])


def test_department_user_sees_only_matching_branches(env):
    p = Principal(user_id=102, username="alpha_support", role="department", customer_id=1, department_ids=[10], customer_ids=[1])
    with env["db"].conn() as c:
        where, params = scope_sql(c, p, None)
    names = _rows(env, where, params)
    # ext 436: out (party), external 2026-08-19 (party); ext 548 internal callee (target); queue 126 (target)
    assert names == sorted([
        "out-3281883752-436-20260820-115255-1787215975.372897.wav",
        "external-436-70000001-20260819-090000-1787100000.100000.wav",
        "internal-548-525-20260820-093910-1787207950.370959.wav",
        "q-126-437-20260820-102616-1787210776.371575.wav",
    ])
    # never Beta's file with the same extension 436
    assert not any("22222222" in n for n in names)


def test_did_branch(env):
    p = Principal(user_id=104, username="fresh", role="department", customer_id=1, department_ids=[11], customer_ids=[1])
    with env["db"].conn() as c:
        where, params = scope_sql(c, p, None)
    assert _rows(env, where, params) == ["in-3282-27972203-20260820-092903-1787207343.370894.wav"]


def test_customer_admin_sees_whole_drive_only(env):
    p = Principal(user_id=101, username="alpha_admin", role="customer_admin", customer_id=1, customer_ids=[1])
    with env["db"].conn() as c:
        where, params = scope_sql(c, p, None)
        beta_where, beta_params = scope_sql(c, p, 2)  # asks for Beta: gets nothing
    names = _rows(env, where, params)
    assert len(names) == 9 and not any("9999" in n for n in names)
    assert _rows(env, beta_where, beta_params) == []


def test_superadmin_can_pick_customer(env):
    p = Principal(user_id=100, username="root", role="superadmin", customer_id=None)
    with env["db"].conn() as c:
        assert len(_rows(env, *scope_sql(c, p, 2))) == 2
        assert len(_rows(env, *scope_sql(c, p, None))) == 11


def test_department_user_without_departments_sees_nothing(env):
    p = Principal(user_id=999, username="x", role="department", customer_id=1, department_ids=[])
    with env["db"].conn() as c:
        assert _rows(env, *scope_sql(c, p, None)) == []
