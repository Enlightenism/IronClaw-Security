from app.services import mitre_utils as mu


class _Obj:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_normalize_mitre_various_inputs():
    assert mu.normalize_mitre("t1059") == "T1059"
    assert mu.normalize_mitre(" T1059.001 ") == "T1059.001"
    assert mu.normalize_mitre(None) is None
    assert mu.normalize_mitre("") is None
    # non-string coercion to string then uppercased
    assert mu.normalize_mitre("t1078") == "T1078"


def test_coerce_str_list_behaviour():
    assert mu.coerce_str_list(None) == []
    assert mu.coerce_str_list(["a", None, "  b "]) == ["a", "b"]
    assert mu.coerce_str_list(("x", "y")) == ["x", "y"]
    # sets may not preserve order but should include items
    s = set(["one", "two"])
    out = mu.coerce_str_list(s)
    assert set(out) == {"one", "two"}
    assert mu.coerce_str_list("single") == ["single"]
    assert mu.coerce_str_list("a, b, c") == ["a", "b", "c"]


def test_dedupe_preserve_order():
    vals = ["A", "B", "A", "C", "B"]
    assert mu.dedupe_preserve_order(vals) == ["A", "B", "C"]


def test_extract_mitre_from_source_object_and_dict():
    # object-like (IOCMatch-like)
    obj = _Obj(
        mitre_technique_id="t1059",
        mitre_technique_ids=["t1078"],
        mitre_techniques=("T1204",),
    )
    res = mu.extract_mitre_from_source(obj)
    assert res == ["T1059", "T1078", "T1204"]

    # dict-like
    d = {
        "mitre_technique_id": " t2001 ",
        "mitre_technique_ids": "t3001, t3002",
        "mitre_techniques": ["t4001", None, "T4002"],
    }
    res2 = mu.extract_mitre_from_source(d)
    assert res2 == ["T2001", "T3001", "T3002", "T4001", "T4002"]


def test_extract_mitre_from_signal_nested_containers():
    # Signal-like object that has top-level and nested containers
    sig = _Obj(
        mitre_technique_id="t1111",
        metadata={"mitre_technique_ids": ["t2222", "T3333"]},
        details={"mitre_techniques": "t4444, t5555"},
        enrichment={"some": "value"},  # should be ignored
    )
    res = mu.extract_mitre_from_signal(sig)
    # Order: top-level -> metadata -> details
    assert res == ["T1111", "T2222", "T3333", "T4444", "T5555"]


def test_aggregate_mitre_techniques_preserves_ioc_order_then_signals():
    m1 = _Obj(mitre_technique_id="tA", mitre_technique_ids=["tB"])
    m2 = _Obj(mitre_technique_id="tC", mitre_techniques=["tD", "tB"])  # tB duplicate
    sig = _Obj(mitre_technique_ids=["tE"], metadata={"mitre_techniques": ["tF", "tC"]})

    aggregated = mu.aggregate_mitre_techniques([m1, m2], [sig])
    # Expect ioc order: tA, tB, tC, tD  then signals: tE, tF  (tC already seen)
    assert aggregated == ["TA", "TB", "TC", "TD", "TE", "TF"]
