from __future__ import annotations

import re

from fastapi.testclient import TestClient
import pytest

URL = "/ui/docs/changelog"

_REQUIRED_TOP_LEVEL_FIELDS = (
    "generatedat",
    "headline",
    "intro",
    "totalentries",
    "entries",
    "notes",
)

_REQUIRED_ENTRY_FIELDS = (
    "version",
    "releasedate",
    "summary",
    "additions",
    "changes",
    "deprecations",
    "breakingchanges",
)

_REQUIRED_ADDITION_FIELDS = (
    "itemid",
    "label",
    "description",
)

_REQUIRED_CHANGE_FIELDS = (
    "itemid",
    "label",
    "before",
    "after",
    "reason",
)

_REQUIRED_DEPRECATION_FIELDS = (
    "itemid",
    "label",
    "description",
)

_REQUIRED_BREAKING_CHANGE_FIELDS = (
    "itemid",
    "label",
    "description",
    "migrationnote",
    "affectedroutes",
)

_KNOWN_VERSIONS = {
    "gen1.0.0",
    "gen1.1.0",
    "gen1.2.0",
    "gen1.3.0",
    "gen1.4.0",
    "gen1.5.0",
}

_VERSION_PATTERN = re.compile(r"^gen\d+\.\d+\.\d+$")
_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def test_get_docs_changelog_returns_200(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200


def test_get_docs_changelog_content_type_is_json(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert "application/json" in response.headers.get("content-type", "")


def test_get_docs_changelog_response_is_object(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert isinstance(response.json(), dict)


def test_get_docs_changelog_required_top_level_fields_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in _REQUIRED_TOP_LEVEL_FIELDS:
        assert field in body, f"missing top-level field: {field!r}"


def test_get_docs_changelog_scalar_fields_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    for field in ("generatedat", "headline", "intro"):
        assert isinstance(body[field], str), f"{field!r} must be str"
        assert body[field].strip(), f"{field!r} must not be empty"


def test_get_docs_changelog_generatedat_is_iso8601(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    generatedat = response.json()["generatedat"]
    assert isinstance(generatedat, str)
    assert "T" in generatedat
    assert "Z" in generatedat or "+" in generatedat


def test_get_docs_changelog_totalentries_is_positive_int(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["totalentries"], int)
    assert body["totalentries"] > 0


def test_get_docs_changelog_entries_is_non_empty_list(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    entries = response.json()["entries"]
    assert isinstance(entries, list)
    assert len(entries) > 0


def test_get_docs_changelog_totalentries_matches_entries_length(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    body = response.json()
    assert body["totalentries"] == len(body["entries"])


def test_get_docs_changelog_notes_is_non_empty_list(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    notes = response.json()["notes"]
    assert isinstance(notes, list)
    assert len(notes) > 0


def test_get_docs_changelog_notes_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, note in enumerate(response.json()["notes"]):
        assert isinstance(note, str), f"notes[{i}] must be str"
        assert note.strip(), f"notes[{i}] must not be empty"


def test_get_docs_changelog_entry_required_fields_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        assert isinstance(entry, dict), f"entries[{i}] must be a dict"
        for field in _REQUIRED_ENTRY_FIELDS:
            assert field in entry, f"entries[{i}] missing field: {field!r}"


def test_get_docs_changelog_entry_version_format(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        version = entry["version"]
        assert isinstance(version, str), f"entries[{i}].version must be str"
        assert _VERSION_PATTERN.match(version), f"entries[{i}].version {version!r} does not match gen{{major}}.{{minor}}.{{patch}}"


def test_get_docs_changelog_entry_releasedate_format(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        releasedate = entry["releasedate"]
        assert isinstance(releasedate, str), f"entries[{i}].releasedate must be str"
        assert _DATE_PATTERN.match(releasedate), f"entries[{i}].releasedate {releasedate!r} does not match YYYY-MM-DD"


def test_get_docs_changelog_entry_summary_is_non_empty_string(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        assert isinstance(entry["summary"], str), f"entries[{i}].summary must be str"
        assert entry["summary"].strip(), f"entries[{i}].summary must not be empty"


def test_get_docs_changelog_entry_list_fields_are_lists(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        for field in ("additions", "changes", "deprecations", "breakingchanges"):
            assert isinstance(entry[field], list), f"entries[{i}].{field!r} must be a list"


def test_get_docs_changelog_entry_versions_are_unique(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    versions = [e["version"] for e in response.json()["entries"]]
    assert len(versions) == len(set(versions))


def test_get_docs_changelog_all_known_versions_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    present_versions = {e["version"] for e in response.json()["entries"]}
    for version in _KNOWN_VERSIONS:
        assert version in present_versions, f"expected version {version!r} not found in entries"


def test_get_docs_changelog_entries_ordered_newest_first(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    dates = [e["releasedate"] for e in response.json()["entries"]]
    assert dates == sorted(dates, reverse=True)


def test_get_docs_changelog_gen150_is_first_entry(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert response.json()["entries"][0]["version"] == "gen1.5.0"


def test_get_docs_changelog_gen100_is_last_entry(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    assert response.json()["entries"][-1]["version"] == "gen1.0.0"


def test_get_docs_changelog_gen150_has_additions(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    gen150 = next(e for e in response.json()["entries"] if e["version"] == "gen1.5.0")
    assert len(gen150["additions"]) > 0


def test_get_docs_changelog_gen150_has_changes(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    gen150 = next(e for e in response.json()["entries"] if e["version"] == "gen1.5.0")
    assert len(gen150["changes"]) > 0


def test_get_docs_changelog_gen110_has_breaking_changes(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    gen110 = next(e for e in response.json()["entries"] if e["version"] == "gen1.1.0")
    assert len(gen110["breakingchanges"]) > 0


def test_get_docs_changelog_addition_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        for j, addition in enumerate(entry["additions"]):
            assert isinstance(addition, dict), f"entries[{i}].additions[{j}] must be a dict"
            for field in _REQUIRED_ADDITION_FIELDS:
                assert field in addition, f"entries[{i}].additions[{j}] missing field: {field!r}"
            assert isinstance(addition["itemid"], str)
            assert addition["itemid"].strip()
            assert isinstance(addition["label"], str)
            assert addition["label"].strip()
            assert isinstance(addition["description"], str)
            assert addition["description"].strip()


def test_get_docs_changelog_addition_relatedroute_is_str_or_none(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        for j, addition in enumerate(entry["additions"]):
            relatedroute = addition.get("relatedroute")
            assert relatedroute is None or isinstance(relatedroute, str), f"entries[{i}].additions[{j}].relatedroute must be str or None"


def test_get_docs_changelog_change_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        for j, change in enumerate(entry["changes"]):
            assert isinstance(change, dict), f"entries[{i}].changes[{j}] must be a dict"
            for field in _REQUIRED_CHANGE_FIELDS:
                assert field in change, f"entries[{i}].changes[{j}] missing field: {field!r}"
            for str_field in ("itemid", "label", "before", "after", "reason"):
                assert isinstance(change[str_field], str), f"entries[{i}].changes[{j}].{str_field!r} must be str"
                assert change[str_field].strip(), f"entries[{i}].changes[{j}].{str_field!r} must not be empty"


def test_get_docs_changelog_change_relatedroute_is_str_or_none(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        for j, change in enumerate(entry["changes"]):
            relatedroute = change.get("relatedroute")
            assert relatedroute is None or isinstance(relatedroute, str), f"entries[{i}].changes[{j}].relatedroute must be str or None"


def test_get_docs_changelog_deprecation_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        for j, dep in enumerate(entry["deprecations"]):
            assert isinstance(dep, dict), f"entries[{i}].deprecations[{j}] must be a dict"
            for field in _REQUIRED_DEPRECATION_FIELDS:
                assert field in dep, f"entries[{i}].deprecations[{j}] missing field: {field!r}"
            assert isinstance(dep["itemid"], str)
            assert dep["itemid"].strip()
            assert isinstance(dep["label"], str)
            assert dep["label"].strip()
            assert isinstance(dep["description"], str)
            assert dep["description"].strip()


def test_get_docs_changelog_deprecation_optional_fields_are_str_or_none(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        for j, dep in enumerate(entry["deprecations"]):
            for opt_field in ("replacedby", "sunsetversion"):
                val = dep.get(opt_field)
                assert val is None or isinstance(val, str), f"entries[{i}].deprecations[{j}].{opt_field!r} must be str or None"


def test_get_docs_changelog_breaking_change_shape(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        for j, brk in enumerate(entry["breakingchanges"]):
            assert isinstance(brk, dict), f"entries[{i}].breakingchanges[{j}] must be a dict"
            for field in _REQUIRED_BREAKING_CHANGE_FIELDS:
                assert field in brk, f"entries[{i}].breakingchanges[{j}] missing field: {field!r}"
            for str_field in ("itemid", "label", "description", "migrationnote"):
                assert isinstance(brk[str_field], str), f"entries[{i}].breakingchanges[{j}].{str_field!r} must be str"
                assert brk[str_field].strip(), f"entries[{i}].breakingchanges[{j}].{str_field!r} must not be empty"
            assert isinstance(brk["affectedroutes"], list), f"entries[{i}].breakingchanges[{j}].affectedroutes must be a list"


def test_get_docs_changelog_breaking_change_affected_routes_are_non_empty_strings(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        for j, brk in enumerate(entry["breakingchanges"]):
            for k, route in enumerate(brk["affectedroutes"]):
                assert isinstance(route, str), f"entries[{i}].breakingchanges[{j}].affectedroutes[{k}] must be str"
                assert route.strip(), f"entries[{i}].breakingchanges[{j}].affectedroutes[{k}] must not be empty"


def test_get_docs_changelog_breaking_change_affected_routes_non_empty_list(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    for i, entry in enumerate(response.json()["entries"]):
        for j, brk in enumerate(entry["breakingchanges"]):
            assert len(brk["affectedroutes"]) > 0, f"entries[{i}].breakingchanges[{j}].affectedroutes must not be empty"


def test_get_docs_changelog_gen110_breaking_change_detail(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    gen110 = next(e for e in response.json()["entries"] if e["version"] == "gen1.1.0")
    brk = gen110["breakingchanges"][0]
    assert brk["itemid"] == "break-guard-action-decision-verdict-rename"
    assert "POST /guard/action-decision" in brk["affectedroutes"]
    assert "decision" in brk["migrationnote"].lower()


def test_get_docs_changelog_gen150_addition_itemids_include_webhook_events(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    gen150 = next(e for e in response.json()["entries"] if e["version"] == "gen1.5.0")
    addition_itemids = {a["itemid"] for a in gen150["additions"]}
    for expected_itemid in (
        "add-webhook-event-scan-verdict",
        "add-webhook-event-quarantine",
        "add-webhook-event-policy-violation",
    ):
        assert expected_itemid in addition_itemids, f"gen1.5.0 additions missing item: {expected_itemid!r}"


def test_get_docs_changelog_gen150_addition_itemids_include_docs_surfaces(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    gen150 = next(e for e in response.json()["entries"] if e["version"] == "gen1.5.0")
    addition_itemids = {a["itemid"] for a in gen150["additions"]}
    for expected_itemid in ("add-docs-webhooks", "add-docs-changelog"):
        assert expected_itemid in addition_itemids, f"gen1.5.0 additions missing item: {expected_itemid!r}"


def test_get_docs_changelog_gen150_changes_include_guard_webhook_emit(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    gen150 = next(e for e in response.json()["entries"] if e["version"] == "gen1.5.0")
    change_itemids = {c["itemid"] for c in gen150["changes"]}
    assert "change-guard-telemetry-webhook-emit" in change_itemids


def test_get_docs_changelog_gen150_webhook_auto_disable_change_present(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    gen150 = next(e for e in response.json()["entries"] if e["version"] == "gen1.5.0")
    change_itemids = {c["itemid"] for c in gen150["changes"]}
    assert "change-webhook-auto-disable" in change_itemids


def test_get_docs_changelog_addition_itemids_unique_across_all_entries(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    all_itemids: list[str] = []
    for entry in response.json()["entries"]:
        all_itemids.extend(a["itemid"] for a in entry["additions"])
    assert len(all_itemids) == len(set(all_itemids))


def test_get_docs_changelog_change_itemids_unique_across_all_entries(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    all_itemids: list[str] = []
    for entry in response.json()["entries"]:
        all_itemids.extend(c["itemid"] for c in entry["changes"])
    assert len(all_itemids) == len(set(all_itemids))


def test_get_docs_changelog_breaking_change_itemids_unique_across_all_entries(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    all_itemids: list[str] = []
    for entry in response.json()["entries"]:
        all_itemids.extend(b["itemid"] for b in entry["breakingchanges"])
    assert len(all_itemids) == len(set(all_itemids))


def test_get_docs_changelog_gen100_has_most_additions(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    entries = response.json()["entries"]
    gen100 = next(e for e in entries if e["version"] == "gen1.0.0")
    for other in entries:
        if other["version"] != "gen1.0.0":
            assert len(gen100["additions"]) >= len(other["additions"]), f"gen1.0.0 should have >= additions than {other['version']!r}"


def test_get_docs_changelog_gen100_no_breaking_changes(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    gen100 = next(e for e in response.json()["entries"] if e["version"] == "gen1.0.0")
    assert gen100["breakingchanges"] == []


def test_get_docs_changelog_notes_mention_version_scheme(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    notes_text = " ".join(response.json()["notes"]).lower()
    assert "gen" in notes_text


def test_get_docs_changelog_notes_mention_breaking_changes(
    test_client: TestClient,
) -> None:
    response = test_client.get(URL)
    assert response.status_code == 200
    notes_text = " ".join(response.json()["notes"]).lower()
    assert "breaking" in notes_text


def test_get_docs_changelog_no_auth_required(test_client: TestClient) -> None:
    response = test_client.get(URL)
    assert response.status_code != 401
    assert response.status_code != 403


@pytest.mark.parametrize(
    "method",
    ["post", "put", "patch", "delete"],
)
def test_get_docs_changelog_non_get_methods_not_allowed(
    test_client: TestClient,
    method: str,
) -> None:
    response = getattr(test_client, method)(URL)
    assert response.status_code == 405
