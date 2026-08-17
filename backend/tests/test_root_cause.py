from types import SimpleNamespace

from app.services.root_cause import mismatched_root_cause_key_error, pick_parent_for_duplicate


def _v(**kw):
    defaults = dict(
        id=1,
        project_id=1,
        vuln_type="ssrf",
        file_path="",
        submission_tier="cve_candidate",
        status="confirmed",
        root_cause_key=None,
        severity_score=3,
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def test_pick_parent_by_key_token_in_filename():
    parent = _v(
        id=90,
        file_path="src/application/src/main/java/run/halo/app/infra/DefaultReactiveUrlDataBufferFetcher.java",
    )
    same_file_low = _v(
        id=72,
        submission_tier="low_impact",
        file_path="src/application/src/main/java/run/halo/app/migration/MigrationEndpoint.java",
    )
    dup = _v(
        id=76,
        submission_tier="duplicate_grouped",
        file_path="src/application/src/main/java/run/halo/app/migration/MigrationEndpoint.java",
        root_cause_key="ssrf:DefaultReactiveUrlDataBufferFetcher",
    )
    picked = pick_parent_for_duplicate(dup, [parent, same_file_low, dup])
    assert picked is not None
    assert picked.id == 90


def test_pick_parent_by_file_family():
    parent = _v(
        id=91,
        vuln_type="sqli",
        file_path="src/jeecg/modules/system/service/impl/SysDictServiceImpl.java",
    )
    dup = _v(
        id=92,
        vuln_type="sqli",
        submission_tier="duplicate_grouped",
        file_path="src/jeecg/modules/system/mapper/xml/SysDictMapper.xml",
        root_cause_key="sqli:specialFilterContentForDictSql:filterSql",
    )
    picked = pick_parent_for_duplicate(dup, [parent, dup])
    assert picked is not None
    assert picked.id == 91


def test_pick_parent_same_file_prefers_older_cve():
    older = _v(
        id=74,
        vuln_type="privilege_escalation",
        file_path="src/modules/system/controller/SysTenantController.java",
    )
    newer = _v(
        id=85,
        vuln_type="privilege_escalation",
        file_path="src/modules/system/controller/SysTenantController.java",
    )
    dup = _v(
        id=73,
        vuln_type="privilege_escalation",
        submission_tier="duplicate_grouped",
        file_path="src/modules/system/controller/SysTenantController.java",
        root_cause_key="missing_permissions:SysTenantController",
    )
    picked = pick_parent_for_duplicate(dup, [newer, older, dup])
    assert picked is not None
    assert picked.id == 74


def test_pick_parent_skips_unrelated_controllers():
    parent = _v(
        id=63,
        vuln_type="privilege_escalation",
        file_path="src/modules/system/controller/SysDepartPermissionController.java",
    )
    dup = _v(
        id=66,
        vuln_type="privilege_escalation",
        submission_tier="duplicate_grouped",
        file_path="src/modules/system/controller/SysLogController.java",
        root_cause_key="cwe862:RequiresPermissions",
    )
    assert pick_parent_for_duplicate(dup, [parent, dup]) is None


def test_duplicate_must_reuse_parent_key():
    parent = _v(
        id=74,
        vuln_type="privilege_escalation",
        file_path="src/modules/system/controller/SysTenantController.java",
        root_cause_key="missing_permissions:SysTenantController",
    )
    dup = _v(
        id=75,
        vuln_type="privilege_escalation",
        submission_tier="duplicate_grouped",
        file_path="src/modules/system/controller/SysTenantController.java",
        root_cause_key="missing_permissions:SysTenantController:edit",
    )
    err = mismatched_root_cause_key_error(dup, [parent], dup.root_cause_key)
    assert err is not None
    assert "missing_permissions:SysTenantController" in err
    ok = mismatched_root_cause_key_error(dup, [parent], "missing_permissions:SysTenantController")
    assert ok is None
