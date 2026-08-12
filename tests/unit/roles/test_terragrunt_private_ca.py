from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]


def test_terragrunt_private_ca_is_optional_and_used_everywhere():
    defaults = yaml.safe_load(
        (ROOT / "roles/terragrunt/defaults/main.yml").read_text(encoding="utf-8")
    )
    tasks = (ROOT / "roles/terragrunt/tasks/main.yml").read_text(encoding="utf-8")

    assert defaults["terragrunt_vault_ca_path"] == ""
    assert tasks.count("ca_path: \"{{ terragrunt_vault_ca_path | default(omit, true) }}\"") == 3
    assert tasks.count("VAULT_CACERT: \"{{ terragrunt_vault_ca_path | default(omit, true) }}\"") >= 7


def test_terragrunt_import_accepts_guarded_extra_arguments():
    tasks = (ROOT / "roles/terragrunt/tasks/main.yml").read_text(encoding="utf-8")

    assert "item.extra_args | default([]) is sequence" in tasks
    assert "item.extra_args | default([]) is not string" in tasks
    assert "+ (item.extra_args | default([]))" in tasks


def test_terragrunt_state_migrations_are_explicit_and_non_destructive():
    defaults = yaml.safe_load(
        (ROOT / "roles/terragrunt/defaults/main.yml").read_text(encoding="utf-8")
    )
    tasks = (ROOT / "roles/terragrunt/tasks/main.yml").read_text(encoding="utf-8")

    assert defaults["terragrunt_state_moves"] == []
    assert defaults["terragrunt_state_removals"] == []
    assert defaults["terragrunt_state_migration_strict"] is False
    assert "argv: [terragrunt, state, mv" in tasks
    assert "argv: [terragrunt, state, rm" in tasks
    assert "item.remote_resource_preserved | default(false) | bool" in tasks
    assert "no_log: true" in tasks


def test_terragrunt_provider_lock_upgrade_is_explicitly_opt_in():
    defaults = yaml.safe_load(
        (ROOT / "roles/terragrunt/defaults/main.yml").read_text(encoding="utf-8")
    )
    tasks = (ROOT / "roles/terragrunt/tasks/main.yml").read_text(encoding="utf-8")

    assert defaults["terragrunt_init_upgrade"] is False
    assert "(['-upgrade'] if terragrunt_init_upgrade | bool else [])" in tasks
