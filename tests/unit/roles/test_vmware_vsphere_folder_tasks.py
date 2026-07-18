from pathlib import Path
import unittest

import yaml


COLLECTION_ROOT = Path(__file__).resolve().parents[3]
TASKS_DIR = COLLECTION_ROOT / "roles" / "vmware_vsphere" / "tasks"


def _load_tasks(name):
    return yaml.safe_load((TASKS_DIR / name).read_text())


class VmwareVsphereFolderTaskTests(unittest.TestCase):
    def test_folder_entry_points_delegate_to_the_canonical_manager(self):
        entry_points = [
            ("create_folder.yml", "not vmware_vsphere_destroy | bool"),
            ("delete_folder.yml", "vmware_vsphere_destroy | bool"),
        ]

        for entrypoint, expected_condition in entry_points:
            with self.subTest(entrypoint=entrypoint):
                tasks = _load_tasks(entrypoint)

                self.assertEqual(len(tasks), 1)
                self.assertEqual(
                    tasks[0]["ansible.builtin.include_tasks"],
                    "manage_folder.yml",
                )
                self.assertEqual(tasks[0]["when"], [expected_condition])
                self.assertNotIn("vmware.vmware.folder", yaml.safe_dump(tasks))

    def test_canonical_destroy_path_is_ancestry_guarded_and_idempotent(self):
        tasks = _load_tasks("manage_folder.yml")
        validate_task = next(
            task
            for task in tasks
            if task.get("name") == "Validate guarded VM folder deletion target"
        )
        inspect_task = next(
            task
            for task in tasks
            if task.get("name")
            == "Inspect existing VM folders before refusing recursive deletion"
        )
        absent_task = next(
            task
            for task in tasks
            if task.get("name") == "Confirm absent VM folder needs no deletion"
        )

        validation = "\n".join(validate_task["ansible.builtin.assert"]["that"])
        self.assertIn("_vmware_vsphere_folder_delete_root", validation)
        self.assertIn("/[^/]+", validation)
        self.assertIn("'.' not in", validation)
        self.assertIn("'..' not in", validation)
        self.assertIn("community.vmware.vmware_folder_info", inspect_task)
        self.assertIs(inspect_task["changed_when"], False)
        self.assertEqual(
            inspect_task["register"],
            "vmware_vsphere_folder_delete_info",
        )
        response_validation = next(
            task
            for task in tasks
            if task.get("name") == "Validate VM folder inventory response"
        )
        self.assertIn(
            "vmware_vsphere_folder_delete_info.flat_folder_info is defined",
            response_validation["ansible.builtin.assert"]["that"],
        )
        self.assertIn(
            "_vmware_vsphere_folder_delete_matches | length == 0",
            absent_task["when"],
        )

    def test_canonical_destroy_path_refuses_every_existing_folder(self):
        tasks = _load_tasks("manage_folder.yml")
        refusal_task = next(
            task
            for task in tasks
            if task.get("name") == "Refuse recursive VM folder deletion"
        )

        self.assertIn(
            "_vmware_vsphere_folder_delete_matches | length > 0",
            refusal_task["when"],
        )
        self.assertIn("ansible.builtin.fail", refusal_task)
        self.assertIn(
            "recursive",
            refusal_task["ansible.builtin.fail"]["msg"],
        )
        self.assertNotIn(
            "state: absent",
            yaml.safe_dump(tasks),
        )
