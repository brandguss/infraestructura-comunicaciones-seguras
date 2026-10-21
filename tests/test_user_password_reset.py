"""Pruebas del restablecimiento seguro de una contraseña."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.comunicaciones_seguras.auth import AccessController, make_user_record
from src.comunicaciones_seguras.user_password_reset import reset_password


class PasswordResetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "users.json"
        self.records = [
            make_user_record("admin", "administrador", "old-admin-password"),
            make_user_record("consulta", "consulta", "consulta-password"),
        ]
        self.path.write_text(json.dumps({"users": self.records}, indent=2), encoding="utf-8")

    def test_resets_only_requested_user_and_keeps_backup(self) -> None:
        backup = reset_password(self.path, "admin", "new-admin-password")
        self.assertTrue(backup.is_file())
        original = json.loads(backup.read_text(encoding="utf-8"))
        updated = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertEqual(original["users"], self.records)
        self.assertEqual([item["username"] for item in updated["users"]], ["admin", "consulta"])
        controller = AccessController.from_file(self.path)
        self.assertEqual(controller.authenticate("admin", "new-admin-password").role, "administrador")
        self.assertEqual(controller.authenticate("consulta", "consulta-password").role, "consulta")

    def test_unknown_user_does_not_modify_file(self) -> None:
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            reset_password(self.path, "missing", "some-password")
        self.assertEqual(self.path.read_bytes(), before)

    def test_empty_password_does_not_modify_file(self) -> None:
        before = self.path.read_bytes()
        with self.assertRaises(ValueError):
            reset_password(self.path, "admin", "")
        self.assertEqual(self.path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
