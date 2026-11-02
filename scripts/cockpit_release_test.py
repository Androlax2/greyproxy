"""Offline contracts for the fork's Linux release workflow and archive script."""
import hashlib
import itertools
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class LinuxReleaseTests(unittest.TestCase):
    def test_workflow_gates_and_payload(self):
        workflow = (ROOT / '.github/workflows/cockpit-release.yml').read_text()
        smoke = workflow.split('\n  smoke-test:\n', 1)[1].split('\n  release:\n', 1)[0]
        self.assertEqual(re.findall(r'- target: (.+)', smoke), ['linux-amd64', 'linux-arm64'])
        release = workflow.split('\n  release:\n', 1)[1]
        self.assertIn('needs: [build, smoke-test]', release)
        condition = re.search(r'^    if: (.+)$', release, re.M)[1]
        for event, build, smoke in itertools.product(
                ['push', 'pull_request'],
                ['success', 'failure', 'cancelled', 'skipped', ''],
                ['success', 'failure', 'cancelled', 'skipped', '']):
            expression = condition
            for key, value in {'github.event_name': event, 'needs.build.result': build,
                               'needs.smoke-test.result': smoke}.items():
                expression = expression.replace(key, repr(value))
            result = subprocess.run(['bash', '-c', '[[ ' + expression + ' ]]'], capture_output=True)
            self.assertEqual(result.returncode == 0,
                             event == 'push' and build == 'success' and smoke == 'success',
                             (event, build, smoke, condition))
        self.assertRegex(release, r'uses: actions/attest-build-provenance@[^\n]+\n        with:\n          subject-path: dist/\*-linux-\*.tar.gz')
        self.assertIn('gh release create "$RELEASE_NAME" dist/*-linux-*.tar.gz dist/SHA256SUMS', release)
        self.assertIn('macOS delivery is deferred', release)
        self.assertIn('--verify-tag --latest=false', release)

    def test_archive_payload_and_checksums(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            def run(*args, **kwargs):
                return subprocess.run(args, cwd=work, check=True, capture_output=True, **kwargs)
            (work / 'release.sh').write_bytes((ROOT / 'scripts/cockpit-release.sh').read_bytes())
            (work / 'LICENSE').write_text('fixture license\n')
            run('git', 'init', '-q')
            run('git', 'add', '.')
            run('git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture')
            (work / 'dist').mkdir()
            (work / 'dist/greyproxy-v0.4.5-cockpit.99-darwin-arm64.tar.gz').write_bytes(b'stale')
            (work / 'bin').mkdir()
            # Stub only compilation; exercise real Git, tar, gzip and checksums.
            (work / 'bin/go').write_text('''#!/bin/bash
set -eu
[[ $CGO_ENABLED == 0 && $GOOS == linux && ( $GOARCH == amd64 || $GOARCH == arm64 ) ]]
while [[ $1 != -o ]]; do shift; done
printf 'fixture binary %s/%s\\n' "$GOOS" "$GOARCH" > "$2"
''')
            (work / 'bin/go').chmod(0o755)
            run('bash', 'release.sh', 'v0.4.5-cockpit.99', '0.4.5', 'dist',
                env={**os.environ, 'PATH': str(work / 'bin') + ':' + os.environ['PATH']})
            dist = work / 'dist'
            expected = {f'greyproxy-v0.4.5-cockpit.99-linux-{arch}.tar.gz' for arch in ['amd64', 'arm64']}
            self.assertEqual({p.name for p in dist.iterdir()}, expected | {'SHA256SUMS', 'greyproxy-v0.4.5-cockpit.99-darwin-arm64.tar.gz'})
            sums = dict(line.split('  ', 1)[::-1] for line in (dist / 'SHA256SUMS').read_text().splitlines())
            self.assertEqual(set(sums), expected)
            for name in expected:
                self.assertEqual(hashlib.sha256((dist / name).read_bytes()).hexdigest(), sums[name])
                with tarfile.open(dist / name) as archive:
                    self.assertEqual(set(archive.getnames()), {'greyproxy', 'LICENSE'})
                    self.assertEqual(archive.extractfile('LICENSE').read(), b'fixture license\n')


if __name__ == '__main__':
    unittest.main()
