import os
import stat
import subprocess
import sys
from pathlib import Path

from scripts.release_smoke import run_release_smoke_check


def test_run_release_smoke_check_accepts_help_output(tmp_path: Path):
    fake_bin = tmp_path / ("fake-secagent.py" if sys.platform == "win32" else "fake-secagent")
    fake_bin.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('SecAgent 1.0.0')\n"
        "print('usage: fake-secagent [--help] [scan --target TARGET]')\n"
        "sys.exit(0)\n"
    )
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)

    completed = run_release_smoke_check(str(fake_bin), ["--help"], timeout=10)

    assert completed.returncode == 0
    assert "SecAgent" in completed.stdout
    assert "usage" in completed.stdout.lower()


def test_run_release_smoke_check_rejects_nonzero_exit(tmp_path: Path):
    fake_bin = tmp_path / ("bad-secagent.py" if sys.platform == "win32" else "bad-secagent")
    fake_bin.write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('startup failed', file=sys.stderr)\n"
        "sys.exit(2)\n"
    )
    fake_bin.chmod(fake_bin.stat().st_mode | stat.S_IEXEC)

    completed = run_release_smoke_check(str(fake_bin), ["--help"], timeout=10)

    assert completed.returncode == 2
    assert "startup failed" in completed.stderr.lower()
