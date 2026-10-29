"""Build and exercise the installed distribution outside the source checkout."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="compliancekit-release-") as directory:
        work = Path(directory)
        subprocess.run(
            [sys.executable, "-m", "pip", "wheel", "--no-deps", str(ROOT), "-w", str(work)],
            check=True,
        )
        wheels = list(work.glob("compliancekit-*.whl"))
        if len(wheels) != 1:
            raise RuntimeError("Expected exactly one built distribution.")
        target = work / "installed"
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-deps", "--target", str(target),
             str(wheels[0])], check=True,
        )
        entry = (
            f"import sys; sys.path.insert(0, {str(target)!r}); "
            "from compliancekit.cli import main; raise SystemExit(main())"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-S", "-c", entry, "--json"],
            input="Contact synthetic@example.test", text=True, capture_output=True, cwd=work, check=True,
        )
        payload = json.loads(result.stdout)
        if payload["summary"]["total_findings"] != 1 or "synthetic@example.test" in result.stdout:
            raise RuntimeError("Installed CLI failed detection or masking.")
        failure = subprocess.run(
            [sys.executable, "-I", "-S", "-c", entry, "--file", str(work / "missing.txt")],
            text=True, capture_output=True, cwd=work, check=False,
        )
        if failure.returncode != 2 or "Traceback" in failure.stderr:
            raise RuntimeError("Installed CLI failed its missing-file contract.")
        print("Built wheel installed cleanly; CLI detection, masking and failure handling passed.")


if __name__ == "__main__":
    main()
