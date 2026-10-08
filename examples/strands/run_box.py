"""Explicit optional Strands Box launch support, macOS only.

Operator-approved configuration controls the agent command and policy. This is
not the RVM VerifiedPackage execution path and makes no RVM isolation claim.
Protect the binary, config, policy and their parent directories against writes
by untrusted workloads; digest checks alone cannot prevent filesystem races.
"""
import argparse
import hashlib
import platform
import subprocess
import tomllib
from pathlib import Path


def checked_file(path, expected):
    path = Path(path).resolve(strict=True)
    if len(expected) != 64 or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise ValueError("SHA-256 mismatch for " + str(path))
    return path


def plan(binary, config, binary_sha256, config_sha256, policy_sha256):
    if platform.system() != "Darwin":
        raise RuntimeError("the supported Strands Box release requires macOS; no fallback")
    binary = checked_file(binary, binary_sha256)
    config = checked_file(config, config_sha256)
    data = tomllib.loads(config.read_text())
    policy = data.get("policy")
    if not isinstance(policy, str) or not policy:
        raise ValueError("an explicit policy file is required")
    checked_file(config.parent / policy, policy_sha256)
    if not data.get("agent", {}).get("command"):
        raise ValueError("an explicit agent command is required")
    # No shell interpretation, download, automatic upgrade, or alternate runner.
    return [str(binary), "run", "--config", str(config)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("binary", "config", "binary-sha256", "config-sha256", "policy-sha256"):
        parser.add_argument("--" + key, required=True)
    parser.add_argument("--execute", action="store_true", help="run the reviewed configuration")
    args = parser.parse_args()
    command = plan(args.binary, args.config, args.binary_sha256,
                   args.config_sha256, args.policy_sha256)
    if args.execute:
        # Box owns credential binding, child environments and containment.
        # Inherit the operator environment only into the trusted Box process.
        return subprocess.run(command, check=False).returncode
    import json
    print(json.dumps({"argv": command, "executed": False, "isolation_verified": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
