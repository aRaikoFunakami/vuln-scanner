"""Self-check for the threat registry (run directly: python3 tests/test_threats.py).

Guards against the `all_packages` regression where a threat with many
`direct_packages` entries (e.g. a mass npm worm) only exposed one of them
for parsing/judgment.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from vuln_scanner.threats import get_all_threats, judge  # noqa: E402
from vuln_scanner.threats.ecosystems.npm import (  # noqa: E402
    parse_package_lock_json,
    parse_pnpm_lock,
)


def main():
    threats = {t.name: t for t in get_all_threats()}

    keyv = threats["keyv"]
    assert len(keyv.all_packages) == 394, len(keyv.all_packages)
    assert judge("keyv", "6.0.0")[0] == "VULNERABLE"
    assert judge("keyv", "5.0.0")[0] == "SAFE"
    assert judge("@crawlee/core", "3.17.1-beta.80")[0] == "VULNERABLE"
    assert judge("cache-manager", "8.0.0")[0] == "SAFE"

    # Regression guard: with 394 packages sharing one threat, a version
    # malicious for package A must not be flagged VULNERABLE for unrelated
    # package B just because the version string happens to collide.
    assert judge("@adminide-stack/clock-tik-browser", "1.81.0")[0] == "SAFE"
    assert judge("@adminide-stack/clock-tik-browser", "12.0.24")[0] == "VULNERABLE"
    assert judge("@7n/rules", "1.81.0")[0] == "VULNERABLE"

    # Regression guard: scoped package names must survive lockfile parsing
    # (package-lock.json v2/v3 and pnpm-lock.yaml both strip everything
    # before the last "/" naively if not handled).
    targets = {"@arv-bedrock/auth", "keyv"}
    lock_json = (
        '{"packages": {'
        '"node_modules/@arv-bedrock/auth": {"version": "1.1.7"}, '
        '"node_modules/keyv": {"version": "6.0.0"}'
        "}}"
    )
    assert set(parse_package_lock_json(lock_json, targets)) == {
        ("@arv-bedrock/auth", "1.1.7"),
        ("keyv", "6.0.0"),
    }
    pnpm_content = "/@arv-bedrock/auth@1.1.7:\n" "/keyv@6.0.0:\n"
    assert set(parse_pnpm_lock(pnpm_content, targets)) == {
        ("@arv-bedrock/auth", "1.1.7"),
        ("keyv", "6.0.0"),
    }

    # Regression guard: single direct_package threats still work.
    axios = threats["axios"]
    assert axios.all_packages == {"axios", "plain-crypto-js"}
    assert judge("axios", "1.14.1")[0] == "VULNERABLE"
    assert judge("plain-crypto-js", None)[0] == "VULNERABLE"

    print("OK")


if __name__ == "__main__":
    main()
