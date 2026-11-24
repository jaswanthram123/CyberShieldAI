
from functools import lru_cache
from pathlib import Path

import yara

BASE_DIR = Path(__file__).resolve().parent
RULES_PATH = (
    BASE_DIR / "yara_rules" / "cybershield_rules.yar"
)

MAX_SIZE = 10 * 1024 * 1024

SEVERITY_SCORES = {
    "low": 10,
    "medium": 40,
    "high": 70,
}


@lru_cache(maxsize=1)
def load_rules():
    return yara.compile(filepath=str(RULES_PATH))


def scan_with_yara(data: bytes):
    if not data:
        raise ValueError("File cannot be empty")

    if len(data) > MAX_SIZE:
        raise ValueError("Maximum file size is 10 MB")

    try:
        rules = load_rules()

        matches = rules.match(
            data=data,
            timeout=5,
        )

    except yara.TimeoutError:
        return {
            "status": "TIMEOUT",
            "matches": [],
            "score": 0,
            "error": "YARA scan exceeded its time limit",
        }

    except (yara.Error, OSError) as error:
        return {
            "status": "ERROR",
            "matches": [],
            "score": 0,
            "error": str(error),
        }

    findings = []
    scores = []

    for match in matches:
        severity = str(
            match.meta.get("severity", "low")
        ).lower()

        score = SEVERITY_SCORES.get(severity, 10)

        findings.append({
            "rule": match.rule,
            "description": str(
                match.meta.get(
                    "description",
                    "YARA rule matched",
                )
            ),
            "severity": severity,
            "score": score,
        })

        scores.append(score)

    return {
        "status": "COMPLETED",
        "matches": findings,
        "score": max(scores, default=0),
        "error": None,
    }
