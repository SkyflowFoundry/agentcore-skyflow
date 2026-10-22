"""The CDK stack turns log terms into metrics and alarms; the code must emit them.

A metric filter on a term nothing logs is an alarm that can never fire, and
nothing else would notice. This reads the terms from the stack source and
checks each one is logged somewhere in the Lambda source.

Run: python3 gateway/interceptor/tests/test_metric_terms.py
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STACK = ROOT / "cdk" / "lib" / "interceptor-stack.ts"
SRC = ROOT / "src"


def metric_terms() -> dict[str, list[str]]:
    """`{metric: [log terms]}` from the METRICS table in the stack."""
    source = STACK.read_text()
    table = source[source.index("const METRICS"):source.index("];", source.index("const METRICS"))]
    rows = re.findall(r"\['(\w+)',\s*\[([^\]]*)\]", table)
    return {name: re.findall(r"'([a-z_]+)'", terms) for name, terms in rows}


class MetricTermsTestCase(unittest.TestCase):
    def test_the_table_was_found(self):
        terms = metric_terms()
        self.assertIn("FailClosed", terms)
        self.assertIn("PolicyUnavailable", terms)

    def test_every_term_is_logged_by_the_lambda(self):
        logged = "\n".join(path.read_text() for path in SRC.glob("*.py"))
        for metric, terms in metric_terms().items():
            for term in terms:
                with self.subTest(metric=metric, term=term):
                    self.assertRegex(logged, rf'"{term}[ "]', f"{term} feeds {metric} but nothing logs it")


if __name__ == "__main__":
    unittest.main(verbosity=2)
