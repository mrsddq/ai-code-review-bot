import json

from code_review_bot.reporters import sarif_report
from code_review_bot.reviewer import review_source


def test_detects_high_risk_execution():
    source = """
import subprocess
def run(command):
    eval(command)
    subprocess.run(command, shell=True)
"""
    rules = {finding.rule for finding in review_source(source)}
    assert {"CRB001", "CRB002"}.issubset(rules)


def test_detects_mutable_default_and_bare_except():
    source = """
def add(value, values=[]):
    try:
        values.append(value)
    except:
        pass
"""
    rules = {finding.rule for finding in review_source(source)}
    assert {"CRB003", "CRB004"}.issubset(rules)


def test_clean_code_has_no_findings():
    assert review_source("def double(value: int) -> int:\n    return value * 2\n") == []


def test_sarif_is_valid_json():
    findings = review_source("eval(user_input)\n", "app.py")
    document = json.loads(sarif_report(findings))
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["ruleId"] == "CRB001"

