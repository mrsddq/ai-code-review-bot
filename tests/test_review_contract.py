import json
import subprocess
import sys

import pytest

from code_review_bot.reporters import json_report
from code_review_bot.reviewer import review_path, review_source


def test_missing_path_fails_instead_of_reporting_clean(tmp_path):
    with pytest.raises(FileNotFoundError):
        review_path(tmp_path / "absent")
    result = subprocess.run([sys.executable, "-m", "code_review_bot.cli", str(tmp_path / "absent")],
                            capture_output=True, text=True)
    assert result.returncode == 2
    assert "No findings" not in result.stdout


def test_hidden_parent_does_not_hide_explicit_review_root(tmp_path):
    root = tmp_path / ".checkout" / "project"
    root.mkdir(parents=True)
    (root / "app.py").write_text("eval(value)\n")
    assert review_path(root)[0].rule == "CRB001"


def test_secret_assignment_cannot_be_hidden_by_test_comment():
    secret = "abcd1234567890"
    findings = review_source(f'api_key: str = "{secret}" # test example\n')
    assert any(item.rule == "CRB006" for item in findings)
    assert secret not in json_report(findings)


def test_comments_are_not_executable_secret_assignments():
    assert review_source('# password = "some-long-example"\n') == []


def test_multiline_assignment_is_detected():
    assert review_source('token = (\n "long-value-here"\n)\n')[0].rule == "CRB006"


def test_symlink_does_not_expand_review_scope(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    external = tmp_path / "outside.py"
    external.write_text("eval(value)\n")
    (root / "link.py").symlink_to(external)
    assert review_path(root) == []


def test_unreadable_source_is_a_high_severity_finding(tmp_path):
    path = tmp_path / "binary.py"
    path.write_bytes(b"\xff\xfe")
    findings = review_path(path)
    assert findings[0].rule == "CRB999"
    assert json.loads(json_report(findings))["findings"][0]["severity"] == "high"


@pytest.mark.parametrize("target", ["self.api_key", "settings.password", "accessToken", "databasePassword", "self.accessToken: str"])
def test_attribute_and_camelcase_credentials_are_detected(target):
    findings = review_source(f'{target} = "abcdefgh12345"\n')
    assert any(item.rule == "CRB006" for item in findings)
