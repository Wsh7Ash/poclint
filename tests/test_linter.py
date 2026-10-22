from poclint.linter import lint_report
def test_missing_sections():
    issues = lint_report({})
    assert any('missing section' in i for i in issues)
def test_severity_mismatch():
    r = {'title':'t','description':'d','poc':'p','impact':'i','remediation':'r','cvss_vector':'CVSS:3.1/AV:N/AC:L','cvss_base':9.8,'claimed_severity':'LOW'}
    issues = lint_report(r)
    assert any('inconsistent' in i for i in issues)
