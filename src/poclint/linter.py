REQUIRED_SECTIONS = ['title', 'description', 'poc', 'impact', 'remediation']

def lint_report(report):
    issues = []
    for sec in REQUIRED_SECTIONS:
        if not report.get(sec):
            issues.append(f'missing section: {sec}')
    cvss = report.get('cvss_vector', '')
    if cvss and not cvss.startswith('CVSS:3.1/'):
        issues.append('cvss vector missing CVSS:3.1 prefix')
    if 'production-ready' in report.get('description', '').lower():
        issues.append('unsupported claim in description')
    severity = report.get('claimed_severity', '')
    base = report.get('cvss_base', None)
    if base is not None and severity:
        bands = [('CRITICAL', 9.0), ('HIGH', 7.0), ('MEDIUM', 4.0), ('LOW', 0.0)]
        expected = next(name for name, floor in bands if base >= floor)
        if expected != severity.upper():
            issues.append(f'severity {severity} inconsistent with base {base} (expected {expected})')
    return issues
