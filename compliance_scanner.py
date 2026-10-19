import boto3
import json
import markdown
import re
import os
from datetime import datetime, timezone

# AWS clients
iam = boto3.client('iam', region_name='eu-west-2')
s3 = boto3.client('s3', region_name='eu-west-2')
cloudtrail = boto3.client('cloudtrail', region_name='eu-west-2')
guardduty = boto3.client('guardduty', region_name='eu-west-2')
bedrock = boto3.client('bedrock-runtime', region_name='eu-west-2')
ec2 = boto3.client('ec2', region_name='eu-west-2')

# Bedrock model
MODEL_ID = 'eu.anthropic.claude-haiku-4-5-20251001-v1:0'

def get_timestamp():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

def clean_ai_response(text):
    clean = re.sub(r'[^\x00-\x7F]+', '', text)
    return markdown.markdown(clean)

# CIS benchmark check results
checks = []

def add_check(control_id, title, status, risk, detail):
    # Standardised format for every compliance check
    checks.append({
        'ControlID': control_id,
        'Title': title,
        'Status': status,  # PASS or FAIL
        'Risk': risk,       # CRITICAL, HIGH, MEDIUM, LOW
        'Detail': detail,
        'Timestamp': get_timestamp()
    })

def check_iam_password_policy():
    # CIS 1.8 - Ensure IAM password policy requires minimum length of 14
    # CIS 1.9 - Ensure IAM password policy prevents password reuse
    try:
        policy = iam.get_account_password_policy()['PasswordPolicy']
        
        # Check minimum password length
        if policy.get('MinimumPasswordLength', 0) >= 14:
            add_check('CIS-1.8', 'Password minimum length 14+', 'PASS', 'LOW',
                     f"Minimum length is {policy['MinimumPasswordLength']}")
        else:
            add_check('CIS-1.8', 'Password minimum length 14+', 'FAIL', 'MEDIUM',
                     f"Minimum length is only {policy.get('MinimumPasswordLength', 'not set')}")
        
        # Check password reuse prevention
        if policy.get('PasswordReusePrevention', 0) >= 24:
            add_check('CIS-1.9', 'Password reuse prevention 24+', 'PASS', 'LOW',
                     f"Reuse prevention set to {policy['PasswordReusePrevention']}")
        else:
            add_check('CIS-1.9', 'Password reuse prevention 24+', 'FAIL', 'MEDIUM',
                     f"Reuse prevention is {policy.get('PasswordReusePrevention', 'not set')}")
        
        # Check password expiry
        if policy.get('MaxPasswordAge', 999) <= 90:
            add_check('CIS-1.11', 'Password expiry 90 days or less', 'PASS', 'LOW',
                     f"Password expires every {policy['MaxPasswordAge']} days")
        else:
            add_check('CIS-1.11', 'Password expiry 90 days or less', 'FAIL', 'MEDIUM',
                     f"Password expiry is {policy.get('MaxPasswordAge', 'not set')} days")
                     
    except iam.exceptions.NoSuchEntityException:
        add_check('CIS-1.8', 'Password minimum length 14+', 'FAIL', 'HIGH',
                 'No password policy exists')
        add_check('CIS-1.9', 'Password reuse prevention 24+', 'FAIL', 'HIGH',
                 'No password policy exists')
        add_check('CIS-1.11', 'Password expiry 90 days or less', 'FAIL', 'HIGH',
                 'No password policy exists')

def check_root_mfa():
    # CIS 1.5 - Ensure MFA is enabled for root account
    try:
        summary = iam.get_account_summary()['SummaryMap']
        if summary.get('AccountMFAEnabled', 0) == 1:
            add_check('CIS-1.5', 'Root account MFA enabled', 'PASS', 'LOW',
                     'Root account has MFA enabled')
        else:
            add_check('CIS-1.5', 'Root account MFA enabled', 'FAIL', 'CRITICAL',
                     'Root account does not have MFA enabled')
    except Exception as e:
        add_check('CIS-1.5', 'Root account MFA enabled', 'ERROR', 'UNKNOWN', str(e))

def check_user_mfa():
    # CIS 1.10 - Ensure MFA is enabled for all IAM users with console access
    try:
        paginator = iam.get_paginator('list_users')
        users_without_mfa = []
        
        for page in paginator.paginate():
            for user in page['Users']:
                # Only check users with console access
                try:
                    iam.get_login_profile(UserName=user['UserName'])
                    mfa = iam.list_mfa_devices(UserName=user['UserName'])
                    if not mfa['MFADevices']:
                        users_without_mfa.append(user['UserName'])
                except iam.exceptions.NoSuchEntityException:
                    pass  # No console access, skip
        
        if not users_without_mfa:
            add_check('CIS-1.10', 'MFA enabled for all console users', 'PASS', 'LOW',
                     'All console users have MFA enabled')
        else:
            add_check('CIS-1.10', 'MFA enabled for all console users', 'FAIL', 'HIGH',
                     f"Users without MFA: {', '.join(users_without_mfa)}")
    except Exception as e:
        add_check('CIS-1.10', 'MFA enabled for all console users', 'ERROR', 'UNKNOWN', str(e))

def check_cloudtrail():
    # CIS 3.1 - Ensure CloudTrail is enabled in all regions
    # CIS 3.2 - Ensure CloudTrail log file validation is enabled
    try:
        trails = cloudtrail.describe_trails(includeShadowTrails=False)['trailList']
        
        if not trails:
            add_check('CIS-3.1', 'CloudTrail enabled', 'FAIL', 'CRITICAL',
                     'No CloudTrail trails found')
            return
        
        multi_region = [t for t in trails if t.get('IsMultiRegionTrail', False)]
        if multi_region:
            add_check('CIS-3.1', 'CloudTrail multi-region enabled', 'PASS', 'LOW',
                     f"Multi-region trail: {multi_region[0]['Name']}")
        else:
            add_check('CIS-3.1', 'CloudTrail multi-region enabled', 'FAIL', 'HIGH',
                     'No multi-region trail found')
        
        # Check log file validation
        validated = [t for t in trails if t.get('LogFileValidationEnabled', False)]
        if validated:
            add_check('CIS-3.2', 'CloudTrail log validation enabled', 'PASS', 'LOW',
                     'Log file validation is enabled')
        else:
            add_check('CIS-3.2', 'CloudTrail log validation enabled', 'FAIL', 'MEDIUM',
                     'Log file validation is not enabled')
                     
    except Exception as e:
        add_check('CIS-3.1', 'CloudTrail enabled', 'ERROR', 'UNKNOWN', str(e))

def check_s3_public_access():
    # CIS 2.1.5 - Ensure S3 account level public access block is enabled
    try:
        s3control = boto3.client('s3control', region_name='eu-west-2')
        account_id = boto3.client('sts').get_caller_identity()['Account']
        
        response = s3control.get_public_access_block(AccountId=account_id)
        config = response['PublicAccessBlockConfiguration']
        
        all_blocked = all([
            config.get('BlockPublicAcls', False),
            config.get('BlockPublicPolicy', False),
            config.get('IgnorePublicAcls', False),
            config.get('RestrictPublicBuckets', False)
        ])
        
        if all_blocked:
            add_check('CIS-2.1.5', 'S3 account public access block', 'PASS', 'LOW',
                     'All S3 public access block settings enabled')
        else:
            add_check('CIS-2.1.5', 'S3 account public access block', 'FAIL', 'HIGH',
                     'S3 account public access block not fully enabled')
                     
    except Exception as e:
        add_check('CIS-2.1.5', 'S3 account public access block', 'ERROR', 'UNKNOWN', str(e))

def check_guardduty():
    # CIS 4.15 - Ensure GuardDuty is enabled
    try:
        detectors = guardduty.list_detectors()
        if detectors['DetectorIds']:
            detector = guardduty.get_detector(DetectorId=detectors['DetectorIds'][0])
            if detector['Status'] == 'ENABLED':
                add_check('CIS-4.15', 'GuardDuty enabled', 'PASS', 'LOW',
                         'GuardDuty is active and monitoring')
            else:
                add_check('CIS-4.15', 'GuardDuty enabled', 'FAIL', 'HIGH',
                         'GuardDuty detector exists but is disabled')
        else:
            add_check('CIS-4.15', 'GuardDuty enabled', 'FAIL', 'HIGH',
                     'No GuardDuty detectors found')
    except Exception as e:
        add_check('CIS-4.15', 'GuardDuty enabled', 'ERROR', 'UNKNOWN', str(e))

def get_ai_recommendations():
    # Use Bedrock to analyse compliance failures and prioritise remediation
    failures = [c for c in checks if c['Status'] == 'FAIL']
    
    if not failures:
        return "All checks passed - environment meets CIS benchmark requirements."
    
    summary = []
    for f in failures:
        summary.append(f"[{f['Risk']}] {f['ControlID']} - {f['Title']}: {f['Detail']}")
    
    prompt = f"""You are a cloud security compliance engineer reviewing CIS AWS Foundations 
Benchmark results.

Failed controls:

{chr(10).join(summary)}

Provide:
1. Compliance risk summary in two sentences
2. Top 3 remediation steps in priority order with exact AWS console steps
3. Which failures represent the most urgent risk and why
4. Estimated time to remediate all failures

Be specific and direct."""

    try:
        response = bedrock.invoke_model(
            modelId=MODEL_ID,
            body=json.dumps({
                'anthropic_version': 'bedrock-2023-05-31',
                'max_tokens': 1000,
                'messages': [{'role': 'user', 'content': prompt}]
            })
        )
        result = json.loads(response['body'].read())
        return clean_ai_response(result['content'][0]['text'])
    except Exception as e:
        print(f"Bedrock error: {e}")
        return "AI recommendations unavailable"

def generate_report(ai_recommendations):
    # Generate HTML compliance report
    os.makedirs('reports', exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"reports/compliance_report_{timestamp}.html"
    
    passed = [c for c in checks if c['Status'] == 'PASS']
    failed = [c for c in checks if c['Status'] == 'FAIL']
    errors = [c for c in checks if c['Status'] == 'ERROR']
    
    score = int((len(passed) / len(checks)) * 100) if checks else 0
    
    if score >= 80:
        score_color = '#44bb44'
    elif score >= 60:
        score_color = '#f0b400'
    else:
        score_color = '#ff4444'
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CIS Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }}
        h1, h2 {{ color: #00d4ff; }}
        h2 {{ border-bottom: 1px solid #333; padding-bottom: 8px; }}
        .score {{ font-size: 72px; font-weight: bold; color: {score_color}; text-align: center; }}
        .score-label {{ text-align: center; color: #888; margin-bottom: 20px; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin: 20px 0; }}
        .metric {{ background: #16213e; padding: 20px; border-radius: 8px; text-align: center; }}
        .metric-value {{ font-size: 36px; font-weight: bold; }}
        .pass {{ color: #44bb44; }}
        .fail {{ color: #ff4444; }}
        .error {{ color: #888; }}
        .check {{ background: #16213e; border-left: 4px solid #444; margin: 8px 0; padding: 12px; border-radius: 4px; }}
        .check.PASS {{ border-left-color: #44bb44; }}
        .check.FAIL {{ border-left-color: #ff4444; }}
        .check.CRITICAL {{ border-left-color: #ff0000; }}
        .check.HIGH {{ border-left-color: #ff9900; }}
        .risk-badge {{ padding: 2px 8px; border-radius: 12px; font-size: 12px; margin-left: 8px; background: #333; }}
        .ai-box {{ background: #0f3460; border-left: 4px solid #00d4ff; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .timestamp {{ color: #888; font-size: 12px; }}
        .control-id {{ color: #00d4ff; font-weight: bold; margin-right: 8px; }}
    </style>
</head>
<body>
    <h1>CIS AWS Foundations Benchmark Report</h1>
    <p class="timestamp">Generated: {get_timestamp()}</p>
    
    <div class="score">{score}%</div>
    <div class="score-label">Compliance Score ({len(passed)}/{len(checks)} controls passing)</div>
    
    <div class="summary-grid">
        <div class="metric">
            <div class="metric-value pass">{len(passed)}</div>
            <div>Passed</div>
        </div>
        <div class="metric">
            <div class="metric-value fail">{len(failed)}</div>
            <div>Failed</div>
        </div>
        <div class="metric">
            <div class="metric-value error">{len(errors)}</div>
            <div>Errors</div>
        </div>
    </div>
    
    <div class="ai-box">
        <h2>AI Remediation Recommendations</h2>
        {ai_recommendations}
    </div>
    
    <h2>Failed Controls ({len(failed)})</h2>"""

    for c in failed:
        html += f"""
    <div class="check FAIL">
        <span class="control-id">{c['ControlID']}</span>
        <strong>{c['Title']}</strong>
        <span class="risk-badge">{c['Risk']}</span>
        <p>{c['Detail']}</p>
        <p class="timestamp">{c['Timestamp']}</p>
    </div>"""

    html += f"<h2>Passed Controls ({len(passed)})</h2>"
    
    for c in passed:
        html += f"""
    <div class="check PASS">
        <span class="control-id">{c['ControlID']}</span>
        <strong>{c['Title']}</strong>
        <p>{c['Detail']}</p>
    </div>"""

    html += "</body></html>"
    
    with open(filename, 'w') as f:
        f.write(html)
    
    print(f"Report saved to: {filename}")
    return filename

if __name__ == "__main__":
    print("=== CIS AWS Foundations Compliance Scanner ===")
    print(f"Running at: {get_timestamp()}\n")
    
    print("Running IAM checks...")
    check_iam_password_policy()
    check_root_mfa()
    check_user_mfa()
    
    print("Running CloudTrail checks...")
    check_cloudtrail()
    
    print("Running S3 checks...")
    check_s3_public_access()
    
    print("Running GuardDuty checks...")
    check_guardduty()
    
    # Summary
    passed = [c for c in checks if c['Status'] == 'PASS']
    failed = [c for c in checks if c['Status'] == 'FAIL']
    
    print(f"\nResults: {len(passed)} passed, {len(failed)} failed")
    
    print("\nGetting AI recommendations...")
    recommendations = get_ai_recommendations()
    
    print("Generating report...")
    report_file = generate_report(recommendations)
    
    score = int((len(passed) / len(checks)) * 100) if checks else 0
    print(f"\nCompliance Score: {score}%")
    print(f"Report: {report_file}")

