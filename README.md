# CIS AWS Foundations Compliance Scanner

A Python tool that automatically audits an AWS account against CIS 
AWS Foundations Benchmark controls, generates a compliance score, 
and uses AI to provide prioritised remediation guidance.

## Benchmark scope

This scanner implements a selected subset of CIS AWS Foundations 
Benchmark controls. It does not claim full benchmark compliance.
A 100% score means all nine implemented controls passed - not that 
the account meets the complete CIS standard.

Controls implemented:

| Control ID | Title | Pass condition |
|------------|-------|----------------|
| CIS-1.5 | Root account MFA | MFA device assigned to root |
| CIS-1.8 | Password minimum length | Policy requires 14+ characters |
| CIS-1.9 | Password reuse prevention | Policy prevents reuse of 24+ passwords |
| CIS-1.10 | Console user MFA | All users with console access have MFA |
| CIS-1.11 | Password expiry | Policy sets expiry at 90 days or less |
| CIS-3.1 | CloudTrail multi-region | At least one multi-region trail exists |
| CIS-3.2 | CloudTrail log validation | Log file validation enabled on trail |
| CIS-2.1.5 | S3 public access block | All four account-level block settings enabled |
| CIS-4.15 | GuardDuty enabled | Detector exists and status is ENABLED |

## Required permissions

The scanner requires read-only access. Minimum IAM permissions:

- iam:GetAccountPasswordPolicy
- iam:GetAccountSummary
- iam:ListUsers
- iam:GetLoginProfile
- iam:ListMFADevices
- cloudtrail:DescribeTrails
- s3:GetAccountPublicAccessBlock
- guardduty:ListDetectors
- guardduty:GetDetector

## Error handling and scoring

The compliance score is calculated as passed checks divided by 
total checks. If a check returns an ERROR status due to missing 
permissions or an API failure, it is counted in the denominator 
but not as a pass. This means an error can lower the score without 
indicating a genuine misconfiguration.

Always review ERROR results separately - they indicate the scanner 
could not assess that control, not that the control passed or failed.

## Why I built this

Compliance frameworks like CIS, SOC 2, and ISO 27001 are central 
to cloud security work in regulated industries. Most tools that 
check compliance are expensive commercial products. I wanted to 
build something that demonstrates understanding of the controls 
themselves rather than just knowing how to run a commercial scanner.

The before and after story is the point - the scanner identified 
two real failures (root MFA and admin user MFA), generated exact 
remediation steps, and confirmed 100% compliance after fixes were 
applied. That is the workflow a security engineer runs in practice.

## Tech used

- Python 3
- boto3 (AWS SDK)
- AWS IAM
- AWS CloudTrail
- AWS S3
- AWS GuardDuty
- AWS Bedrock (Claude Haiku) for AI remediation guidance

## How to run it

Configure AWS CLI with appropriate permissions, then:

pip install boto3 markdown
python3 compliance_scanner.py

Reports are saved to the reports/ folder. The HTML report includes 
a compliance score, all failed controls with risk ratings, and AI 
generated remediation steps.

## Example results

Initial scan: 77% compliance score - identified root account MFA 
and admin user MFA as failures with CRITICAL risk rating.

After remediation: 100% compliance score across all nine controls.

The AI remediation output included exact AWS console steps, time 
estimates per fix, and a prioritised order of remediation based 
on risk impact.

## Connection to other projects

This scanner complements the other tools in this portfolio:

- The IAM Security Auditor checks individual user configurations
- The Threat Detection Pipeline monitors CloudTrail in real time
- The Secure Infrastructure Baseline provisions compliant 
  infrastructure via Terraform
- This scanner validates the overall compliance posture and 
  confirms the baseline controls are working

## What's next

Planning to add more CIS controls covering VPC configuration, 
S3 bucket encryption, KMS key rotation, and Security Hub 
integration for centralised compliance tracking.
