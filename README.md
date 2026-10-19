# CIS AWS Foundations Compliance Scanner

A Python tool that automatically audits an AWS account against CIS 
AWS Foundations Benchmark controls, generates a compliance score, 
and uses AI to provide prioritised remediation guidance.

## What it does

Runs automated checks across nine CIS benchmark controls covering:

### IAM Controls
- CIS 1.5 - Root account MFA enabled
- CIS 1.8 - Password minimum length 14 or more
- CIS 1.9 - Password reuse prevention 24 or more
- CIS 1.10 - MFA enabled for all console users
- CIS 1.11 - Password expiry 90 days or less

### Logging Controls
- CIS 3.1 - CloudTrail multi-region trail enabled
- CIS 3.2 - CloudTrail log file validation enabled

### Storage Controls
- CIS 2.1.5 - S3 account level public access block enabled

### Detection Controls
- CIS 4.15 - GuardDuty enabled and active

Generates a compliance score, dark-themed HTML report, and uses 
AWS Bedrock to provide step-by-step remediation guidance for 
every failed control.

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
