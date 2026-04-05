# IAM Analyzer

A security tool built in Go that helps AWS engineers identify and eliminate
excessive IAM permissions before they become a problem.

## The Problem

In AWS, roles accumulate permissions over time. Developers add permissions
"just in case" and nobody removes them. This creates unnecessary risk —
if an attacker compromises a role, they get access to everything that role
was ever granted, not just what it actually needs.

## What This Tool Does

IAM Analyzer compares what a role **has** vs what it **actually uses**,
then tells you exactly what to remove.

- Reads all IAM role policies from AWS
- Pulls CloudTrail logs to see real usage over the last N days
- Calculates a risk score (0-100) based on unused and dangerous permissions
- Shows the last time each permission was used
- Generates an HTML report you can share with your team
- Suggests a minimal least-privilege policy

## How It Works

AWS IAM ──────────────┐
├──→ Analyzer → Risk Score → HTML Report
AWS CloudTrail ────────┘

## Tech Stack

- **Go** — fast, statically typed, great for CLI tools
- **AWS SDK v2** — official AWS SDK for Go
- **CloudTrail** — audit log of every AWS API call
- **Cobra** — CLI framework

## Quick Start

```bash
# Clone the repo
git clone https://github.com/bathed/iam-analyzer.git
cd iam-analyzer

# Install dependencies
go mod tidy

# List all roles in your AWS account
go run ./cmd list-roles

# Analyze a specific role
go run ./cmd analyze --role my-role

# Generate HTML report
go run ./cmd analyze --role my-role --html report.html

# Analyze last 90 days
go run ./cmd analyze --role my-role --days 90
```

## Example Output

================================================
IAM ANALYZER - test-analyzer-role
Role: test-analyzer-role
Risk Score: 100/100 🔴 HIGH - remove unused permissions immediately!
Total permissions: 2
Used: 0
Unused: 2
Unused permissions (remove):

s3:_
s3-object-lambda:_
================================================

## Required AWS Permissions

Your AWS user needs read-only access:

```json
{
  "Effect": "Allow",
  "Action": [
    "iam:GetRole",
    "iam:ListRoles",
    "iam:GetRolePolicy",
    "iam:ListRolePolicies",
    "iam:ListAttachedRolePolicies",
    "iam:GetPolicy",
    "iam:GetPolicyVersion",
    "cloudtrail:LookupEvents"
  ],
  "Resource": "*"
}
```
