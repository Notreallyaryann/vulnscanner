---
name: auditing-infrastructure-as-code
description: Audit Terraform, CloudFormation, and Kubernetes manifests for cloud misconfigurations, overly permissive IAM, public storage buckets, and unencrypted databases.
---

# Auditing Infrastructure as Code (IaC)

## Purpose
Scan Infrastructure-as-Code (IaC) definitions (Terraform `.tf`, CloudFormation, Kubernetes `.yaml`) to identify security misconfigurations prior to cloud deployment, such as public S3 buckets, unrestricted security groups (`0.0.0.0/0` on port 22/3389), overly permissive IAM policies (`"Action": "*", "Resource": "*"`), and unencrypted data at rest.

## Safe operating rules
- Statically audit local template and configuration files.
- Do not interact with live cloud accounts without authorization.
- Provide least-privilege IAM and secure cloud baseline templates.

## Workflow
1. Locate all `.tf`, `.tfvars`, Kubernetes YAML, and CloudFormation templates.
2. Scan for public ingress rules (`cidr_blocks = ["0.0.0.0/0"]`) on management ports.
3. Check for unencrypted block storage (`encrypted = false`) and public cloud storage buckets (`acl = "public-read"`).
4. Identify wildcard IAM policies granting administrative privileges.

## Remediation Guidance
- Enforce private bucket ACLs and block public access:
  ```hcl
  resource "aws_s3_bucket_public_access_block" "example" {
    bucket = aws_s3_bucket.example.id
    block_public_acls       = true
    block_public_policy     = true
    ignore_public_acls      = true
    restrict_public_buckets = true
  }
  ```
- Restrict security group ingress to specific VPC CIDRs or bastion hosts.
- Apply AWS KMS customer-managed keys for EBS, RDS, and S3 encryption.
