---
description: Regex catalogue for classifying a captured corpus by sensitive-data type (national IDs, financial, contact, credentials, infrastructure identifiers, medical) with the validation each broad pattern needs
skill: sensitive-data-detection
---

# Sensitive-data regex catalogue

Load when a captured response, dump or file needs classifying by data type. Run the patterns
over the local copy (`TARGET_FILE`), never as target traffic. Many patterns are broad (12-digit
IDs, passport and Personalausweis shapes, ICD codes, US phone numbers) and match ordinary tokens:
a match is a candidate until context (the field name, surrounding record) and a validation step
(Luhn for cards, the published check digit for national IDs, an `arn:` or account field for AWS
IDs) confirm it, because the FP gate kills unvalidated type claims. For secrets, trufflehog's
verified detectors are stronger than these hand patterns (`agent/references/tools/recon/trufflehog.md`).

```bash
TARGET_FILE=<path to the saved response, dump or file>

# === IDENTITY DOCUMENTS ===

# China — 18-digit ID card (with checksum digit X)
rg -oN '[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]' "$TARGET_FILE"

# US — Social Security Number
rg -oN '\b\d{3}-\d{2}-\d{4}\b' "$TARGET_FILE"

# UK — National Insurance Number
rg -oN '\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b' "$TARGET_FILE"

# Japan — My Number (12 digits; same shape as an AWS account ID, so confirm by context and the check digit)
rg -oN '\b\d{12}\b' "$TARGET_FILE"

# South Korea — Resident Registration Number
rg -oN '\b\d{6}-[1-4]\d{6}\b' "$TARGET_FILE"

# India — Aadhaar (12 digits, starts with 2-9)
rg -oN '\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b' "$TARGET_FILE"

# EU/International — Passport (common formats)
rg -oN '\b[A-Z]{1,2}\d{6,9}\b' "$TARGET_FILE"

# Brazil — CPF
rg -oN '\b\d{3}\.\d{3}\.\d{3}-\d{2}\b' "$TARGET_FILE"

# Germany — Personalausweis
rg -oN '\b[CFGHJKLMNPRTVWXYZ0-9]{9}\b' "$TARGET_FILE"

# === FINANCIAL ===

# Credit card numbers (13-19 digits, common prefixes)
rg -oN '\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,7}\b' "$TARGET_FILE"

# IBAN (international bank account)
rg -oN '\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b' "$TARGET_FILE"

# China — Bank card (16-19 digits, starts with 62)
rg -oN '\b62\d{14,17}\b' "$TARGET_FILE"

# Bitcoin address
rg -oN '\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b' "$TARGET_FILE"
rg -oN '\bbc1[a-zA-HJ-NP-Z0-9]{25,90}\b' "$TARGET_FILE"

# === CONTACT ===

# Email
rg -oN '\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b' "$TARGET_FILE"

# Phone — international with country code
rg -oN '\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}' "$TARGET_FILE"

# Phone — China mobile (11 digits starting with 1)
rg -oN '\b1[3-9]\d{9}\b' "$TARGET_FILE"

# Phone — US (10 digits)
rg -oN '\b\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b' "$TARGET_FILE"

# Phone — Japan
rg -oN '\b0[789]0-\d{4}-\d{4}\b' "$TARGET_FILE"

# Physical address patterns (street number + name)
rg -oN '\b\d{1,5}\s[A-Z][a-z]+\s(St|Ave|Rd|Blvd|Dr|Ln|Ct|Way|Pl)\b' "$TARGET_FILE"

# === CREDENTIALS & SECRETS ===

# API keys (high entropy strings)
rg -oN '(?i)(api[_-]?key|apikey|api[_-]?secret|access[_-]?key)["\s:=]+["\x27]?[A-Za-z0-9/+=_-]{20,}' "$TARGET_FILE"

# AWS keys
rg -oN '\bAKIA[A-Z0-9]{16}\b' "$TARGET_FILE"
rg -oN '(?i)(aws[_-]?secret|secret[_-]?key)["\s:=]+["\x27]?[A-Za-z0-9/+=]{40}' "$TARGET_FILE"

# Azure / GCP
rg -oN '(?i)(azure|subscription)[_-]?(id|key|secret|token)["\s:=]+["\x27]?[A-Za-z0-9/+=_-]{20,}' "$TARGET_FILE"
rg -oN '\bAIza[A-Za-z0-9_-]{35}\b' "$TARGET_FILE"

# JWT tokens
rg -oN '\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' "$TARGET_FILE"

# Private keys
rg -oN -e '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----' "$TARGET_FILE"

# Generic password patterns
rg -oN '(?i)(password|passwd|pwd|pass)["\s:=]+["\x27]?[^\s"'\'']{4,}' "$TARGET_FILE"

# Bearer tokens
rg -oN '(?i)bearer\s+[A-Za-z0-9_.-]{20,}' "$TARGET_FILE"

# Database connection strings
rg -oN '(?i)(mysql|postgres|mongodb|redis|mssql)://[^\s"<>]+' "$TARGET_FILE"

# Webhook URLs (Slack, Discord, etc)
rg -oN 'https://hooks\.(slack|discord)\.com/[^\s"<>]+' "$TARGET_FILE"

# === CORPORATE INFRASTRUCTURE ===

# Internal IPs (RFC1918)
rg -oN '\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b' "$TARGET_FILE"

# Internal hostnames
rg -oN '(?i)\b[a-z0-9-]+\.(internal|local|corp|intranet|private|lan)\b' "$TARGET_FILE"

# AWS Account ID: the 12-digit pattern above, confirmed by context (`arn:aws:` prefixes, account fields)

# S3 bucket names
rg -oN '(?i)(s3://|s3\.amazonaws\.com/|\.s3\.)[a-z0-9.-]+' "$TARGET_FILE"

# Docker registry
rg -oN '(?i)\b[a-z0-9.-]+\.(azurecr\.io|gcr\.io|ecr\.[a-z-]+\.amazonaws\.com)/[^\s"]+' "$TARGET_FILE"

# === MEDICAL (HIPAA) ===

# ICD codes (diagnosis)
rg -oN '\b[A-Z]\d{2}(\.\d{1,4})?\b' "$TARGET_FILE"

# US Medicare/Medicaid ID
rg -oN '\b\d{10}[A-Z]\b' "$TARGET_FILE"

# DEA number (prescriber)
rg -oN '\b[ABCDFGHMJKLPT][A-Z9]\d{7}\b' "$TARGET_FILE"
```
