# GF Bucket: cors

## Purpose

CORS-control parameters and origin reflection hints can indicate cross-origin trust bugs, especially around authenticated API routes and token-bearing frontends.

## Classifier Signal

- Weight: `25`
- Parameter keys: `origin`, `access_control`, `allow_origin`, `cors`, `callback_origin`
- Path fragments: none

## Review Notes

Confirm with browser-equivalent requests and credentials behavior. Do not report permissive CORS without showing sensitive data exposure or an authenticated action made reachable cross-origin.
