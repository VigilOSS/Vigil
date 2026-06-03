---
name: gf-patterns:img_traversal
description: Image-handling parameters and `/img/`, `/thumb/`, `/photo/` paths (LFI vector)
origin: 1ndianl33t/Gf-Patterns (+ local overlay)
bucket: img_traversal
weight: 35
---

# GF Bucket: img_traversal

## Purpose

Image-serving endpoints that accept image-like path or filename parameters are a common LFI variant. Keep them separate from generic `lfi` so `/img?src=../../etc/passwd` and thumbnail renderers stay visible as their own cluster.

## Classifier Signal

- Weight: `35`
- Parameter keys: `img`, `image`, `photo`, `thumb`, `thumbnail`
- Path fragments: `/img/`, `/image/`, `/images/`, `/thumb/`, `/thumbnail/`, `/photo/`

## Review Notes

Treat this as traversal/file-read work first, not visual asset review. Test path normalization, extension allowlists, remote URL fetches, and renderer backends before deferring the cluster.
