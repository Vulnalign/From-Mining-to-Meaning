## Overview

This dataset is the final, deduplicated output of a multi-step reconstruction pipeline applied to the base refined vulnerability-patch dataset (refined_ep_hp.csv). It contains 16,988 unique vulnerability findings, each with aligned code_before and code_after fields extracted directly from GitHub at the correct parent commit, resolving systematic code-alignment issues present in the original dataset.

---
 
## File Variants
 
| File | Description |
|---|---|
| `refined_dataset_full_repaired_extended.csv` | Full repaired dataset before deduplication |
| `refined_dataset_full_repaired_extended_unique.csv` | Final deduplicated dataset (**this dataset**, 16,988 rows) |
 
---

## Reconstruction Pipeline

The dataset was produced by a 4-step pipeline starting from `refined_ep_hp.csv`:

```
Step 1: build_commit_repo_mapping.py
        Resolves a canonical repo URL for each commit SHA from raw metadata.
        Confidence: high (1 repo/commit) or medium (2–3 repos/commit).
        → commit_repo_mapping_extended.csv

Step 2: merge_fixed_repo_into_refined.py
        Joins resolved repo URLs back into the base dataset on commit_sha.
        → refined_ep_hp_with_fixed_repo_extended.csv

Step 3: reextract_aligned_before_after.py
        Re-fetches code_before (at parent commit) and code_after (at fix commit)
        via the GitHub API for each unique (repo, commit, file) triple.
        Requires: GITHUB_TOKENS env variable (comma-separated, rotated for rate limits).
        → refined_dataset_aligned_extended.csv

Step 4: merge_aligned_code_back_to_full_dataset.py
        Overwrites code_before/code_after with aligned versions where available.
        Adds aligned_repair_applied flag.
        → refined_dataset_full_repaired_extended.csv

[deduplicate on finding_id]
        → refined_dataset_full_repaired_extended_unique.csv  ← this file
```

---

## Column Reference

| Column | Description |
|---|---|
| `finding_id` | Unique finding identifier (deduplication key) |
| `cve_id` | Associated CVE |
| `cwe_original` | CWE label from the source dataset |
| `cwe_detected` | CWE label detected by the static analysis rule |
| `cwe_final` | Refined CWE after ontology-based hierarchy resolution |
| `rules_triggered` | Static analysis rule(s) that fired |
| `match_type` | `EP` (Exact-Path) or `HP` (Hierarchy-Path) consistency match |
| `static_match` | Whether `cwe_detected` exactly matches `cwe_original` |
| `commit_sha` | Fix commit SHA |
| `parent_sha` | Parent (pre-fix) commit SHA |
| `file_path` | File path within the repository |
| `repo_url` | Original source dataset repo URL |
| `base_repo_url` | Resolved canonical GitHub repo URL |
| `mapping_confidence` | `high` or `medium` (from Step 1) |
| `code_before` | Full file content before the fix |
| `code_after` | Full file content after the fix |
| `aligned_repair_applied` | `True` if code was replaced by the re-extraction pipeline |

---

 
## Reproducibility Notes
 
- **GitHub tokens:** Step 3 requires `GITHUB_TOKENS` to be set as an environment variable. Multiple tokens are rotated to stay within API rate limits.
- **Large fields:** All scripts apply a `csv.field_size_limit` workaround to handle the large code content fields without truncation.
- **Checkpointing:** Step 3 writes a checkpoint file (`refined_dataset_aligned_extended_checkpoint.csv`) every 100 rows, allowing interrupted runs to be inspected without data loss.
- **Chunk processing:** Steps 2 and 4 process the dataset in 50,000-row chunks to avoid memory issues with large CSVs containing full file content.
- **Merge commits:** For fix commits with multiple parents, Step 3 always uses the first parent as the pre-fix baseline.