# VulnAlign Artifact (Anonymous Submission)

This repository contains the code, sample data, and configuration files used to support the anonymous submission titled **VulnAlign**.  
The artifact demonstrates the dataset construction pipeline for:

- Linking CVEs to vulnerable and patched code
- Validating labels using static (rule-based) analysis
- Reconciling CWEs using ontology-aware reasoning

The repository is structured to allow reviewers to inspect the methodology and reproduce a small-scale version of the pipeline using the included samples.

---

## 📁 Repository Structure

```text
vulnalign-artifact/
│
├── CODE/
│   ├── mining/               # NVD mining, commit discovery, patch extraction
│   ├── validation/           # Static validation (Semgrep-based)
│   ├── ontology_scripts/     # CWE hierarchy reasoning and reconciliation
│   └── sanitize.py           # Utility script (formatting / cleanup)
│
├── DATA/
│   └── samples/              # Representative dataset snapshots (JSONL)
│
├── CONFIG/
│   ├── reproduce_config.json         # Parameters for sample reproduction
│   └── github_tokens.txt.example     # Template for optional GitHub tokens
│
├── SCRIPTS/
│   └── reproduce_results.sh          # Reproduces validation + ontology steps
│
├── OPEN_SCIENCE.md
├── REPRODUCIBILITY.md
└── README.md

```
Note: The full VulnAlign dataset is several gigabytes in size and is not included in this repository.
Instead, we provide two representative samples that match the schema and processing stages described in the paper.

📄 Dataset Samples

1. DATA/master_validated_dataset.jsonl
  - JSONL file (one JSON object per line).
  - Contains the full Semgrep validation output for a sample of vulnerability–fix pairs.

It includes (field names may be abbreviated in practice):

  - CVE and repository metadata (e.g., cve_id, repo_url, commit_sha)
  - Vulnerable / patched code identifiers (e.g., original_filename, file paths)
  -Semgrep match information:

      - high-precision / extended-precision counts (HP/EP)
      - rule identifiers
  - Flags for mismatches / noisy examples
  -Intermediate validation metadata used to derive the final dataset

This file is intended to illustrate the complete validation output, including both “good” and “noisy” cases, so reviewers can see how Semgrep and filtering operate.


2. DATA/unique_validated_dataset_for_review.jsonl

  - JSONL file (one JSON object per line).
  - Contains only validated examples (HP/EP), i.e. high-confidence matches after filtering.

Compared to master_validated_dataset.jsonl, this file:

  - Excludes noisy / mismatched entries
  - Keeps only the unique, validated vulnerability–fix pairs that pass the filtering criteria
  - Reflects the clean subset used for experiments in the paper

This file is intended for quick inspection and for understanding the final dataset structure without noise.
