# Dataset Artifact 

Artifact repository for the paper "From Mining to Meaning: Ontology-Driven Validation of Vulnerability Labels in Large-Scale Datasets" (ESORICS 2026)

This repository contains the code, sample data, and configuration files used to support the submission titled **From Mining to Meaning**. The artifact demonstrates the dataset construction pipeline for:

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
│   ├── mining/                                       # NVD mining, commit discovery, patch extraction
│   ├── validation/                                   # Static validation (Semgrep-based)
│   ├── ontology_scripts/                             # CWE hierarchy reasoning and reconciliation
│   ├── experiments/                                  # Classification downstream task
│   └── sanitize.py                                    # Utility script (formatting / cleanup)
│
├── DATA/
│   └── master_validated_dataset.jsonl                # Representative dataset snapshots of validation output, including both “good” and “noisy” cases (JSONL)
│   └── nique_validated_dataset_for_review.jsonl      # Representative dataset snapshots of clean subset of validated cases (JSONL)
│
├── OPEN_SCIENCE.md
├── REPRODUCIBILITY.md
└── README.md

```
Note: The full VulnAlign dataset is several gigabytes in size and is not included in this repository.
Instead, we provide two representative samples that match the schema and processing stages described in the paper.

---


📄 Dataset Samples

1. DATA/master_validated_dataset.jsonl: 
This file is intended to illustrate the complete validation output, including both “good” and “noisy” cases, so reviewers can see how Semgrep and filtering operate.
  - JSONL file (one JSON object per line).
  - Contains the full Semgrep validation output for a sample of vulnerability–fix pairs.
  - It includes:
    - CVE and repository metadata (e.g., cve_id, repo_url, commit_sha), Vulnerable / patched code identifiers (e.g., original_filename, file paths)
    - Semgrep match information: Exact Positive / Hierarchy True Positive counts (EP/HP), rule identifiers, flags for mismatches / noisy examples
    - Intermediate validation metadata used to derive the final dataset


2. DATA/unique_validated_dataset_for_review.jsonl: 
This file is intended for quick inspection and for understanding the final dataset structure without noise.
  - JSONL file (one JSON object per line).
  - Contains only validated examples (HP/EP).
Compared to master_validated_dataset.jsonl, this file excludes mismatched entries and reflects the clean subset used for experiments in the paper.


---


Code Overview (Inspection-Oriented)

The code is organized so that reviewers can trace each stage of the pipeline. Running everything end-to-end is not required and may be impractical (external APIs, runtime), but the logic is fully visible.

CODE/mining/
Contains notebooks and scripts used to:
 - Download CVE data from NVD
 - Resolve references to repositories and commits
 - Extract vulnerable and patched code from version control history
These scripts depend on NVD dumps and external Git hosting (e.g., GitHub) and are not expected to be re-run during artifact review.

CODE/validation/
Contains notebooks and scripts used to:
  - Run Semgrep on candidate vulnerability–fix pairs
  - Compute EP/HP metrics
  - Flag mismatches and noisy examples

This code is responsible for producing the kinds of results seen in master_validated_dataset.jsonl.

CODE/ontology_scripts/
Contains notebooks and scripts used to:
  - Reason over the CWE hierarchy
  - Reconcile high-level / abstract CWEs with more specific CWE categories
  - Produce the reconciled labels used in the final dataset

sanitize.py
Utility helper for:
  - Cleaning notebooks or exported files
  - Normalizing formats before committing / sharing



Restrictions (if applicable)
The full corpus is large (25GB), we provide a representative subset in the artifact repo for reproducibility and format verification. Full release will follow Zenodo
