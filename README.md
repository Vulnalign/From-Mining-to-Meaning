# VulnAlign Artifacts

# VulnAlign Artifact (Anonymous Submission)

This repository contains the code, sample data, and configuration files used to support the anonymous submission titled **VulnAlign**.  
The artifact demonstrates the dataset construction pipeline for linking CVEs to vulnerable and patched code, validating labels using static rules, and reconciling CWEs using ontology-aware reasoning.

The repository is structured to allow reviewers to inspect the methodology and reproduce a small-scale version of the dataset using the included samples.

---

## 📁 Repository Structure
vulnalign-artifact/
│
├── CODE/
│ ├── mining/ # NVD mining, commit discovery, patch extraction   --
│ ├── validation/ # Static validation (Semgrep-based)
│ ├── ontology_scripts/ # CWE hierarchy reasoning and reconciliation
│ ├── sanitize_ipynb.py # Utility script (formatting, cleanup)
│ 
│
├── DATA/
│ └── samples/ # Representative dataset snapshots (JSONL)
│
├── CONFIG/
│ ├── reproduce_config.json # Parameters for sample reproduction
│ └── github_tokens.txt.example # Template for optional GitHub tokens
│
├── SCRIPTS/
│ └── reproduce_results.sh # Reproduces validation + ontology steps
│
├── OPEN_SCIENCE.md
├── REPRODUCIBILITY.md
└── README.md



The full dataset used in the paper is too large to host in this repository (≈ 4.2GB).
We provide small samples for demonstration:
DATA/samples/vulnalign_raw_sample.jsonl
DATA/samples/vulnalign_validated_sample.jsonl

