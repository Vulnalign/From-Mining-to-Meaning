# Open Science Artifacts (Anonymous)

This repository contains the artifacts required to evaluate the accompanying anonymous submission.

## Artifacts Provided
1. Dataset
   - DATA/validated/ : validated vulnerability–fix pairs
   - DATA/raw/ : raw/mined data or a representative subset (if provided)

2. Tooling
   - CODE/ : pipeline components (mining, validation, reconciliation, evaluation)
   - CONFIG/ : experiment configurations

3. Reproducibility
   - SCRIPTS/setup_env.* : environment setup
   - SCRIPTS/reproduce_results.* : reproduces key tables/figures/metrics

## How to Use (High Level)
- Install dependencies (see SCRIPTS/setup_env.*)
- Run SCRIPTS/reproduce_results.* to regenerate key results

## Restrictions (if applicable)
If any artifact cannot be fully redistributed (e.g., size/licensing), representative subsets and the full pipeline are provided so reviewers can evaluate the methodology end-to-end.
