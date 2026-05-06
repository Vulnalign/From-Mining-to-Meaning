import pandas as pd
import csv


ORIGINAL_FILE = "refined_ep_hp_with_fixed_repo_extended.csv"
ALIGNED_FILE = "refined_dataset_aligned_extended.csv"
OUTPUT_FILE = "refined_dataset_full_repaired_extended.csv"
KEYS = ["base_repo_url", "commit_sha", "file_path"]

def set_csv_field_limit():
    max_int = 2147483647
    while True:
        try:
            csv.field_size_limit(max_int)
            break
        except OverflowError:
            max_int = int(max_int / 10)

set_csv_field_limit()

aligned = pd.read_csv(ALIGNED_FILE)

aligned = aligned[aligned["reextraction_success"] == True].copy()

aligned_keep = aligned[
    [
        "repo_url",
        "commit_sha",
        "file_path",
        "code_before_aligned",
        "code_after_aligned",
        "parent_sha",
    ]
].drop_duplicates(subset=["repo_url", "commit_sha", "file_path"])

aligned_keep = aligned_keep.rename(columns={"repo_url": "base_repo_url"})

first_chunk = True
total_rows = 0
repaired_rows = 0

for chunk in pd.read_csv(
    ORIGINAL_FILE,
    chunksize=50000,
    engine="python"
):
    chunk["commit_sha"] = chunk["commit_sha"].astype(str).str.strip()
    chunk["file_path"] = chunk["file_path"].astype(str).str.strip()
    chunk["base_repo_url"] = chunk["base_repo_url"].astype(str).str.strip()

    merged = chunk.merge(
        aligned_keep,
        on=KEYS,
        how="left"
    )

    has_aligned = merged["code_before_aligned"].notna() & merged["code_after_aligned"].notna()
    repaired_rows += has_aligned.sum()
    total_rows += len(merged)

    merged.loc[has_aligned, "code_before"] = merged.loc[has_aligned, "code_before_aligned"]
    merged.loc[has_aligned, "code_after"] = merged.loc[has_aligned, "code_after_aligned"]

    merged["aligned_repair_applied"] = has_aligned

    merged.drop(columns=["code_before_aligned", "code_after_aligned"], inplace=True)

    merged.to_csv(
        OUTPUT_FILE,
        mode="w" if first_chunk else "a",
        header=first_chunk,
        index=False
    )
    first_chunk = False

print("Done")
print("Total rows:", total_rows)
print("Rows repaired:", repaired_rows)
print("Rows not repaired:", total_rows - repaired_rows)
print("Repair coverage:", repaired_rows / total_rows if total_rows else 0)
print(f"Saved {OUTPUT_FILE}")

