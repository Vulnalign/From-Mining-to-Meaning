import pandas as pd
import re
from pathlib import Path

# ---------- CONFIG ----------
ROOT_DIR = Path(r"C:\Users\guptap\DevGPT\Workpackage1-dataset\Custom_dataset\final_output")
#OUTPUT_FILE = "commit_repo_mapping_highconf.csv"
OUTPUT_FILE = "commit_repo_mapping_extended.csv"
MAX_REPOS_PER_COMMIT = 3


def normalize_base_url(url: str):
    url = str(url).strip()
    m = re.match(r"^https?://github\.com/([^/]+)/([^/#?]+)", url)
    if m:
        return f"https://github.com/{m.group(1)}/{m.group(2)}"
    return None


def main():
    csv_files = list(ROOT_DIR.rglob("snippets_metadata_patches.csv"))
    print(f"Found {len(csv_files)} snippets_metadata_patches.csv files")

    dfs = []
    for f in csv_files:
        try:
            df = pd.read_csv(f)
            df["source_csv"] = str(f)
            dfs.append(df)
        except Exception as e:
            print(f"Failed to read {f}: {e}")

    if not dfs:
        raise RuntimeError("No snippets_metadata_patches.csv files could be loaded.")

    df_mapping_raw = pd.concat(dfs, ignore_index=True)

    df_mapping_raw["commit_sha"] = df_mapping_raw["commit_sha"].astype(str).str.strip()
    df_mapping_raw["base_repo_url"] = df_mapping_raw["repo_url"].apply(normalize_base_url)

    df_mapping_raw = df_mapping_raw.dropna(subset=["commit_sha", "base_repo_url"]).copy()

    print("Total metadata rows:", len(df_mapping_raw))
    print("Unique raw commit SHAs:", df_mapping_raw["commit_sha"].nunique())
    print("Rows with recoverable base repo URL:", df_mapping_raw["base_repo_url"].notna().sum())

    conflicts = (
        df_mapping_raw
        .groupby("commit_sha")["base_repo_url"]
        .nunique()
        .reset_index(name="n_repos")
    )


    print("Commits with >1 repo mapping:", (conflicts["n_repos"] > 1).sum())

    # keep high + medium confidence mappings
    valid_shas = conflicts[conflicts["n_repos"] <= MAX_REPOS_PER_COMMIT]["commit_sha"]

    df_mapping_extended = df_mapping_raw[
        df_mapping_raw["commit_sha"].isin(valid_shas)
    ].copy()


    # choose most frequent repo per commit
    repo_choice = (
        df_mapping_extended
        .groupby(["commit_sha", "base_repo_url"])
        .size()
        .reset_index(name="repo_count")
        .sort_values(["commit_sha", "repo_count"], ascending=[True, False])
        .drop_duplicates(subset=["commit_sha"])
    )

    repo_choice = repo_choice.merge(conflicts, on="commit_sha", how="left")

    repo_choice["mapping_confidence"] = repo_choice["n_repos"].apply(
        lambda x: "high" if x == 1 else "medium"
    )

    repo_choice = repo_choice[
        ["commit_sha", "base_repo_url", "mapping_confidence", "n_repos", "repo_count"]
    ].copy()

    print("Extended mappings:", len(repo_choice))
    print(repo_choice["mapping_confidence"].value_counts().to_string())

    #df_mapping_highconf = (df_mapping_raw[df_mapping_raw["commit_sha"].isin(valid_shas)].dropna(subset=["commit_sha", "base_repo_url"]).drop_duplicates(subset=["commit_sha"])[["commit_sha", "base_repo_url"]].copy()))

    #print("High-confidence mappings:", len(df_mapping_highconf))

    repo_choice.to_csv(OUTPUT_FILE, index=False)
    print(f"Saved {OUTPUT_FILE}")


if __name__ == "__main__":
    main()