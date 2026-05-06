import os
import time
import logging
from urllib.parse import quote
import csv
import pandas as pd
import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("reextraction.log"),
        logging.StreamHandler()
    ]
)

# ---------- CONFIG ----------



INPUT_FILE = "refined_ep_hp_with_fixed_repo_extended.csv"
OUTPUT_FILE = "refined_dataset_aligned_extended.csv"
CHECKPOINT_FILE = "refined_dataset_aligned_extended_checkpoint.csv"

#1#CHUNK_FILTER_CWES = ["cwe-119", "cwe-79", "cwe-22", "cwe-125"]  # adjust if needed
CHUNK_FILTER_CWES = None  # set to None to include all CWEs

REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
BASE_SLEEP_SECONDS = 10



GITHUB_TOKENS = [t.strip() for t in os.getenv("GITHUB_TOKENS", "").split(",") if t.strip()]
if not GITHUB_TOKENS:
    raise ValueError("GITHUB_TOKENS is empty. Set one or more GitHub tokens in the environment.")

token_idx = 0
session = requests.Session()

RETRYABLE_STATUS_CODES = {403, 429, 500, 502, 503, 504}


def get_token():
    global token_idx
    token = GITHUB_TOKENS[token_idx % len(GITHUB_TOKENS)]
    token_idx += 1
    return token


def parse_owner_repo(repo_url: str):
    parts = repo_url.rstrip("/").split("/")
    owner, repo = parts[-2], parts[-1].replace(".git", "")
    return owner, repo


def compute_wait_seconds(resp: requests.Response, default_wait: int = BASE_SLEEP_SECONDS) -> int:
    reset = resp.headers.get("X-RateLimit-Reset")
    if reset:
        try:
            return max(int(reset) - int(time.time()), 10)
        except Exception:
            pass
    return default_wait


def fetch_file_content(repo_url: str, commit_sha: str, file_path: str, retries: int = MAX_RETRIES):
    owner, repo = parse_owner_repo(repo_url)
    encoded_path = quote(file_path, safe="/")

    token = get_token()
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.raw"
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{encoded_path}?ref={commit_sha}"

    try:
        resp = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as e:
        if retries > 0:
            time.sleep(BASE_SLEEP_SECONDS)
            return fetch_file_content(repo_url, commit_sha, file_path, retries=retries - 1)
        return None, "file_request_exception"

    if resp.status_code == 200:
        return resp.text, None

    if resp.status_code in RETRYABLE_STATUS_CODES and retries > 0:
        wait = compute_wait_seconds(resp)
        logging.warning(
            f"Retryable error {resp.status_code} for {owner}/{repo}/{file_path}@{commit_sha[:7]}. "
            f"Waiting {wait}s ({retries} retries left)"
        )
        time.sleep(wait)
        return fetch_file_content(repo_url, commit_sha, file_path, retries=retries - 1)

    if resp.status_code == 404:
        return None, "http_404"

    return None, f"http_{resp.status_code}"


def get_parent_sha(repo_url: str, commit_sha: str, retries: int = MAX_RETRIES):
    owner, repo = parse_owner_repo(repo_url)

    token = get_token()
    headers = {"Authorization": f"token {token}"}
    url = f"https://api.github.com/repos/{owner}/{repo}/commits/{commit_sha}"

    try:
        resp = session.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException:
        if retries > 0:
            time.sleep(BASE_SLEEP_SECONDS)
            return get_parent_sha(repo_url, commit_sha, retries=retries - 1)
        return None, "parent_request_exception"

    if resp.status_code == 200:
        parents = resp.json().get("parents", [])
        if len(parents) >= 1:
            if len(parents) > 1:
                logging.info(
                    f"Merge commit {commit_sha[:7]} has {len(parents)} parents; using first parent {parents[0]['sha'][:7]}"
                )
            return parents[0]["sha"], None
        return None, "parent_no_parents"

    if resp.status_code in RETRYABLE_STATUS_CODES and retries > 0:
        wait = compute_wait_seconds(resp)
        logging.warning(
            f"Retryable error {resp.status_code} for commit {owner}/{repo}@{commit_sha[:7]}. "
            f"Waiting {wait}s ({retries} retries left)"
        )
        time.sleep(wait)
        return get_parent_sha(repo_url, commit_sha, retries=retries - 1)

    if resp.status_code == 404:
        return None, "parent_http_404"

    return None, f"parent_http_{resp.status_code}"



def set_csv_field_limit():
    max_int = 2147483647
    while True:
        try:
            csv.field_size_limit(max_int)
            break
        except OverflowError:
            max_int = int(max_int / 10)

def main():
    set_csv_field_limit()

    needed_cols = [
        "finding_id",
        "cve_id",
        "cwe_final",
        "match_type",
        "commit_sha",
        "file_path",
        "language",
        "base_repo_url",
    ]

    df = pd.read_csv(
        INPUT_FILE,
        usecols=needed_cols,
        engine="python"
    )
    print(len(df), "rows read from input")
    #df = pd.read_csv(INPUT_FILE)
    df = df.drop_duplicates(subset="finding_id").copy()
    #df = df[df["cwe_final"].isin(CHUNK_FILTER_CWES)].copy()
    if CHUNK_FILTER_CWES is not None:
        df = df[df["cwe_final"].isin(CHUNK_FILTER_CWES)].copy()
    df = df[df["base_repo_url"].notna()].copy()
    print(len(df), "rows after filtering out null base_repo_url")
    triple_cols = ["base_repo_url", "commit_sha", "file_path"]

    triple_counts = (
        df.groupby(triple_cols)
        .size()
        .reset_index(name="original_rows_for_triple")
    )

    triple_cve_counts = (
        df.groupby(triple_cols)["cve_id"]
        .nunique()
        .reset_index(name="unique_cves_for_triple")
    )

    df_unique = (
        df.drop_duplicates(subset=triple_cols)
        .merge(triple_counts, on=triple_cols, how="left")
        .merge(triple_cve_counts, on=triple_cols, how="left")
        .copy()
    )

    logging.info(f"Re-extracting {len(df_unique)} unique (repo, commit, file) triples")

    results = []

    for i, (_, row) in enumerate(df_unique.iterrows(), start=1):
        if i % 10 == 1:
            logging.info(f"Progress: {i - 1}/{len(df_unique)}")

        commit_sha = str(row["commit_sha"]).strip()
        repo_url = str(row["base_repo_url"]).strip()
        file_path = str(row["file_path"]).strip()

        parent_sha, parent_error = get_parent_sha(repo_url, commit_sha)

        code_before = None
        code_after = None
        error_type = parent_error

        if parent_sha:
            code_before, err_before = fetch_file_content(repo_url, parent_sha, file_path)
            code_after, err_after = fetch_file_content(repo_url, commit_sha, file_path)

            if err_before:
                error_type = f"before_{err_before}"
            elif err_after:
                error_type = f"after_{err_after}"
            else:
                error_type = None

        success = code_before is not None and code_after is not None

        results.append({
            "representative_finding_id": row.get("finding_id"),
            "cve_id": row["cve_id"],
            "cwe_final": row["cwe_final"],
            "match_type": row["match_type"],
            "repo_url": repo_url,
            "commit_sha": commit_sha,
            "parent_sha": parent_sha,
            "file_path": file_path,
            "language": row["language"],
            "original_rows_for_triple": row["original_rows_for_triple"],
            "unique_cves_for_triple": row["unique_cves_for_triple"],
            "reextraction_success": success,
            "error_type": error_type,
            "code_before_aligned": code_before,
            "code_after_aligned": code_after,
        })

        time.sleep(0.5)

        if i % 100 == 0:
            pd.DataFrame(results).to_csv(CHECKPOINT_FILE, index=False)
            logging.info(f"Checkpoint saved: {len(results)} rows")

    df_results = pd.DataFrame(results)
    df_results.to_csv(OUTPUT_FILE, index=False)

    total = len(df_results)
    success_count = int(df_results["reextraction_success"].sum())
    success_rate = success_count / total if total else 0.0

    logging.info(f"Done. {success_count}/{total} ({success_rate:.1%}) successfully re-extracted")

    logging.info("Success rate by CWE:")
    logging.info(
        df_results.groupby("cwe_final")["reextraction_success"]
        .mean()
        .sort_values(ascending=False)
        .to_string()
    )

    logging.info("Failures by type:")
    failure_counts = df_results.loc[~df_results["reextraction_success"], "error_type"].value_counts(dropna=False)
    logging.info(failure_counts.to_string() if not failure_counts.empty else "No failures")

    df_ok = df_results[df_results["reextraction_success"]].copy()
    if not df_ok.empty:
        df_ok["before_lines"] = df_ok["code_before_aligned"].fillna("").str.count("\n") + 1
        df_ok["after_lines"] = df_ok["code_after_aligned"].fillna("").str.count("\n") + 1

        logging.info("Aligned file line statistics:")
        logging.info(df_ok[["before_lines", "after_lines"]].describe().to_string())


if __name__ == "__main__":

    
    main()