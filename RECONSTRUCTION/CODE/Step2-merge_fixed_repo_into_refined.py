import pandas as pd
import csv

# ---------- CONFIG ----------
INPUT_REFINED = "refined_ep_hp.csv"
#INPUT_MAPPING = "commit_repo_mapping_highconf.csv"
INPUT_MAPPING = "commit_repo_mapping_extended.csv"
OUTPUT_FILE = "refined_ep_hp_with_fixed_repo_extended.csv"
CHUNK_SIZE = 50000


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

    df_map = pd.read_csv(INPUT_MAPPING)
    df_map["commit_sha"] = df_map["commit_sha"].astype(str).str.strip()

    first_chunk = True
    total_rows = 0
    recovered_rows = 0

    for chunk in pd.read_csv(INPUT_REFINED, chunksize=CHUNK_SIZE, engine="python"):
        chunk["commit_sha"] = chunk["commit_sha"].astype(str).str.strip()

        merged = chunk.merge(df_map, on="commit_sha", how="left")
        #merged.rename(columns={"base_repo_url": "repo_url_for_fetch"}, inplace=True)

        total_rows += len(merged)
        recovered_rows += merged["base_repo_url"].notna().sum()

        

        merged.to_csv(
            OUTPUT_FILE,
            mode="w" if first_chunk else "a",
            header=first_chunk,
            index=False
        )
        first_chunk = False

    print("Merge complete")
    print("Recovered repo URLs:", recovered_rows / total_rows if total_rows else 0.0)
    print("Total rows:", total_rows)
    print(recovered_rows, "recovered rows")
    print(total_rows - recovered_rows, "missing rows")
    print(f"Saved {OUTPUT_FILE}")


if __name__ == "__main__":
    main()