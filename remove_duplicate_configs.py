from services import fingerprint
from services.read_configs import read_configs


def remove_duplicates(configs: list[str]):
    unique_configs = {}

    for config in configs:
        fgp = fingerprint.generate_fingerprint(config)

        if not fgp:
            continue  # Skip invalid configs

        # Check if this ID exists in our database
        if fgp not in unique_configs:
            unique_configs[fgp] = config

    # Calculate stats
    initial_count = len(configs)
    unique_count = len(unique_configs)
    duplicates_count = initial_count - unique_count

    print(
        f"➤ Deduplication Report: Processed {initial_count} configs. Kept {unique_count} unique. Removed {duplicates_count} duplicates."
    )

    return list(unique_configs.values())


def run(configs_file: str, output_file: str):
    configs = read_configs(configs_file)
    unique_configs = remove_duplicates(configs)

    with open(output_file, "w", encoding="utf-8") as f:
        for config in unique_configs:
            f.write(config + "\n")

    print(f"saved to {output_file}")
