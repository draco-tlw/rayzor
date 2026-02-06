from services.read_channels import read_channels


def clean(channels_file: str, output_file: str):
    print("--- Channel Cleanup ---")
    print(f"Reading from: {channels_file}")

    channels = read_channels(channels_file)

    if channels:
        raw_count = len(channels)
        print(f"   • Raw entries found: {raw_count}")

        channels = [ch.lower() for ch in channels]
        channels_set = set(channels)
        unique_count = len(channels_set)
        duplicates_removed = raw_count - unique_count

        channels = list(channels_set)
        channels.sort()

        print(f"   • Duplicates removed: {duplicates_removed}")
        print(f"   • Unique channels:    {unique_count}")

        # Save
        print(f"Saving to: {output_file}")
        with open(output_file, "w", encoding="utf-8") as f:
            for channel in channels:
                f.write(channel + "\n")

        print("\nSuccess! List cleaned and sorted.")
    else:
        print(f"No channels found in {output_file} (or file is missing).")


def run(channels_file: str, output_file: str):
    clean(channels_file, output_file)
