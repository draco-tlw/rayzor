from services.read_channels import read_channels

CHANNELS_FILE = "./channels.txt"
OUTPUT_FILE = "clean-channels.txt"


def main():
    print("--- Channel Cleanup ---")
    print(f"Reading from: {CHANNELS_FILE}")

    channels = read_channels(CHANNELS_FILE)

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
        print(f"Saving to: {OUTPUT_FILE}")
        with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
            for channel in channels:
                f.write(channel + "\n")

        print("\nSuccess! List cleaned and sorted.")
    else:
        print(f"No channels found in {CHANNELS_FILE} (or file is missing).")


if __name__ == "__main__":
    main()
