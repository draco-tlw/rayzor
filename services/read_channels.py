def read_channels(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        channels = f.read().split("\n")

        return channels[:-1]


if __name__ == "__main__":
    res = read_channels("./channels.txt")
    print(res)
