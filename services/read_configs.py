def read_configs(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        configs = f.read().split("\n")

        return configs[:-1]


if __name__ == "__main__":
    res = read_configs("./configs.txt")
    print(res)
