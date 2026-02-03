from typing import Any


class V2rayConfig:
    link: str
    parsed_data: dict[str, Any]

    def __init__(self, link: str, parsed_data: dict[str, Any]) -> None:
        self.link = link
        self.parsed_data = parsed_data
