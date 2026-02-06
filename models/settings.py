from pydantic import BaseModel, ValidationError


class Settings(BaseModel):
    PROXY_URL: str
    MAX_CONCURRENT_SCANS: int
    MAX_PAGES: int
    CORE_PATH: str
    BASE_PORT: int
    TEST_URL: str
    TIMEOUT: int
    BATCH_SIZE: int  # Pydantic will auto-convert "500" -> 500
    MAX_WORKERS: int
    MAX_RETRIES: int


def load_settings(file_path: str):
    try:
        with open(file_path, "r") as f:
            # .model_validate_json() handles the casting and validation
            return Settings.model_validate_json(f.read())
    except ValidationError as e:
        print(f"Configuration Error: {e}")
        raise
