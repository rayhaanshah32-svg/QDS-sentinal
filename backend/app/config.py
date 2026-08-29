from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "QDS Sentinel"
    app_version: str = "0.1.0"
    api_prefix: str = "/api/v1"
    host: str = "0.0.0.0"
    port: int = 8000
    default_signature_length: int = 16
    default_bell_state: str = "PHI_PLUS"


settings = Settings()
