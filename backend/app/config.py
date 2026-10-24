from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "postgresql://iot_user:iot_pass@localhost:5432/iot_scanner"
    redis_url: str = "redis://localhost:6379/0"
    shodan_api_key: str = ""
    censys_api_key: str = ""
    collect_interval_hours: int = 24
    target_countries: list[str] = ["IR", "RU"]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
