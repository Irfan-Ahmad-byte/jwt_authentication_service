from pydantic_settings import BaseSettings
from dotenv import find_dotenv, load_dotenv

class Configs(BaseSettings):
    """
    Configuration class to hold all the configurations for the application.
    """

    # Load environment variables from .env file
    load_dotenv(find_dotenv())

    # Database configuration
    DB_HOST: str
    DB_PORT: int = 5432
    DB_NAME: str
    DB_USER: str
    DB_URL: str
    DB_PASSWORD: str
    REDIS_ENABLED: bool = True
    REDIS_URL: str = "redis://localhost:6379/0"
    SECRET_KEY: str = "secret_key"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 30
    IS_REDIS_RUNNING: bool = False

    # Other configurations can be added here

    # Example: API keys, secret keys, etc.
    class Config:
        env_file = ".env"

settings = Configs()