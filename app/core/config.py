from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://postgres:yourpassword@localhost:5432/trustguard"
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    OPENAI_API_KEY: str = ""
    APP_ENV: str = "development"
    
    # API Keys חדשים
    VIRUSTOTAL_API_KEY: str = "7a32243de1bdb58cfb2cd7644f2993f6cbba920c81e13329dc80a780a535fa08"
    ABUSEIPDB_API_KEY: str = ""
    GREYNOISE_API_KEY: str = "825d8c7b-006f-4bdb-b73f-b9cc5f77ab12"

    class Config:
        env_file = ".env"

settings = Settings()