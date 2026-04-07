import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    DATABASE_URL: str
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    OPENAI_API_KEY: str = ""
    APP_ENV: str = "development"

    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""
    GREYNOISE_API_KEY: str = ""

    # הוספת שדות עבור Threat Intelligence ו-Redis
    OTX_API_KEY: str = ""
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    FRONTEND_URL: str = ""
    ALLOWED_ORIGINS: str = ""
    CORS_ALLOW_ORIGIN_REGEX: str = r"https://.*\.vercel\.app"

    @property
    def allowed_origins_list(self) -> list[str]:
        default_origins = [
            "http://localhost:5000",
            "http://localhost:5173",
            "http://127.0.0.1:5000",
            "http://127.0.0.1:5173",
        ]
        configured_origins = []
        if self.FRONTEND_URL:
            configured_origins.append(self.FRONTEND_URL.strip())
        if self.ALLOWED_ORIGINS:
            configured_origins.extend(
                origin.strip()
                for origin in self.ALLOWED_ORIGINS.split(",")
                if origin.strip()
            )

        origins = []
        seen = set()
        for origin in [*configured_origins, *default_origins]:
            if origin and origin not in seen:
                origins.append(origin)
                seen.add(origin)
        return origins

    class Config:
        env_file = ".env"

settings = Settings()
