from openai import OpenAI
from app.core.config import settings

client = OpenAI(
    api_key="sk-5931a0b186f74353b24458470746f730",
    base_url="https://api.deepseek.com"
)