import os

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "default-secret-key")
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///diary.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
