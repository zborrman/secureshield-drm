from passlib.context import CryptContext

# Используем bcrypt для хеширования (стандарт индустрии)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_license_key(key: str) -> str:
    return pwd_context.hash(key)

def verify_license_key(plain_key: str, hashed_key: str) -> bool:
    return pwd_context.verify(plain_key, hashed_key)
