from datetime import datetime, timedelta
from jose import jwt
from passlib.hash import sha256_crypt

SECRET_KEY = "your-secret-key-at-least-32-chars"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# --- Password Hashing 
def get_password_hash(password: str):
    """แปลงรหัสผ่านเป็นค่า Hash"""
    return sha256_crypt.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    """ตรวจสอบรหัสผ่านว่าตรงกับค่า Hash หรือไม่"""
    return sha256_crypt.verify(plain_password, hashed_password)