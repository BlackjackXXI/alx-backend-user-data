#!/usr/bin/env python3
"""encrypt pswd
"""
import bcrypt

def hash_password(password: str) -> bytes:
    """hashing passwd
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def is_valid(hashed_password: bytes, password: str) -> bool:
    """cheking passwd
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
