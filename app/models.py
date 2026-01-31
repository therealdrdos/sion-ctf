from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class User:
    id: int
    username: str
    password_hash: str
    created_at: datetime


@dataclass
class Challenge:
    id: int
    user_id: int
    vuln_type: str
    difficulty: str
    description: Optional[str]
    container_id: Optional[str]
    flag: str
    status: str
    created_at: datetime


@dataclass
class Session:
    id: int
    user_id: int
    token: str
    expires_at: datetime
