""" PROJECT : Functional Programming and Object-Oriented Programming
 
    FILENAME : main.py
 
    DESCRIPTION :
        ...
 
    FUNCTIONS :
        main()
 
    NOTES :
        - ...
 
    AUTHOR(S) : Noah Da Silva               START DATE : 2022.04.06 (YYYY.MM.DD)
 
    CHANGES :
        - ...
 
    VERSION     DATE        WHO             DETAILS
    0.1.0      2022.04.06  Noah            Creation of project.
"""

from dataclasses import dataclass, field
from datetime import datetime
from hashlib import pbkdf2_hmac
from uuid import uuid1, uuid4


def generate_salt() -> str:
    """Generate a salt for the user's password."""
    return str(uuid4())


def generate_id() -> str:
    """Generate a unique user ID (UUID) using the uuid module."""
    return str(uuid1())


def generate_datetime() -> str:
    return f"{datetime.utcnow().isoformat()}+00:00"


@dataclass
class User:
    """Keeps inventory of user's information."""
    name: str
    username: str
    email: str
    password: str
    date_of_birth: str
    password_salt: str = field(init=False, default_factory=generate_salt)
    previous_emails: list[str] = field(init=False, default_factory=list)
    is_active: bool = field(init=False, default=True)
    is_staff: bool = field(init=False, default=False)
    is_admin: bool = field(init=False, default=False)
    account_id: str = field(init=False, default_factory=generate_id)
    date_joined: str = field(init=False, default_factory=generate_datetime)
    last_login: str = field(init=False, default=None)

    def __post_init__(self):
        """Salt and hash the password to be stored back into the user."""
        self.make_password()

    def make_password(self) -> None:
        """Salt and hash a user's password for secure storage of credentials."""
        self.password = pbkdf2_hmac(
            "sha512", 
            self.password.encode(), 
            self.password_salt.encode(), 
            iterations=205_735
        ).hex()


class UserManagement:
    def check_password(user: User, password_input: str) -> bool:
        """Compare the hashed salt and password input to the user's hashed password."""
        if pbkdf2_hmac(
            "sha512", 
            password_input.encode(), 
            user.password_salt.encode(), 
            iterations=205_735
        ).hex() == user.password:
            return True
        return False

    def update_last_login(user: User) -> None:
        user.last_login = generate_datetime()