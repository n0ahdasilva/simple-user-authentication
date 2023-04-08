from hashlib import pbkdf2_hmac


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