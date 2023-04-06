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

from dataclasses import asdict

from user import User, UserManagement
from data_visual import get_long_date


def main() -> None:
    """Program's main function."""
    print()

    # Create a user.
    user = User(
        name="John Smith",
        username="johnsmith",
        email="email@example.com",
        password="verysecurepassword123!",
        date_of_birth="1995-07-17",
    )

    # Print out its entries.
    for key, value in asdict(user).items():
        print(f"{key}: {value}")
    print()

    print(f"Clean birthday: {get_long_date(user.date_of_birth)}\n")

    # Verify password.
    password_inputs = [
        "unsecurepassword123!",
        "verysecurepassword123!"
    ]
    for password in password_inputs:
        print(f"Logging attempt with input: {password}")
        if UserManagement.check_password(
            user=user, 
            password_input=password
           ) is True:
            print(f"-> Authentication successful!")
            UserManagement.update_last_login(user)
            print(f"Last login: {user.last_login}")
        else:
            print(f"-> Authentication failed!")
        print()


if __name__ == "__main__":
    main()