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

MONTHS = {
    1: "January",
    2: "February",
    3: "March",
    4: "April",
    5: "May",
    6: "June",
    7: "July",
    8: "August",
    9: "September",
    10: "October",
    11: "November",
    12: "December",
}


def get_long_date(date: str) -> str:
    """Return a clean date from a YYYY-MM-DD format."""
    date = date.split("-")
    date[2] = date[2][0:2]
    month_name = MONTHS.get(int(date[1]))

    if month_name is not None:
        return f"{month_name} {date[2]}, {date[0]}"
    else:
        raise ValueError("Invalid month number, maybe date formatting is incorrect?")
