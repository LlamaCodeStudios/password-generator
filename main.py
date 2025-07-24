# Made my llama code studios
# Licenced under the 

import random
import string
from time import sleep

charlimit = 6  # Default length of the password
charlimit = input("Enter the length of the password (default is 6): ")

def gerarate_password(length=charlimit):
    print("Generating a random password...")
    """Generate a random password with letters, digits, and punctuation."""
    chars = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(chars) for _ in range(length))
    return password

print("Your password has been generated. \n Please type \"Yes, do as I say\" to see your password.")
if input() == "Yes, do as I say":
    try:
        length = int(charlimit)
    except ValueError:
        print("Invalid input. Using default length of 6.")
        length = 6
    password = gerarate_password(length)
    print(f"Your password is: {password}")
    input("Press Enter to exit the program.")
else:
    print("You did not authenticate. Exiting the program.")    
    sleep(3.0)
    exit()
