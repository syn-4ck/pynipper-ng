
import re

from .rockyou_top_1000 import ROCKYOU_LIST

MINIMUM_LENGTH = 8

def _minimum_length(password: str) -> bool:
    if (len(password) > MINIMUM_LENGTH):
        return True
    return False

def _special_character(password: str) -> bool:
    if (re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password)):
        return True
    return False

def _lowercase_char(password: str) -> bool:
    if (re.search(r'[a-z]', password)):
        return True
    return False

def _uppercase_char(password: str) -> bool:
    if (re.search(r'[A-Z]', password)):
        return True
    return False

def _digit(password: str) -> bool:
    if (re.search(r'\d', password)):
        return True
    return False

def _not_rockyou(password: str) -> bool:
    for top_password in ROCKYOU_LIST:
        if (password.lower() == top_password.lower()):
            return False
    return True

'''
    This method checks the following conditions:
        Password must have:
            - Password length >= 8
            - >=1 uppercase char
            - >=1 lowercase char
            - >=1 special char
            - >=1 digit
            - Not top 1000 in rockyou passwords dictionary
'''
def check_password(password: str) -> bool:
    if (_minimum_length(password) and _special_character(password) and _lowercase_char(password)
        and _uppercase_char(password) and _digit(password)):
        if (_not_rockyou(password)):
            return True
        return False
    return False

# Based on https://github.com/richardstrnad/cisco7decrypt/blob/master/cisco7decrypt.py
def decrypt_cisco_password_7(encrypted_password: str) -> str:

    # This is the well known used salt for the cisco type 7 encryption
    salt = 'dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87'
 
    # The first 2 digits represent the salt index salt[index]
    index = int(encrypted_password[:2])
    # The rest of the string is the encrypted password
    enc_pw = encrypted_password[2:].rstrip()
    # Split the pw string into the hex chars, each cleartext char is two hex chars
    hex_pw = [enc_pw[i:i+2] for i in range(0, len(enc_pw), 2)]
    # Create the cleartext list
    cleartext = []
    # Iterate over the hex list
    for i in range(0, len(hex_pw)):
        '''
        The current salt index equals the starting index + current itteration
        floored by % 53. This is to make sure that the salt index start at 0
        again after it reached 53.
        '''
        cur_index = (i+index) % 53
        # Get the current salt
        cur_salt = ord(salt[cur_index])
        # Get the current hex char as int
        cur_hex_int = int(hex_pw[i], 16)
        # XOR the 2 values (this is the decryption itself, XOR of the salt + encrypted char)
        cleartext_char = cur_salt ^ cur_hex_int
        # Get the char for the XOR'ed INT and append it to the cleartext List
        cleartext.append(chr(cleartext_char))
    return ''.join(cleartext)
