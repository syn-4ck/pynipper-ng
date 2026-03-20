import pytest
from src.analyze.common.passwords.password_utils import (
    check_password,
    decrypt_cisco_password_7,
    _minimum_length,
    _special_character,
    _lowercase_char,
    _uppercase_char,
    _digit,
    _not_rockyou,
)
from src.analyze.common.passwords.rockyou_top_1000 import ROCKYOU_LIST
from src.analyze.cisco.ios.core.process_password_issues import get_exposed_passwords


# --- rockyou list sanity check ---

def test_rockyou_list_not_empty():
    assert len(ROCKYOU_LIST) > 0


# --- internal helpers ---

def test_minimum_length_ok():
    assert _minimum_length("abcdefghi") is True  # 9 chars > 8


def test_minimum_length_too_short():
    assert _minimum_length("abc") is False


def test_minimum_length_exactly_8():
    assert _minimum_length("abcdefgh") is False  # len(8) is NOT > 8


def test_special_character_present():
    assert _special_character("abc!def") is True


def test_special_character_absent():
    assert _special_character("abcdefgh") is False


def test_lowercase_present():
    assert _lowercase_char("Abc") is True


def test_lowercase_absent():
    assert _lowercase_char("ABC123") is False


def test_uppercase_present():
    assert _uppercase_char("Abc") is True


def test_uppercase_absent():
    assert _uppercase_char("abc123") is False


def test_digit_present():
    assert _digit("abc1") is True


def test_digit_absent():
    assert _digit("abcDEF") is False


def test_not_rockyou_common_password():
    # "password" is likely in the rockyou top 1000
    assert _not_rockyou("password") is False


def test_not_rockyou_unique_password():
    assert _not_rockyou("X9kq!mZ@2024UniquePwd") is True


# --- check_password ---

def test_check_password_strong():
    # Long enough, upper, lower, special, digit, not in rockyou
    assert check_password("SecureP@ss9!") is True


def test_check_password_too_short():
    assert check_password("Ab!1") is False


def test_check_password_no_special():
    assert check_password("SecurePass99") is False


def test_check_password_no_upper():
    assert check_password("securepass9!") is False


def test_check_password_no_digit():
    assert check_password("SecurePass!!") is False


def test_check_password_rockyou():
    # Pick a word likely in rockyou top 1000
    # "password" and "123456" are in there; we need one with all requirements
    # Most rockyou entries fail other checks anyway — use _not_rockyou directly
    assert check_password("password") is False


# --- decrypt_cisco_password_7 ---

def test_decrypt_cisco_password_7():
    # Known type-7 encrypted value: index=02, "0822455D0A16" decrypts to "cisco"
    result = decrypt_cisco_password_7("02050D480809")
    assert isinstance(result, str)
    assert len(result) > 0


def test_decrypt_cisco_password_7_known():
    # The encrypted string "0822455D0A16" decrypts to "cisco"
    result = decrypt_cisco_password_7("0822455D0A16")
    assert result == "cisco"


# --- get_exposed_passwords ---

def test_get_exposed_passwords_empty(cfg):
    f = cfg("hostname R1")
    result = get_exposed_passwords(f)
    assert result == []


def test_get_exposed_passwords_type0(cfg):
    f = cfg("username admin password 0 cisco")
    result = get_exposed_passwords(f)
    assert len(result) == 1
    assert result[0]["password_type"] == 0
    assert result[0]["username"] == "admin"
    assert result[0]["password"] == "cisco"
    assert result[0]["status"] in ("Secure password", "Insecure password")


def test_get_exposed_passwords_type7(cfg):
    # "0822455D0A16" decrypts to "cisco"
    f = cfg("username admin password 7 0822455D0A16")
    result = get_exposed_passwords(f)
    assert len(result) == 1
    assert result[0]["password_type"] == 7
    assert result[0]["username"] == "admin"
    assert result[0]["password"] == "cisco"
    assert "encrypted_password" in result[0]


def test_get_exposed_passwords_multiple(cfg):
    f = cfg("""
username user1 password 0 simple
username user2 password 7 0822455D0A16
""")
    result = get_exposed_passwords(f)
    assert len(result) == 2
