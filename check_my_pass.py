""" Checks passwords security """

import hashlib
import sys

import requests


def request_api_data(query_char):
    """fetchs data about password security from api

    Args:
        query_char (str): first 5 letters of hashed password

    Raises:
        RuntimeError: when the response is not OK

    Returns:
        Response: the raw response from the api
    """
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url, timeout=40)

    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}")
    return res


def get_passwords_leak_count(hashes, hash_to_check):
    """counts how many times the password has been pwned

    Args:
        hashes (str): the pwned passwords list fetched from api
        hash_to_check (bool): the tail part version of entered password, from 5th char to the end

    Returns:
        int: the count of password leakage
    """
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if str(h) == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    """hashes password and fetchs data from api

    Args:
        password (str): password to check

    Returns:
        int: the count of password leakage
    """
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_chars, tail = sha1_password[:5], sha1_password[5:]

    response = request_api_data(first5_chars)
    return get_passwords_leak_count(response, tail)


def main(args):
    """main logic executer

    Args:
        args (list[str]): a list of passswords to check

    Returns:
        str: a string of "Done!" showing that execution has ended
    """
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"'{password}' found {count} times... consider changing it!")
        else:
            print(f"'{password}' was not found. Password is safe!")
        return "Done!"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
