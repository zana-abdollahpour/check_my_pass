""" Checks passwords security """

import requests
import hashlib
import sys


def request_api_data(query_char):
    URL = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(URL)

    if res.status_code != 200:
        raise RuntimeError(f"Error fetching: {res.status_code}")
    return res


def get_passwords_leak_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if str(h) == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_chars, tail = sha1_password[:5], sha1_password[5:]

    response = request_api_data(first5_chars)
    return get_passwords_leak_count(response, tail)


def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f"'{password}' found {count} times... consider changing it!")
        else:
            print(f"'{password}' was not found. Password is safe!")
        return "Done!"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
