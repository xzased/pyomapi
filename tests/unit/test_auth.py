import hmac

import pytest

from pyomapi.auth import HMACMD5Authenticator


TEST_AUTH_USER = 'testuser'
TEST_AUTH_KEY = 'cNGknqtjqExBclMiiBcOJQ=='


@pytest.fixture
def authenticator():
    """
    Instantiate the HMAC authenticator with 
    
    :return: HMACMD5Authenticator
    """

    return HMACMD5Authenticator(user=TEST_AUTH_USER, key=TEST_AUTH_KEY)


def test_auth_sign(authenticator):
    signed = authenticator.sign(b'\x00\x00')
    expected = b"0\x84s\xe3Q\x8e'<\x9c\x84\x03\xea\xdb_\x96P"
    assert hmac.compare_digest(signed, expected)



def test_auth_to_dict(authenticator):
    expected = {
        'name': TEST_AUTH_USER,
        'algorithm': HMACMD5Authenticator.ALGORITHM
    }
    assert authenticator.to_dict() == expected
