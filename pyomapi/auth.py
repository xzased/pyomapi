# Copyright 2018 Ruben Quinones (ruben.quinones@rackspace.com)
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import binascii
import hmac


class HMACMD5Authenticator:
    """
    HMAC5 based authentication class.
    """
    LENGTH = 16
    ALGORITHM = 'hmac-md5.SIG-ALG.REG.INT.'

    def __init__(self, user, key, auth_id=None):
        """
        Initialize the authenticator class providing 
        the dhcp HMAC user and key.
        
        :param user: DHCP HMAC user
        :param key: Key passphrase
        :param auth_id: Authentication id
        """
        self.user = user
        self.key = binascii.a2b_base64(key)
        self.auth_id = auth_id

    def sign(self, message):
        """
        Sign the message with the provided key.
        
        :param message: OMAPIMessage 
        :return: HMAC signature
        """
        signature = hmac.HMAC(self.key, message).digest()
        return signature

    def to_dict(self):
        """
        Dictionary representation used to initialize authentication.
        
        :return: dict
        """
        data = {
            'name': self.user,
            'algorithm': self.ALGORITHM
        }

        return data
