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

import secrets
import hmac
import struct
import io

from pyomapi import utils
from pyomapi.exceptions import OMAPIException


class OMAPIMessage:
    # OP codes
    OMAPI_OP_OPEN = 1
    OMAPI_OP_REFRESH = 2
    OMAPI_OP_UPDATE = 3
    OMAPI_OP_NOTIFY = 4
    OMAPI_OP_STATUS = 5
    OMAPI_OP_DELETE = 6

    # OP code map
    OP_MAP = {
        OMAPI_OP_OPEN: 'open',
        OMAPI_OP_REFRESH: 'refresh',
        OMAPI_OP_UPDATE: 'update',
        OMAPI_OP_NOTIFY: 'notify',
        OMAPI_OP_STATUS: 'status',
        OMAPI_OP_DELETE: 'delete',
    }

    def __init__(self, auth_id=0, opcode=0, handle=0, transmission_id=0,
                 response_id=0, message=[], obj=[], signature=b''):
        self.auth_id = auth_id
        self.opcode = opcode
        self.handle = handle
        self.transmission_id = transmission_id
        self.response_id = response_id
        self.message = message
        self.obj = obj
        self.signature = signature

        if not self.transmission_id:
            self.set_transmission_id()

        self.buffer = io.BytesIO()

    @classmethod
    def open(cls, type_name):
        return cls(opcode=cls.OMAPI_OP_OPEN, message=[('type', type_name)])

    @classmethod
    def update(cls, handle):
        return cls(opcode=cls.OMAPI_OP_UPDATE, handle=handle)

    @classmethod
    def delete(cls, handle):
        return cls(opcode=cls.OMAPI_OP_DELETE, handle=handle)

    @classmethod
    def from_bytes(cls, data):
        ids = struct.unpack('!LLLLLL', data[:24])
        obj, signature = utils.unpack_list_from_bytes(data[26:])
        return cls(*ids, obj=obj, signature=signature)

    def get_value(self, for_signature=False):
        data = [
            struct.pack('!L', len(self.signature)),
            struct.pack('!L', self.opcode),
            struct.pack('!L', self.handle),
            struct.pack('!L', self.transmission_id),
            struct.pack('!L', self.response_id),
        ]
        data.expand(utils.pack_list_of_tuples(self.message))
        data.expand(utils.pack_list_of_tuples(self.obj))

        if for_signature:
            data.insert(0, struct.pack('!L', self.auth_id))
            data.append(self.signature)

        self.buffer.write(*data)

        return self.buffer.getvalue()

    def clear(self):
        self.buffer.truncate(0)
        self.buffer.seek(0)

    def consume(self, for_signature=False):
        value = self.get_value(for_signature=for_signature)
        self.clear()

        return value

    def sign(self, authenticator):
        self.auth_id = authenticator.auth_id
        # match the authenticator signature length
        self.signature = b'\0' * authenticator.LENGTH
        self.signature = authenticator.sign(self.consume(for_signature=True))
        if len(self.signature) != authenticator.LENGTH:
            raise OMAPIException('Signature length mismatch')

    def verify(self, authenticator):
        signature = authenticator.sign(self.consume(for_signature=True))
        return hmac.compare_digest(signature, self.signature)

    def is_response(self, message):
        return self.response_id == message.transmission_id

    def update_object(self, update):
        self.obj = [(key, value) for key, value in self.obj if key not in update]
        self.obj.extend(update.items())

    def set_transmission_id(self):
        self.transmission_id = secrets.SystemRandom().randrange(0, 1 << 32)
