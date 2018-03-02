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

import socket
import struct
import io

from pyomapi.exceptions import OMAPIException


class OMAPITransport:

    RCV_BYTES = 4096
    PROTOCOL_VERSION = 100
    HEADER_SIZE = 24

    def __init__(self, host, port, timeout=None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.connection = socket.socket()
        self.connection.settimeout(self.timeout)
        self.connection.connect((self.host, self.port))
        self.send_start_message()

    def send_start_message(self):
        message = io.BytesIO()
        message.write(struct.pack('!L', self.PROTOCOL_VERSION))
        message.write(struct.pack('!L', self.HEADER_SIZE))

        self.write(message.getvalue())
        response = self.read()

        protocol_version, header_size = struct.unpack('>ii', response)

        if protocol_version != self.PROTOCOL_VERSION:
            raise OMAPIException('Protocol mismatch')
        if header_size != self.HEADER_SIZE:
            raise OMAPIException('Header size mismatch')

    def close(self):
        """
        Close the omapi connection if it is open.
        """
        if self.connection:
            self.connection.close()
            self.connection = None

    def read(self):
        """Read bytes from the connection and hand them to the protocol.
        @raises OMAPIException:
        @raises socket.error:
        """
        if not self.connection:
            raise OMAPIException("not connected")

        try:
            data = self.connection.recv(self.RCV_BYTES)
        except socket.error:
            data = None

        if not data:
            self.close()
            raise OMAPIException("connection closed")

        return data

    def write(self, data):
        """
        Send all of data to the connection.
        :param data: 
        :return: 
        """
        try:
            self.connection.sendall(data)
        except socket.error:
            self.close()
            raise
