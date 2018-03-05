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

import struct

from pyomapi.exceptions import OMAPIException, ObjectNotFound
from pyomapi.auth import HMACMD5Authenticator
from pyomapi.message import OMAPIMessage
from pyomapi.transport import OMAPITransport


class OMAPI:

    def __init__(self, dhcp_server, port, username, key, timeout=None):
        self.dhcp_server = dhcp_server
        self.port = port
        self.transport = OMAPITransport(self.dhcp_server,
                                        self.port,
                                        timeout=timeout)
        self.authenticator = None
        auth = HMACMD5Authenticator(username, key)
        self.authenticate(auth)

    def close(self):
        self.transport.close()

    def check_connection_is_open(self):
        if not self.transport.connection:
            raise OMAPIException('not connected')

    def get_response(self, message, sign=True):
        response = self.get_message(sign=sign)
        if not response.is_response(message):
            raise OMAPIException('received message is not the desired response')
        # signature already verified
        if sign and response.auth_id != self.authenticator.auth_id:
            raise OMAPIException('received message is signed with wrong authenticator')
        return response

    def send_message(self, message, sign=True):
        self.check_connection_is_open()

        if sign:
            message.sign(self.authenticator)
        self.transport.write(message.consume())

    def get_message(self, sign=True):
        data = self.transport.read()
        message = OMAPIMessage.from_bytes(data)

        if sign and not message.verify(self.authenticator):
            self.close()
            raise OMAPIException('bad omapi message signature')

        return message

    def query_server(self, message, sign=True):
        self.send_message(message, sign=sign)
        return self.get_response(message, sign=sign)

    def authenticate(self, authenticator):
        message = OMAPIMessage.open(b'authenticator')
        message.update_object(authenticator.to_dict())
        response = self.query_server(message, sign=False)

        if response.opcode != OMAPIMessage.OMAPI_OP_UPDATE:
            raise OMAPIException('received non-update response for open')

        if response.handle == 0:
            raise OMAPIException('received invalid auth id from server')

        authenticator.auth_id = response.handle
        self.authenticator = authenticator

    def add_host(self, ip, mac):
        msg = OMAPIMessage.open(b'host')
        msg.message.append((b'create', struct.pack('!I', 1)))
        msg.message.append((b'exclusive', struct.pack('!I', 1)))
        msg.obj.append((b'hardware-address', utils.pack_mac_address(mac)))
        msg.obj.append((b'hardware-type', struct.pack('!I', 1)))
        msg.obj.append((b'ip-address', utils.pack_ip_address(ip)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OMAPI_OP_UPDATE:
            raise OMAPIException('add failed')

    def delete_host(self, mac):
        msg = OMAPIMessage.open(b'host')
        msg.obj.append((b'hardware-address', utils.pack_mac_address(mac)))
        msg.obj.append((b'hardware-type', struct.pack('!I', 1)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OMAPI_OP_UPDATE:
            raise ObjectNotFound()
        if response.handle == 0:
            raise OMAPIException('received invalid handle from server')
        response = self.query_server(OMAPIMessage.delete(response.handle))
        if response.opcode != OMAPIMessage.OMAPI_OP_STATUS:
            raise OMAPIException('delete failed')

    def lookup_ip_host(self, mac):
        msg = OMAPIMessage.open(b'host')
        msg.obj.append((b'hardware-address', utils.pack_mac_address(mac)))
        msg.obj.append((b'hardware-type', struct.pack('!I', 1)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OMAPI_OP_UPDATE:
            raise ObjectNotFound()
        try:
            return utils.unpack_ip_address(dict(response.obj)[b'ip-address'])
        except KeyError:  # ip-address
            raise ObjectNotFound()

    def lookup_ip(self, mac):
        msg = OMAPIMessage.open(b'lease')
        msg.obj.append((b'hardware-address', utils.pack_mac_address(mac)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OMAPI_OP_UPDATE:
            raise ObjectNotFound()
        try:
            return utils.unpack_ip_address(dict(response.obj)[b'ip-address'])
        except KeyError:  # ip-address
            raise ObjectNotFound()

    def lookup_mac(self, ip):
        msg = OMAPIMessage.open(b'lease')
        msg.obj.append((b'ip-address', utils.pack_ip_address(ip)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OMAPI_OP_UPDATE:
            raise ObjectNotFound()
        try:
            return utils.unpack_mac_address(dict(response.obj)[b'hardware-address'])
        except KeyError:  # hardware-address
            raise ObjectNotFound()

    def lookup_host(self, name):
        msg = OMAPIMessage.open(b'host')
        msg.obj.append((b'name', name.encode('utf-8')))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OMAPI_OP_UPDATE:
            raise ObjectNotFound()
        try:
            ip = utils.unpack_ip_address(dict(response.obj)[b'ip-address'])
            mac = utils.unpack_mac_address(dict(response.obj)[b'hardware-address'])
            hostname = dict(response.obj)[b'name']
            return {'ip': ip, 'mac': mac, 'hostname': hostname.decode('utf-8')}
        except KeyError:
            raise ObjectNotFound()

    def add_host_supersede_name(self, ip, mac, name):  # pylint:disable=E0213
        msg = OMAPIMessage.open(b'host')
        msg.message.append((b'create', struct.pack('!I', 1)))
        msg.message.append((b'exclusive', struct.pack('!I', 1)))
        msg.obj.append((b'hardware-address', utils.pack_mac_address(mac)))
        msg.obj.append((b'hardware-type', struct.pack('!I', 1)))
        msg.obj.append((b'ip-address', utils.pack_ip_address(ip)))
        msg.obj.append((b'name', name.encode('utf-8')))
        msg.obj.append((b'statements', 'supersede host-name "{0}";'.format(name).encode('utf-8')))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OMAPI_OP_UPDATE:
            raise OMAPIException('add failed')

    def add_host_without_ip(self, mac_address):
        message_data = [
            (b'create', struct.pack('!I', 1)),
            (b'exclusive', struct.pack('!I', 1))
        ]
        obj_data = [
            (b'hardware-address', utils.pack_mac_address(mac_address)),
            (b'hardware-type', struct.pack('!I', 1))
        ]
        message = OMAPIMessage.open(b'host')
        message.message.extend(message_data)
        message.obj.extend(obj_data)
        response = self.query_server(message)
        if response.opcode != OMAPIMessage.OMAPI_OP_UPDATE:
            raise OMAPIException('Failed to add host {}'.format(mac_address))

    def lookup_hostname(self, ip):
        obj_data = [
            (b'ip-address', utils.pack_ip_address(ip))
        ]
        message = OMAPIMessage.open(b'lease')
        message.obj.extend(obj_data)
        response = self.query_server(message)
        if response.opcode != OMAPIMessage.OMAPI_OP_UPDATE:
            raise ObjectNotFound()
        try:
            hostname = dict(response.obj)[b'client-hostname']
            return hostname
        except KeyError:  # client hostname
            raise ObjectNotFound()
