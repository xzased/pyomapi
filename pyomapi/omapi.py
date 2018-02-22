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
import socket
import codecs

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

    def _pack_mac_address(self, mac_address):
        return codecs.decode(mac_address.replace(b':', b''), 'hex')

    def _pack_ip_address(self, ip_address):
        return socket.inet_aton(ip_address)

    def _unpack_mac_address(self, mac_address_bytes):
        value = codecs.encode(mac_address_bytes, 'hex')
        mac_address = ':'.join(value[i:i + 2] for i in range(0, len(value), 2))
        return mac_address

    def _unpack_ip_address(self, ip_address_bytes):
        values = struct.unpack('BBBB', ip_address_bytes)
        ip_address = '.'.join(str(i) for i in values)
        return ip_address

    def close(self):
        """Close the omapi connection if it is open."""
        self.transport.close()

    def check_connection_is_open(self):
        """Raise an OMAPIException unless connected.
        @raises OMAPIException:
        """
        if not self.transport.connection:
            raise OMAPIException("not connected")

    def get_response(self, message, insecure=False):
        """Read the response for the given message.
        @type message: OMAPIMessage
        @type insecure: bool
        @param insecure: avoid an OMAPIException about a wrong authenticator
        @rtype: OMAPIMessage
        @raises OMAPIException:
        @raises socket.error:
        """
        response = self.get_message()
        if not response.is_response(message):
            raise OMAPIException("received message is not the desired response")
        # signature already verified
        if response.authid != self.protocol.defauth and not insecure:
            raise OMAPIException("received message is signed with wrong authenticator")
        return response

    def send_message(self, message, sign=True):
        # """Sends the given message to the connection.
        # @type message: OMAPIMessage
        # @type sign: bool
        # @param sign: whether the message needs to be signed
        # @raises OMAPIException:
        # @raises socket.error:
        # """
        self.check_connection_is_open()

        if sign:
            message.sign(self.authenticator)
        self.transport.write(message.pack())

    def get_message(self):
        data = self.transport.read()
        message = OMAPIMessage(*data)

        if not message.verify(self.authenticator):
            self.close()
            raise OMAPIException("bad omapi message signature")

        return message

    def query_server(self, message):
        """Send the message and receive a response for it.
        @type message: OMAPIMessage
        @rtype: OMAPIMessage
        @raises OMAPIException:
        @raises socket.error:
        """
        self.send_message(message)
        return self.get_response(message)

    def authenticate(self, authenticator):
        """
        @type authenticator: OmapiAuthenticatorBase
        @raises OMAPIException:
        @raises socket.error:
        """
        message = OMAPIMessage.open(b'authenticator')
        message.update_object(authenticator.to_dict())
        response = self.query_server(message)

        if response.opcode != OMAPIMessage.OP_OMAPI_UPDATE:
            raise OMAPIException("received non-update response for open")

        if response.handle == 0:
            raise OMAPIException("received invalid auth id from server")

        authenticator.auth_id = response.handle
        self.authenticator = authenticator

    def add_host(self, ip, mac):
        """Create a host object with given ip address and and mac address.
        @type ip: str
        @type mac: str
        @raises ValueError:
        @raises OMAPIException:
        @raises socket.error:
        """
        msg = OMAPIMessage.open(b"host")
        msg.message.append((b"create", struct.pack("!I", 1)))
        msg.message.append((b"exclusive", struct.pack("!I", 1)))
        msg.obj.append((b"hardware-address", self._pack_mac_address(mac)))
        msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
        msg.obj.append((b"ip-address", self._pack_ip_address(ip)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OP_OMAPI_UPDATE:
            raise OMAPIException("add failed")

    def del_host(self, mac):
        """Delete a host object with with given mac address.
        @type mac: str
        @raises ValueError:
        @raises OMAPIException:
        @raises socket.error:
        """
        msg = OMAPIMessage.open(b"host")
        msg.obj.append((b"hardware-address", self._pack_mac_address(mac)))
        msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OP_OMAPI_UPDATE:
            raise ObjectNotFound()
        if response.handle == 0:
            raise OMAPIException("received invalid handle from server")
        response = self.query_server(OMAPIMessage.delete(response.handle))
        if response.opcode != OMAPIMessage.OP_OMAPI_STATUS:
            raise OMAPIException("delete failed")

    def lookup_ip_host(self, mac):
        """Lookup a host object with with given mac address.
        @type mac: str
        @raises ValueError:
        @raises OMAPIException:
        @raises socket.error:
        """
        msg = OMAPIMessage.open(b"host")
        msg.obj.append((b"hardware-address", self._pack_mac_address(mac)))
        msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OP_OMAPI_UPDATE:
            raise ObjectNotFound()
        try:
            return self._unpack_ip_address(dict(response.obj)[b"ip-address"])
        except KeyError:  # ip-address
            raise ObjectNotFound()

    def lookup_ip(self, mac):
        """Look for a lease object with given mac address and return the
        assigned ip address.
        @type mac: str
        @rtype: str or None
        @raises ValueError:
        @raises OMAPIException:
        @raises ObjectNotFound: if no lease object with the given mac
                address could be found or the object lacks an ip address
        @raises socket.error:
        """
        msg = OMAPIMessage.open(b"lease")
        msg.obj.append((b"hardware-address", self._pack_mac_address(mac)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OP_OMAPI_UPDATE:
            raise ObjectNotFound()
        try:
            return self._unpack_ip_address(dict(response.obj)[b"ip-address"])
        except KeyError:  # ip-address
            raise ObjectNotFound()

    def lookup_mac(self, ip):
        """Look up a lease object with given ip address and return the
        associated mac address.
        @type ip: str
        @rtype: str or None
        @raises ValueError:
        @raises OMAPIException:
        @raises ObjectNotFound: if no lease object with the given ip
                address could be found or the object lacks a mac address
        @raises socket.error:
        """
        msg = OMAPIMessage.open(b"lease")
        msg.obj.append((b"ip-address", self._pack_ip_address(ip)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OP_OMAPI_UPDATE:
            raise ObjectNotFound()
        try:
            return self._unpack_mac_address(dict(response.obj)[b"hardware-address"])
        except KeyError:  # hardware-address
            raise ObjectNotFound()

    def lookup_host(self, name):
        """Look for a host object with given name and return the
        name, mac, and ip address
        @type name: str
        @rtype: str or None
        @raises ValueError:
        @raises OMAPIException:
        @raises ObjectNotFound: if no host object with the given name
                could be found or the object lacks an ip address or mac
        @raises socket.error:
        """
        msg = OMAPIMessage.open(b"host")
        msg.obj.append((b"name", name.encode('utf-8')))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OP_OMAPI_UPDATE:
            raise ObjectNotFound()
        try:
            ip = self._unpack_ip_address(dict(response.obj)[b"ip-address"])
            mac = self._unpack_mac_address(dict(response.obj)[b"hardware-address"])
            hostname = dict(response.obj)[b"name"]
            return {'ip': ip, 'mac': mac, 'hostname': hostname.decode('utf-8')}
        except KeyError:
            raise ObjectNotFound()

    def add_host_supersede_name(self, ip, mac, name):  # pylint:disable=E0213
        """Add a host with a fixed-address and override its hostname with the given name.
        @type omapi: Omapi
        @type ip: str
        @type mac: str
        @type name: str
        @raises ValueError:
        @raises OMAPIException:
        @raises socket.error:
        """
        msg = OMAPIMessage.open(b"host")
        msg.message.append((b"create", struct.pack("!I", 1)))
        msg.message.append((b"exclusive", struct.pack("!I", 1)))
        msg.obj.append((b"hardware-address", self._pack_mac_address(mac)))
        msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
        msg.obj.append((b"ip-address", self._pack_ip_address(ip)))
        msg.obj.append((b"name", name.encode('utf-8')))
        msg.obj.append((b"statements", 'supersede host-name "{0}";'.format(name).encode('utf-8')))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OP_OMAPI_UPDATE:
            raise OMAPIException("add failed")

    def add_host_without_ip(self, mac):
        """Create a host object with given mac address without assigning a static ip address.
        @type ip: str
        @type mac: str
        @raises ValueError:
        @raises OMAPIException:
        @raises socket.error:
        """
        msg = OMAPIMessage.open(b"host")
        msg.message.append((b"create", struct.pack("!I", 1)))
        msg.message.append((b"exclusive", struct.pack("!I", 1)))
        msg.obj.append((b"hardware-address", self._pack_mac_address(mac)))
        msg.obj.append((b"hardware-type", struct.pack("!I", 1)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OP_OMAPI_UPDATE:
            raise OMAPIException("add failed")

    def lookup_hostname(self, ip):
        """Look up a lease object with given ip address and return the associated client hostname.
        @type ip: str
        @rtype: str or None
        @raises ValueError:
        @raises OMAPIException:
        @raises ObjectNotFound: if no lease object with the given ip
                address could be found or the object lacks a hostname
        @raises socket.error:
        """
        msg = OMAPIMessage.open(b"lease")
        msg.obj.append((b"ip-address", self._pack_ip_address(ip)))
        response = self.query_server(msg)
        if response.opcode != OMAPIMessage.OP_OMAPI_UPDATE:
            raise ObjectNotFound()
        try:
            return (dict(response.obj)[b"client-hostname"])
        except KeyError:  # client hostname
            raise ObjectNotFound()
