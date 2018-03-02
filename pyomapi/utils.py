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


def pack_list_of_tuples(items):
    """
    Pack a list of tuples containing strings.
    
    :param items: list of tuples
    :return: list
    """
    packed_items = []
    for key, value in items:
        if isinstance(key, str):
            key = key.encode('utf-8')
        if isinstance(value, str):
            value = value.encode('utf-8')
        packed_items.extend((
            struct.pack('!H', len(key)),
            key,
            struct.pack('!L', len(value)),
            value
        ))
    # add end marker
    packed_items.append(b'\x00\x00')
    return packed_items


def unpack_str_from_bytes(data, offset, format_char):
    """
    Unpack a variable string with the length specified at the start 
    of the offset with the given format character.
    
    :param data: byte string
    :param offset: index at which to 
    :param format_char: format character to convert from C
    :return: tuple
    """
    format_size = struct.calcsize(format_char)
    data_size = struct.unpack_from(format_char, data, offset)[0]
    start = offset + format_size
    end = start + data_size
    result = struct.unpack('{}s'.format(data_size), data[start: end])[0]
    remainder = data[end:]
    return result, remainder


def unpack_list_from_bytes(data):
    """
    Unpack a list of tuples from a byte string response and return 
    it with the remainder of the byte string.
    
    :param data: bytes 
    :return: tuple
    """
    items = []
    while True:
        try:
            key, data = unpack_str_from_bytes(data, 0, '!H')
            value, data = unpack_str_from_bytes(data, 0, '!L')
            items.append((key, value))
        except struct.error:
            break
    return items, data


def pack_mac_address(mac_address):
    """
    Pack mac address.
    
    :param mac_address: mac address string
    :return: bytes
    """
    return codecs.decode(mac_address.replace(':', ''), 'hex')


def pack_ip_address(ip_address):
    """
    Pack ip address.
    
    :param ip_address: ip address string
    :return: bytes
    """
    return socket.inet_aton(ip_address)


def unpack_mac_address(mac_address_bytes):
    """
    Unpack a mac address from bytes.
    
    :param mac_address_bytes: bytes
    :return: str
    """
    value = codecs.encode(mac_address_bytes, 'hex')
    mac_address = ':'.join(value[i:i + 2] for i in range(0, len(value), 2))
    return mac_address


def unpack_ip_address(ip_address_bytes):
    """
    Unpack an ip address from bytes.
    
    :param ip_address_bytes: bytes
    :return: str
    """
    values = struct.unpack('BBBB', ip_address_bytes)
    ip_address = '.'.join(str(i) for i in values)
    return ip_address
