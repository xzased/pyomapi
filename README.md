# PyOMAPI

ISC DHCP OMAPI python client.


pyomapi is a Python implementation of the DHCP OMAPI protocol used in the most popular Linux DHCP server from ISC.
It can be used to query and modify leases and other objects exported by an ISC DHCP server. The interaction can be authenticated using HMAC-MD5.
Besides basic ready to use operations, custom interaction can be implemented with limited effort.

## Getting Started

# Server side configugration for ISC DHCP3

To allow a OMAPI access to your ISC DHCP3 DHCP Server you should define the following in your dhcpd.conf config file:

```
key defomapi {
	algorithm hmac-md5;
	secret +bFQtBCta6j2vWkjPkNFtgA==;
};

omapi-key defomapi;
omapi-port 7911;
```

Replace the given secret by a key created on your own!

To generate a key use the following command:


```
tsig-keygen -a HMAC-MD5 defomapi
```

### Installing

```
pip install pyomapi
```

# Example OMAPI lookup

```
import pyomapi

USER = 'defomapi'
HMAC_KEY = '+bFQtBCta6j2vWkjPkNFtgA=='

# ip of some host with a dhcp lease on your dhcp server
lease_ip = '192.168.0.250'
dhcp_server = '127.0.0.1'
# Port of the omapi service
port = 7911

try:
    omapi = pyomapi.OMAPI(dhcp_server=dhcp_server, port=port, user=USER, key=HMAC_KEY)
    mac = omapi.lookup_mac(lease_ip)
    print('{} is currently assigned to mac {}'.format(lease_ip, mac))
except pyomapi.exceptions.ObjectNotFound:
    print('{} is currently not assigned'.format(lease_ip))
except pyomapi.OMAPIException as e:
    print('An error occurred trying to reach the DHCP server: {}'.format(e))
```
