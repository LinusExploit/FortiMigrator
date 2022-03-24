# FortiParser
<br>
This script reads Fortinet config file and store the policies, addresses, address groups inside memory. Then it outputs the policies that need to be migrated manually due to having 
an unsupported feature such as Fortinet ISDB objects, web filter values, and wildcard inside FQDN objects. 
<br>
<br>

The Script now support Migrating Fortinet VPN tunnels into PAN firewall config file which 
can be then uploaded into the firewall via xpath commands. 

<br>
1- creates ike gateways
<br>
2- create ike profiles
<br>
3- creates ipsec profiles
<br>
4- create the ipsec tunnel and maps the proxies from fortinet too
<br>



The script uses classes and this is an example of the content of the main file :
<br>
from Forti import Forti
<br>

if __name__ == '__main__':
<br>
    firewall1 = Forti()
    <br>
    firewall1.parse_config('fortinet.conf')
    <br>
    firewall1.parse_policies()
    <br>
    firewall1.unsupported_policies()
    <br>
    firewall1.parse_addresses()
    <br>
    firewall1.parse_adgroups()
    <br>
    firewall1.unsupported_addresses()
    <br>

