#This is an object to represent PANOS firewall
import xml.etree.ElementTree as ET
import ipaddress


# a dictionary for interface mapping from fortinet to palo alto firewall for vpn usage int only
mapped_interfaces = {'forti-int1': 'pan-int1', 'forti-int2': 'pan-int2', 'forti-int3': 'pan-int3'}

# a dictionary of fortinet vpn ip addresses and their masks.
mapped_ips = {
    'ip1':'mask1',
    'ip2':'mask2',
    'ip3':'mask3',
    'ip4':'mask4',

}

# a dictionary to map encryption from fortinet naming to pan naming
mapped_encryption = {
                     '3des': '3des',
                     'aes128':'aes-128-cbc',
                     'aes256' : 'aes-256-cbc'
                     }

# a dictionary to map hashing from fortinet naming to pan naming

mapped_hash  = {
    'sha1':'sha1',
    'sha256':'sha256',
    'md5' : 'md5'

}

# a dictionary to map dhgroup  from fortinet naming to pan naming

mapped_dhgrps = {
    '1':'group1',
    '2' : 'group2',
    '5' : 'group5',
    '14':'group14',

}



# a PAN firewall object
class PAN(object):
    def __init__(self):
        self.tree = None            # the xml tree structure representing the PAN firewall
        self.policies = []          # list of policies initialized as empty.

     # loading the xml tree from a base line file that is almost empty
    def load_config(self, file_name):
        self.tree = ET.parse(file_name)     # loading the xml tree from a base line file that is almost empty

    # add an IKE profile to the xml config file
    def Add_IKE_PROFILE(self, tunnel):
        global mapped_phase1_parameters
        global mapped_hash
        global mapped_encryption
        global mapped_dhgrps

        # get the root of the xml tree
        root = self.tree.getroot()

        # get the parent node for ike crypto profiles
        ike_profiles = root.find('./devices/entry[@name=\'localhost.localdomain\']/network/ike/crypto-profiles/ike-crypto-profiles')

        # build the xml structure for the ike profile
        entry = ET.SubElement(ike_profiles, "entry")
        entry.attrib['name'] = tunnel['name']+ '_IKE_PROFILE'

        encryption = ET.SubElement(entry, "encryption")
        for v in tunnel['encryption']:
            member_encryption = ET.SubElement(encryption, "member")
            member_encryption.text = mapped_encryption[v]

        hash = ET.SubElement(entry, "hash")
        for v in tunnel['hash']:
            member_hash = ET.SubElement(hash, "member")
            member_hash.text = mapped_hash[v]

        dhgrp = ET.SubElement(entry, "dh-group")
        member_dh = ET.SubElement(dhgrp, "member")
        member_dh.text = mapped_dhgrps[tunnel['dhgrp']]

        lifetime = ET.SubElement(entry, "lifetime")
        hours = ET.SubElement(lifetime, "hours")
        hours.text = '8'


        # write the output to the xml file
        with open('mapped.xml', 'a') as f:
            self.tree.write(f, encoding='unicode')

    # a function to add the ike gateway to the xml tree config file.
    def Add_IKE_GW(self, tunnel):
        global mapped_interfaces
        # specs is a dictionary of the values to be added to the IKE gateway
        # get the root of the xml file that has the configuration
        root = self.tree.getroot()

        # get the xpath of the ike gateway entries

        gateway = root.find('./devices/entry[@name=\'localhost.localdomain\']/network/ike/gateway')
        # build the xml gateway structure
        entry = ET.SubElement(gateway, "entry")
        entry.attrib['name'] = tunnel['name']

        authentication = ET.SubElement(entry, "authentication")
        psk = ET.SubElement(authentication, "pre-shared-key")
        key = ET.SubElement(psk, "key")
        key.text = '-AQ==jyY9uenm5yWYZigds5nhb6wxK7s=hDPXDC+F5X5RCnfbo62VTA=='

        protocol = ET.SubElement(entry, "protocol")

        ikev1 = ET.SubElement(protocol, "ikev1")
        dpd_1 = ET.SubElement(ikev1, "dpd")
        enable_1 = ET.SubElement(dpd_1, "enable")
        enable_1.text = "yes"


        ikev2 = ET.SubElement(protocol, "ikev2")
        dpd_2 = ET.SubElement(ikev2, "dpd")
        enable_2 = ET.SubElement(dpd_2, "enable")
        enable_2.text = "yes"

        if tunnel['ike-version'] == 'ikev1':
            ike_profile = ET.SubElement(ikev1, "ike-crypto-profile")
            ike_profile.text = tunnel['name'] + '_IKE_PROFILE'
            ike_version = ET.SubElement(protocol, "version")
            ike_version.text = "ikev1"

        else:
            ikev2_profile = ET.SubElement(ikev2, "ike-crypto-profile")
            ikev2_profile.text = tunnel['name'] + '_IKE_PROFILE'
            ike_version = ET.SubElement(protocol, "version")
            ike_version.text = "ikev2"

        local_address = ET.SubElement(entry, "local-address")
        ip = ET.SubElement(local_address, "ip")
        ip.text = tunnel['local-gw']+mapped_ips[tunnel['local-gw']]



        interface = ET.SubElement(local_address, "interface")
        interface.text = mapped_interfaces[tunnel['interface']]

        protocol_common = ET.SubElement(entry, "protocol-common")

        nat_traversal = ET.SubElement(protocol_common, "nat-traversal")
        enable_traversal = ET.SubElement(nat_traversal, "enable")
        if tunnel['nattraversal'] == 'disable':
            enable_traversal.text = "no"

        else:
            enable_traversal.text = "yes"

        fragmentation = ET.SubElement(protocol_common, "fragmentation")
        enable_fragmentation = ET.SubElement(fragmentation, "enable")
        enable_fragmentation.text = "no"

        passive_mode = ET.SubElement(protocol_common, "passive-mode")
        passive_mode.text = "no"

        peer_address = ET.SubElement(entry, "peer-address")
        peer_address_ip = ET.SubElement(peer_address, "ip")
        if 'remote_gw' in tunnel:
            peer_address_ip.text = tunnel['remote_gw']
        else:
            peer_address_ip.text = tunnel['remotegw-ddns']

        comment = ET.SubElement(entry, "comment")
        comment.text = "Some Comment here or there"
        with open('mapped.xml', 'w') as f:
            self.tree.write(f, encoding='unicode')


# function to add ipsec profile to the xml file
    def Add_IPSEC_PROFILE(self, tunnel):
        global mapped_hash
        global mapped_encryption
        global mapped_dhgrps

        # get the root of the xml tree for the base file
        root = self.tree.getroot()
        # get the xml pointer to the ipsec tunnel section inside the xpath
        ipsec_profiles = root.find('./devices/entry[@name=\'localhost.localdomain\']/network/ike/crypto-profiles/ipsec-crypto-profiles')
        entry = ET.SubElement(ipsec_profiles, "entry")
        entry.attrib['name'] = tunnel['name'] + '_IPSEC_PROFILE'

        esp = ET.SubElement(entry, "esp")

        authentication = ET.SubElement(esp, "authentication")
        for value in tunnel['hash']:
            member = ET.SubElement(authentication, "member")
            member.text = mapped_hash[value]

        encryption = ET.SubElement(esp, "encryption")
        for value in tunnel['encryption']:
            member = ET.SubElement(encryption, "member")
            member.text = mapped_encryption[value]

        lifetime = ET.SubElement(entry, "lifetime")
        seconds = ET.SubElement(lifetime, "seconds")

        max = 65535
        if tunnel['keylifeseconds'] != 'Default':
            if int(tunnel['keylifeseconds']) <= max:
                seconds.text = tunnel['keylifeseconds']
            else:
                seconds.text = str(max)
        else:
                seconds.text = str(max)

        if tunnel['dhgrp'] != 'None':
            dhgrp = ET.SubElement(entry, "dh-group")
            dhgrp.text = mapped_dhgrps[tunnel['dhgrp']]

        else:
            dhgrp = ET.SubElement(entry, "dh-group")
            dhgrp.text = 'no-pfs'

        with open('mapped.xml', 'w') as f:
            self.tree.write(f, encoding='unicode')

    # This is a function that will create the Ipsec tunnel on the firewall
    def Add_IPSEC_TUNNEL(self, tunnel, counter):

        # get the root of the xml file where the base config is stored
        root = self.tree.getroot()
        # get the pointer to the ipsec xml section
        ipsec_tunnels = root.find('./devices/entry[@name=\'localhost.localdomain\']/network/tunnel/ipsec')
        entry = ET.SubElement(ipsec_tunnels, "entry")
        entry.attrib['name'] = tunnel['name']

        auto_key = ET.SubElement(entry, "auto-key")
        ike_gateway = ET.SubElement(auto_key, "ike-gateway")

        entry_ike = ET.SubElement(ike_gateway, "entry")
        entry_ike.attrib['name'] = tunnel['name']

        proxy_id = ET.SubElement(auto_key, "proxy-id")
        # Now we need to iterate over the proxies to add it to the firewall

        ID = 1
        for m in tunnel['proxies']:

            entry_proxy  = ET.SubElement(proxy_id, "entry")
            entry_proxy.attrib['name'] ='PROXY'+str(ID)
            protocol = ET.SubElement(entry_proxy, "protocol")
            any_protocol = ET.SubElement(protocol, "any")

            local_id = ET.SubElement(entry_proxy, "local")
            source_id = str(list(m.keys())[0])
            #if a standalone ip address
            if (len(source_id.split(' '))) == 1:
                if '-' in source_id:
                    local_id.text = source_id
                else:
                    cidr = '32'
                    subnet = source_id
                    local_id.text = subnet + '/' + str(cidr)
            else:
            #now this deals with the subnet mask case
                custom_1 = source_id.replace(' ', '/')
                custom_2 = ipaddress.ip_network(custom_1)
                cidr = custom_2.prefixlen
                subnet = source_id.split(' ')[0]
                local_id.text = subnet + '/' + str(cidr)



            remote_id = ET.SubElement(entry_proxy, "remote")
            #remote_id.text = str(list(m.values())[0])
            remote_subnet = str(list(m.values())[0])
            # if a standalone ip address
            if (len(remote_subnet.split(' '))) == 1:
                if '-' in remote_subnet:
                    remote_id.text = remote_subnet
                else:
                    cidr = '32'
                    subnet = remote_subnet
                    remote_id.text = subnet + '/' + str(cidr)

            #dealing with the range

            else:
                # now this deals with the subnet mask case
                custom_1 = remote_subnet.replace(' ', '/')
                custom_2 = ipaddress.ip_network(custom_1)
                cidr = custom_2.prefixlen
                subnet = remote_subnet.split(' ')[0]
                remote_id.text = subnet + '/' + str(cidr)



            ID = ID + 1

        ipsec_crypto_profile = ET.SubElement(auto_key, "ipsec-crypto-profile")
        ipsec_crypto_profile.text = tunnel['name'] + '_IPSEC_PROFILE'

        tunnel_monitor = ET.SubElement(entry, "tunnel-monitor")
        monitor_enable = ET.SubElement(tunnel_monitor, "enable")
        monitor_enable.text = 'no'

        tunnel_interface=ET.SubElement(entry, "tunnel-interface")
        tunnel_interface.text = "tunnel." + str(counter)

        with open('mapped.xml', 'w') as f:
            self.tree.write(f, encoding='unicode')
