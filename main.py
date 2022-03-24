from Forti import Forti
from PAN import PAN

if __name__ == '__main__':
    firewall1 = Forti()
    firewall1.parse_config('vpn2022.conf')
    firewall1.parse_ike()
    for t in firewall1.ike:
        print(t)
    firewall1.parse_ipsec()
    for t in firewall1.ipsec:
        print(t)
    firewall1.ike_ipsec_link()

    for t in firewall1.tunnels:
        print(t['name'])
        print("Proxies")
        print(t['proxies'])
        print("Encryption:")
        print(t['encryption'])
        print("Hash:")
        print(t['hash'])
        print("PFS:")
        print(t['pfs'])
        print("DH:")
        print(t['dhgrp'])
        print('Keepalives:')
        print(t['keepalive'])
        print("Lifetime:")
        print(t['keylifeseconds'])

        #print("Destination Proxies")
        #print(t['destinations'])
        print("###################")

    #firewall1.ipsec_proposals()
    #firewall1.ike_proposals()

    firewall2 = PAN()
    firewall2.load_config('base-line.xml')
    for tunnel in firewall1.ike:
        print(tunnel)
        firewall2.Add_IKE_PROFILE(tunnel)
        firewall2.Add_IKE_GW(tunnel)
    counter = 1
    for tunnel in firewall1.tunnels:
        firewall2.Add_IPSEC_PROFILE(tunnel)

    for tunnel in firewall1.tunnels:
        firewall2.Add_IPSEC_TUNNEL(tunnel, counter)
        counter = counter + 1

    firewall1.provide_tunnel_interfaces()
    #firewall1.parse_policies()
    #firewall1.unsupported_policies()
    #firewall1.parse_addresses()
    #firewall1.parse_adgroups()
    #firewall1.unsupported_addresses()
    #firewall1.parse_webfilters()
    #firewall1.web_filter_beautify()
    #firewall1.policies_schedules()
    #firewall1.unnamed_policies()
    #firewall1.generate_set('HQ-INT-VSYS4', 'TEST_PROFILE')
    #print(len(firewall1.policies))