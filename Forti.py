
# this is a class that represents a Fortinet Firewall with its objects and methods
import re
import csv



class Forti(object):

    def __init__(self):
        self.policies = []
        self.bad_policies = []
        self.addresses = []
        self.address_groups = []
        self.web_filters = []
        self.isdb_objects = []
        # will contain the name, type, interface, local-gw, keylife , peer type,
        #net-device, proposal, comments, ike-version, dhgrp, nattraversal, remotegw-ddns, remote-gw
        self.ike = []

        # will contain all fortinet phase 2 scattered associations
        # will have to merge at the end to one association
        self.ipsec = []

        # The following will have a list of the unified tunnels on the fortinet
        self.tunnels = []
        self.content = ''

# This function will parse the configuration file of Frotinet and Store it inside the text variable content
    def parse_config(self, config_file):
        f = open(config_file, 'r', encoding="utf8")
        self.content = f.read()
        #print(self.content)


# A function that will parse ike tunnels
    def parse_ike(self):
        ike_text = re.findall(r'^config vpn ipsec phase1-interface.*?^end$', self.content, flags=re.DOTALL | re.MULTILINE)[0]
        ike_tunnels = re.findall(r'^\s{4}(edit.*?)^\s{4}next$', ike_text, flags=re.DOTALL | re.MULTILINE)
        # Now parsing each tunnel attributes
        for tunnel in ike_tunnels:

# a dictionary to store the parameters of the parsed tunnel.
            t_candidate = {}
            #Parsing the name of the phase 1 tunnel.
            name = re.findall(r'edit \"(.*)\"$', tunnel, flags=re.MULTILINE)
            t_candidate['name'] = name[0]
            #Parsing the source interface for the tunnel.
            interface = re.findall(r'^\s{8}set interface \"(.*)\"$', tunnel, flags=re.MULTILINE)
            t_candidate['interface'] = interface[0]
            #Parsing the IKE version of the tunnel.
            ike_version = re.findall(r'^\s{8}set ike-version (.*)$', tunnel, flags=re.MULTILINE)
            if ike_version:
                t_candidate['ike-version'] = ike_version[0]
            else:
                #if the command is not there then the default is ikev1.
                t_candidate['ike-version'] = "ikev1"
                # The type of the ike peer, dynamic for example.
            type = re.findall(r'^\s{8}set type (.*)$', tunnel, flags=re.MULTILINE)
            if type:
                t_candidate['type'] = type[0]
            else:
                t_candidate['type'] = "Default"

                #The local gateway ip address covering cases with secondary addresses used.
            local_gw = re.findall(r'^\s{8}set local-gw (.*)$', tunnel, flags=re.MULTILINE)
            if local_gw:
                t_candidate['local-gw'] = local_gw[0]
                #cover all interfaces used as VPN Gateways.
                #replace with the actual interface names and ip addresses on Fortinet.
            else:
                if t_candidate['interface'] == 'interface#1':
                    t_candidate['local-gw'] = "interface#1 IP Address"

                if t_candidate['interface'] == 'interface#2':
                    t_candidate['local-gw'] = "interface#1 IP Address"

                if t_candidate['interface'] == 'interface#3':
                    t_candidate['local-gw'] = "interface#3 IP Address"

            #parse phase 1 lifetime.
            keylife = re.findall(r'^\s{8}set keylife (.*)$', tunnel, flags=re.MULTILINE)
            if keylife:
                t_candidate['keylife'] = keylife[0]
            else:
                t_candidate['keylife'] = "Default"

            #Parse the peer type
            peertype = re.findall(r'^\s{8}set peertype (.*)$', tunnel, flags=re.MULTILINE)
            if peertype:
                t_candidate['peertype'] = peertype[0]
            else:
                t_candidate['peertype'] = "Default"

            #Parse the Fortinet netdevice config.
            net_device = re.findall(r'^\s{8}set net-device (.*)$', tunnel, flags=re.MULTILINE)
            if net_device:
                t_candidate['net_device'] = net_device[0]
            else:
                t_candidate['net-device'] = "Default"

            #Parse Phase 1 Proposals
            proposal = re.findall(r'^\s{8}set proposal (.*)$', tunnel, flags=re.MULTILINE)

            #Populate Encryption and hashing from the proposal parsed.
            t_candidate['encryption'] = []
            t_candidate['hash'] = []
            #single proposal case
            if len(proposal[0].split(' ')) == 1:
                t_candidate['encryption'].append(proposal[0].split('-')[0])
                t_candidate['hash'].append(proposal[0].split('-')[1])

            #Multi Proposal Case
            else:
                for v in proposal[0].split(' '):
                    t_candidate['encryption'].append(v.split('-')[0])
                    t_candidate['hash'].append(v.split('-')[1])

            #Store a List of Encryption Methods.
            t_candidate['encryption'] = list(set(t_candidate['encryption']))

            #Store a List of Hash Methods
            t_candidate['hash'] = list(set(t_candidate['hash']))

            #Parse Diffie hellman group config for phase 1.
            dhgrp = re.findall(r'^\s{8}set dhgrp (.*)$', tunnel, flags=re.MULTILINE)
            t_candidate['dhgrp'] = dhgrp[0]

            #Parse NAT-T Fortinet Config.
            nattraversal = re.findall(r'^\s{8}set nattraversal (.*)$', tunnel, flags=re.MULTILINE)
            if nattraversal:
                t_candidate['nattraversal'] = nattraversal[0]
            else:
                t_candidate['nattraversal'] = "enable"

            #Parse the remote gateway IP address aka Peer IP address.
            remote_gw = re.findall(r'^\s{8}set remote-gw (.*)$', tunnel, flags=re.MULTILINE)
            if remote_gw:
                t_candidate['remote_gw'] = remote_gw[0]

            #if a dynamic peer is used with DDNS
            if t_candidate['type'] == "ddns":
                remotegw_ddns = re.findall(r'^\s{8}set remotegw-ddns \"(.*)\"$', tunnel, flags=re.MULTILINE)
                t_candidate['remotegw-ddns'] = remotegw_ddns[0]
            # Populate the ike list with the parsed dictionary.
            self.ike.append(t_candidate)

#Just a function to print all phase 1 tunnels parsed from fortinet. Just prints the name for Verification.
    def provide_tunnel_interfaces(self):
        i = 1
        for t in self.ike:
            print("{}   tunnel.{} ".format(t['name'], i))
            i = i+1
#A function to parse all ipsec configuration from Fortinet
    def parse_ipsec(self):
        #Parse all the ipsec text section inside fortinet.
        ipsec_text = re.findall(r'^config vpn ipsec phase2-interface.*?^end$', self.content, flags=re.DOTALL | re.MULTILINE)[0]
        #Find each ipsec tunnel section inside the entire ipsec section.
        ipsec_tunnels = re.findall(r'^\s{4}(edit.*?)^\s{4}next$', ipsec_text, flags=re.DOTALL | re.MULTILINE)
        for tunnel in ipsec_tunnels:
            # A dictionary to parse each tunnel with k,v paris.
            t_candidate = {}
            #Name of the ipsec configuration
            name = re.findall(r'edit \"(.*)\"$', tunnel, flags=re.MULTILINE)
            t_candidate['name'] = name[0]

            #Parse the phase 1 name associated with this phase 2 configuration.
            phase1_name = re.findall(r'^\s{8}set phase1name \"(.*)\"$', tunnel, flags=re.MULTILINE)
            t_candidate['phase1name'] = phase1_name[0]

            #Parse the Phase 2 Proposal.
            proposal = re.findall(r'^\s{8}set proposal (.*)$', tunnel, flags=re.MULTILINE)

            #Parse Encryption / hash from the proposal.
            t_candidate['encryption'] = []
            t_candidate['hash'] = []

            #If only one proposal is configured.
            if len(proposal[0].split(' ')) == 1:
                t_candidate['encryption'].append(proposal[0].split('-')[0])
                t_candidate['hash'].append(proposal[0].split('-')[1])

            #if more than one proposal is used.
            else:
                for v in proposal[0].split(' '):
                    t_candidate['encryption'].append(v.split('-')[0])
                    t_candidate['hash'].append(v.split('-')[1])

            # Populate encryption and hash inside a list for each.
            t_candidate['encryption'] = list(set(t_candidate['encryption']))
            t_candidate['hash'] = list(set(t_candidate['hash']))

            #Parse PFS settings from Fortinet Config
            pfs = re.findall(r'^\s{8}set pfs (.*)$', tunnel, flags=re.MULTILINE)
            if pfs:
                t_candidate['pfs'] = pfs[0]
            else:
                t_candidate['pfs'] = 'enabled'

            #Parse the PFS group configured for phase 2
            dhgrp = re.findall(r'^\s{8}set dhgrp (.*)$', tunnel, flags=re.MULTILINE)
            if dhgrp:
                t_candidate['dhgrp'] = dhgrp[0]
            else:
                t_candidate['dhgrp'] = 'None'

            #Parse Anti Replay Settings.
            replay = re.findall(r'^\s{8}set replay (.*)$', tunnel, flags=re.MULTILINE)
            if replay:
                t_candidate['replay'] = replay[0]
            else:
                t_candidate['replay'] = 'enabled'

            #Parse Dead peer Detection Settings.
            keep_alive = re.findall(r'^\s{8}set keepalive (.*)$', tunnel, flags=re.MULTILINE)
            if keep_alive:
                t_candidate['keepalive'] = keep_alive[0]
            else:
                t_candidate['keepalive'] = 'disabled'

            #Parse the phase 2 liftime settings.
            keylifeseconds = re.findall(r'^\s{8}set keylifeseconds (.*)$', tunnel, flags=re.MULTILINE)
            if keylifeseconds:
                t_candidate['keylifeseconds'] = keylifeseconds[0]
            else:
                t_candidate['keylifeseconds'] = 'Default'

            # Now we need to parse the proxies which has many use cases.
            # source and destination parsing will be separated so we parse source first

            # 1- First use case is with the source type as IP
            # 2- Use case with the source type range
            # 3- Use case with the Source type as a range

            #Parse the Source Address type
            src_addr_type = re.findall(r'^\s{8}set src-addr-type (.*)$', tunnel, flags=re.MULTILINE)

            #if Found Loop over the possibilities
            if src_addr_type:
                #if it is a range:
                if src_addr_type[0] == 'range':
                    # Now we parse src-start-ip and the end-ip
                    src_start_ip = re.findall(r'^\s{8}set src-start-ip (.*)$', tunnel, flags=re.MULTILINE)
                    src_end_ip = re.findall(r'^\s{8}set src-end-ip (.*)$', tunnel, flags=re.MULTILINE)
                    source = src_start_ip[0] + '-' + src_end_ip[0]

                # if an ip address type aka /32
                elif src_addr_type[0] == 'ip':
                    # Now we parse src-start-ip
                    src_start_ip = re.findall(r'^\s{8}set src-start-ip (.*)$', tunnel, flags=re.MULTILINE)
                    source = src_start_ip[0]

            #if not specified then we look for source subnet config
            else:
                src_subnet = re.findall(r'^\s{8}set src-subnet (.*)$', tunnel, flags=re.MULTILINE)
                if src_subnet:
                    source = src_subnet[0]
                #if not found then source is any
                else:
                    source = 'any'
            #append the source to the dictionary
            t_candidate['source'] = source


            # 1- First use case is with the destination type as IP
            # 2- Use case with the destination type range
            # 3- Use case with the destination type as a range

            #Parse the Destination address type if exists
            dst_addr_type = re.findall(r'^\s{8}set dst-addr-type (.*)$', tunnel, flags=re.MULTILINE)

            #if Found
            if dst_addr_type:
                #if a range
                if dst_addr_type[0] == 'range':
                    # Now we parse src-start-ip and the dst-end-ip
                    dst_start_ip = re.findall(r'^\s{8}set dst-start-ip (.*)$', tunnel, flags=re.MULTILINE)
                    dst_end_ip = re.findall(r'^\s{8}set dst-end-ip (.*)$', tunnel, flags=re.MULTILINE)
                    destination = dst_start_ip[0] + '-' + dst_end_ip[0]

                #if the destination is a /32 IP address
                elif dst_addr_type[0] == 'ip':
                    # Now we parse src-start-ip. the /32 ip address
                    dst_start_ip = re.findall(r'^\s{8}set dst-start-ip (.*)$', tunnel, flags=re.MULTILINE)
                    destination = dst_start_ip[0]

            # if not a range and ip then we look for subnet configuration
            else:
                dst_subnet = re.findall(r'^\s{8}set dst-subnet (.*)$', tunnel, flags=re.MULTILINE)
                if dst_subnet:
                    destination = dst_subnet[0]
                #if not found then it is any.
                else:
                    destination = 'any'
            # add the destination key to the dictionary
            t_candidate['destination'] = destination

            #Add the dictionary to the list of the ipsec tunnels proxy SAs for this Fortinet Object.
            self.ipsec.append(t_candidate)


        # Now we need to link phase 2 settings into phase 1 settings under one tunnel
        # Fortinet text file spreads phase 2 config into different sections so it needs to be organized.

    def ike_ipsec_link(self):
            # the function will iterate over phase 1 settings and when it finds a match it wil link the phase 2 settings
            # python dictionaries have a unique key so we should not store proxies in a dicrionary
            # will store in a list of dictionaries

            #iterate over the parsed phase 1 tunnels in the list named ike
            for e in self.ike:
                #an empty draft template
                t_candidate = {}
                # two keys inside the template . name and proxies
                t_candidate['proxies'] = []
                t_candidate['name'] = e['name']

                # for each ike phase 1 config we also iterate inside it over ipsec config to find the matches.
                for config in self.ipsec:
                    #if the name of the tunnel is equal to the phase1 config inside the ipsec config then we have a match
                    if e['name'] == config['phase1name']:
                        #Parse all the needed attribute to build the final tunnel cnstruct
                        t_candidate['proxies'].append({config['source']:config['destination']})
                        t_candidate['encryption']= config['encryption']
                        t_candidate['hash'] = config['hash']
                        t_candidate['pfs'] = config['pfs']
                        t_candidate['dhgrp'] = config['dhgrp']
                        t_candidate['replay'] = config['replay']
                        t_candidate['keepalive'] = config['keepalive']
                        t_candidate['keylifeseconds'] = config['keylifeseconds']


                # append the parsed tunnel dictionary to the list of the tunnels.
                self.tunnels.append(t_candidate)

    # This is a function that will output all unique ike  proposals on Fortinet

    def ike_proposals(self):
        ike_proposals = []
        for t in self.ike:
            if t['proposal'] not in ike_proposals:
                ike_proposals.append(t['proposal'])
        print(ike_proposals)

    # This is a function that will output all unique ipsec proposals on Fortinet
    def ipsec_proposals(self):
        ipsec_proposals = []
        for t in self.ipsec:
                if t['proposal'] not in ipsec_proposals:
                    ipsec_proposals.append(t['proposal'])
        print("IPSEC Proposals Used:")
        print(ipsec_proposals)


    # This is a function to parse all security policies from the Fortinet Firewall config file

    def parse_policies(self):
        # First we need to parse the policies section and then iterate over all the policies
        policies_text = re.findall(r'config firewall policy.*?end$', self.content, flags=re.DOTALL | re.MULTILINE)[0]
        policies = re.findall(r'(edit.*?)next$', policies_text, flags=re.DOTALL | re.MULTILINE)

        #iterate over each policy
        for p in policies:
            # a template dictionary that acts as a construct for the policy.
            p_candidate = {}
            #Parse the name of the policy
            name = re.findall(r'set name (.*)$',p, flags=re.MULTILINE)
            if (name):
                p_candidate['name'] = name[0]
            #If there is no name configured parse the policy number as the name.
            else:
                p_candidate['name'] = re.findall(r'edit (\d+)$',p, flags=re.MULTILINE)[0]

            # Enabled or Disabled settings parsing.
            status = re.findall(r'set status (.*)$', p, flags=re.MULTILINE)
            if (status):
                p_candidate['status'] = status[0]
            else:
                p_candidate['status'] = 'enabled'

            #Parse the uuid of the policy
            uuid =  re.findall(r'set uuid (.*)$',p, flags=re.MULTILINE)
            if (uuid):
                p_candidate['uuid'] = uuid[0]

            # Parse the Source interface of the policy
            srcintf = re.findall(r'set srcintf (.*)$',p, flags=re.MULTILINE)
            if (srcintf):
                p_candidate['srcintf'] = srcintf[0]

            # Parse the destination interface of the policy
            dstintf = re.findall(r'set dstintf (.*)$',p, flags=re.MULTILINE)
            if (dstintf):
                p_candidate['dstintf'] = dstintf[0]

            #Parse the Source address
            srcaddr = re.findall(r'set srcaddr (.*)$',p, flags=re.MULTILINE)
            if (srcaddr):
                p_candidate['srcaddr'] = srcaddr[0]

            # Parse the Destination address
            dstaddr = re.findall(r'set dstaddr (.*)$',p, flags=re.MULTILINE)
            if (dstaddr):
                p_candidate['dstaddr'] = dstaddr[0]

            #Parse the policy action
            action = re.findall(r'set action (.*)$',p, flags=re.MULTILINE)
            if (action):
                p_candidate['action'] = action[0]

            # Parse the schedule if there
            schedule = re.findall(r'set schedule (.*)$',p, flags=re.MULTILINE)
            if (schedule):
                p_candidate['schedule'] = schedule[0]

            # Parse the Service Object .
            service = re.findall(r'set service (.*)$',p, flags=re.MULTILINE)
            if (service):
                p_candidate['service'] = service[0]

            # Parse the Web Filter Configured.
            webfilter_profile = re.findall(r'set webfilter-profile (.*)$',p, flags=re.MULTILINE)
            if (webfilter_profile):
                p_candidate['webfilter_profile'] = webfilter_profile[0]

            # Parse the Internet Service ID if cofigured for the policy
            internet_service_id = re.findall(r'set internet-service-id (.*)$',p, flags=re.MULTILINE)
            if (internet_service_id):
                p_candidate['internet_service_id'] = internet_service_id[0]

            # Parse the Comments on the Policy
            comments = re.findall(r'set comments (.*)$',p, flags=re.MULTILINE)
            if (comments):
                p_candidate['comments'] = comments[0]

            # Append the Policy to the list of the policies for the current object.
            self.policies.append(p_candidate)


# this is a Function that returns all unnamed policies
    def unnamed_policies(self):
        print("The following policies have no names")
        for p in self.policies:
            if 'name' not in p:
                print(p)


# A function that will parse all addresses objects
    def parse_addresses(self):
        # First we need to parse the addresses section and then iterate over all the addresses
        addresses_text = re.findall(r'config firewall address.*?^end$', self.content, flags=re.DOTALL | re.MULTILINE)[0]

        # parse each address subsection inside the full address text.
        addresses = re.findall(r'^\s{4}edit "(.*?)"(.*?)^\s{4}next$', addresses_text, flags=re.DOTALL | re.MULTILINE)

        # Iterate over all the addresses parsed.
        for a in addresses:
            a_candidate = {}
            #parse the name of the address
            a_candidate['name'] = a[0]

            #Parse the UUID of the address
            uuid = re.findall(r'\s{8}set uuid (.*)$', a[1], flags=re.MULTILINE)
            a_candidate['uuid'] = uuid[0]

            #Parse the type of the address
            type = re.findall(r'\s{8}set type (.*)$', a[1], flags=re.MULTILINE)
            if (type):
                a_candidate['type'] = type[0].strip()

            else:
                a_candidate['type'] = 'address'

            # Parse the value of the object
            # subnet type:
            if (a_candidate['type'] == 'address'):
                subnet = re.findall(r'\s{8}set subnet (.*)$', a[1], flags=re.MULTILINE)
                if (subnet):
                    a_candidate['subnet'] = subnet[0]
            #ip range type:
            if (a_candidate['type'] == 'iprange'):
                start_ip = re.findall(r'\s{8}set start-ip (.*)$', a[1], flags=re.MULTILINE)
                end_ip = re.findall(r'\s{8}set end-ip (.*)$', a[1], flags=re.MULTILINE)
                a_candidate['start-ip'] = start_ip[0]
                a_candidate['end-ip'] = end_ip[0]

            # FQDN type.
            if (a_candidate['type'] == 'fqdn'):
                fqdn = re.findall(r'\s{8}set fqdn (.*)$', a[1], flags=re.MULTILINE)
                if (fqdn):
                    a_candidate['fqdn'] = fqdn[0]

            # append the parsed address object
            self.addresses.append(a_candidate)



# A function that parses all address groups from the config file
    def parse_adgroups(self):
        # First we need to parse the address group section and then iterate over all the addresses
        addresses_group_text = re.findall(r'config firewall addrgrp.*?end$', self.content, flags=re.DOTALL | re.MULTILINE)[0]
        address_groups = re.findall(r'edit "(.*?)"(.*?)next$', addresses_group_text, flags=re.DOTALL | re.MULTILINE)

        for m in address_groups:
            a_group_candidate = {}
            #parse the address group name using the regex group matching.
            a_group_candidate['name'] = m[0]

            #parse the address group uuid
            uuid = re.findall(r'set uuid (.*)$', m[1], flags=re.MULTILINE)
            a_group_candidate['uuid'] = uuid[0]

            # Parse the members of the group
            members = re.findall(r'set member (.*)$', m[1], flags=re.MULTILINE)
            a_group_candidate['members'] = members[0]
            #Parse the comments on the group.
            comments = re.findall(r'set comment (.*)$', m[1], flags=re.MULTILINE)
            if comments:
                a_group_candidate['comments'] = comments[0]
            # append the parsed object to the group.
            self.address_groups.append(a_group_candidate)


# A function that will parse the web filters configured on the firewall

    def parse_webfilters(self):
        # First we need to parse the webfilters section
        web_filters_text = re.findall(r'config webfilter profile.*?^end$', self.content, flags=re.DOTALL | re.MULTILINE)[0]
        # parse the web filter names configured on fortinet.
        self.web_filters = re.findall(r'edit "(.*?)"', web_filters_text, flags= re.MULTILINE)


# This function will return the name of the policies that should be migrated manually
# Unsupported Migrations
    def unsupported_policies(self):
        print('####################### The following Policies Needs to be checked Manually #########################')
        for p in self.policies:
            # a policy that has internet service id object configured
            if 'internet_service_id' in p:
                self.bad_policies.append(p)
                continue
            # a policy that has a url filter configured.
            if 'webfilter_profile' in  p :
                self.bad_policies.append(p)
                continue
        # print all of these policies.
        for p in self.bad_policies:
            print(p)
        print('######################################################################################################')
        f = open('unsupported_policies.csv', 'w')
        writer = csv.writer(f)
        for p in self.bad_policies:
            writer.writerow(list(p.values()))

# a list of address objects that needs manual attention.
    def unsupported_addresses(self):
        print('####################### The following wildcard FQDNS are not supported on PAN #########################')
        for address in self.addresses:
            # Look for wildcard objects
            if address['type'] == 'fqdn':
                if 'fqdn' in address:
                    if "*" in address['fqdn']:
                        print(address)

        print('####################### The following wildcard FQDNS groups are not supported on PAN ####################')
        for group in self.address_groups:
            # look for wildcard objects inside address groups.
            if "*" in group['members']:
                print("group {} needs to be converted into a URL match rule.")
        print('######################################################################################################')


    # this function will output each webfilter and the policies associated to it

    def  web_filter_beautify(self):
        result = {}
        # a dictionary that has a key as the filter name and the value as an array containing poliocies for that key
        #iterate over all web filters
        for f in self.web_filters:
            # store the name of the filter as a key and the value is list of policies using that key
            result[f] = []
            #iterate over all policies in the bad policies arena
            for p in self.bad_policies:
                # if the policy has a web filter and the name matches the current filter and the policy is enabled.
                if ('webfilter_profile' in p ) and (p['webfilter_profile'].strip("\"") == f) and (p['status'].strip("\"") == 'enabled'):
                    result[f].append(p['name'].strip("\""))
            # covers the keys where the filter is not used
            if result[f] == []:
                del result[f]

        print("###################The following section shows each web filter and the associated policies###########")
        for k,v in result.items():
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("Webfilter {}".format(k))
            for item in v:
                print(item)
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!")
        return result

    # this is a function that generates set commands to be used for policies with URL filters
    def generate_set(self, dg_name, pf_name):
        result = self.web_filter_beautify()
        for k,v in result.items():
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("edit device-group {}  post-rulebase security".format(dg_name))
            for item in v:
                print("set rules \"{}\" profile-setting group {} ".format(item, k))
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!")

# this is a function that will print the policy and the schedule assigned to it
    def policies_schedules(self):
        for policy in self.policies:
            if 'schedule' in policy and policy['schedule'].strip("\"") != 'always':
                print("{}                                          :    {}".format(policy['name'].strip("\""), policy['schedule'].strip("\"")))
