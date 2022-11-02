"""
scan a network (the user scans network subnet 192.168.1.0)
o E.g. user inputs the target subnet

Use Nmap or other vulnerability scanners to identify potential hosts and services to exploit on the
detected online IP addresses identified in the previous part. You may use embedded Nmap
within the Metasploit package or download the Nmap package separately. You may also
download additional vulnerability scripts for Nmap.
2. Use the Metasploit database to track results of Nmap scans and exploit attempts.
"""
import nmap
import pandas as pd

# import netifaces
# import netaddr

targets = {} #{"host": {"state": bool, "ports": [], "vulnerabilities": []}}
def scan_network(subnet_addr=None, verbose = False):
    global targets
    """
    Scan a network (the user scans network subnet
    - all ports
    - all protocols
    - limit os to windows 7
    - all states

    :param subnet_addr: the subnet address
    :return: list of online hosts
    """
    if not subnet_addr:
        subnet_addr = "192.168.56.132"
    ip_list = []
    nm = nmap.PortScanner()
    # -sP -PE -PA21,23,80,3389
    print(f"Scanning network... {subnet_addr}")
    nm.scan(hosts=subnet_addr, arguments='-O --osscan-guess --osscan-limit -F', sudo=True,)
    # check os typehosts
    # filter hosts that are not up

    # filter hosts that are not windows 7
    print("Ran Command:", nm.command_line())
    if verbose:
        print(nm.scanstats())
    print("nmap found {} hosts".format(len(nm.all_hosts())))
    print(nm.all_hosts())
    for host in nm.all_hosts():

        if verbose:
            print('Host : %s (%s)' % (host, nm[host].hostname()))
            print('State : %s' % nm[host].state())
            # print all details
            print(nm[host].items())

        try:
            if nm[host].state() == 'up':
                    os = nm[host]['osmatch']
                    if os == []:
                        os = nm[host]['vendor']
                        if 'Windows 7' in os:
                            targets[host] = {"state": nm[host]['state'], "ports": [], "vulnerabilities": [], "os_name": "windows", "os_flavor": "7"}
                    else:
                        vendor = os[0]['osclass'][0]['vendor']
                        osfamily = os[0]['osclass'][0]['osfamily']
                        osgen = os[0]['osclass'][0]['osgen']
                        accuracy = os[0]['accuracy']

                        if verbose:
                            print(nm[host]['osmatch'])
                            print('OS : %s' % nm[host]['osmatch'][0]['name'])

                        if verbose:
                            print('Vendor : %s' % vendor, "TV:", vendor == 'Microsoft')
                            print('OS Family : %s' % osfamily, "TV:", osfamily == 'Windows')
                            print('OS Gen : %s' % osgen, "TV:", osgen == '7')

                        if vendor == 'Microsoft' and osfamily == 'Windows' and osgen == '7':
                            targets[host] = {"state": True, "ports": [], "vulnerabilities": [], "os_name": "windows", "os_flavor": "7"}
                            # os_type = nm[host]['osmatch'][0]['name']
                # if 'Windows 7' in os_type:
                #     ip_list.append(host)
        except Exception as e:
            print(e)
            continue
    # print(ip_list)
    # for host in ip_list:
    #     print(host)
    #     for proto in nm[host].all_protocols():
    #         print("Protocol: {}".format(proto))
    #         lport = nm[host][proto].items()
    #         targets[host] = {"state": True, "ports": [port for port in dict(lport).keys()], "vulnerabilities": []}
    #         # iterate through open ports
    #         for port in dict(lport).keys():
    #             print("Port: {}".format(port))
    #             print("State: {}".format(nm[host][proto][port]['state']))
    #             print("Service: {}".format(nm[host][proto][port]['name']))
    #             print("Product: {}".format(nm[host][proto][port]['product']))
    #             print("Version: {}".format(nm[host][proto][port]['version']))
    #             print("Extra Info: {}".format(nm[host][proto][port]['extrainfo']))
    #             print("Reason: {}".format(nm[host][proto][port]['reason']))
    #             print("Conf: {}".format(nm[host][proto][port]['conf']))
    #             print("CPE: {}".format(nm[host][proto][port]['cpe']))
    #             print("")


        # except KeyError:
        #     pass
    return ip_list

def main(client):
    try:
        subnet_addr = input("Enter the subnet address: ")
        scan_network(subnet_addr, verbose=True)
        # write to file
        # get first index of targets
        # add hosts to client db
        target = list(targets.keys())[0]
        # for host in targets.keys():
        #     # Optional Keyword Arguments:
        #     # - state : a host state.
        #     # - os_name : an operating system.
        #     # - os_flavor : something like 'XP or 'Gentoo'.
        #     # - os_sp : something like 'SP2'.
        #     # - os_lang : something like 'English', 'French', or 'en-US'.
        #     # - arch : an architecture.
        #     # - mac : the host's MAC address.
        #     # - scope : interface identifier for link-local IPv6.
        #     # - virtual_host : the name of the VM host software, e.g. 'VMWare', 'QEMU', 'Xen', etc.
        #
        #     print(host)
        #     client.db.workspaces.workspace('default').hosts.report(host=host, state=targets[host]['state'], os_name=targets[host]['os_name'], os_flavor=targets[host]['os_flavor'])
        #     print(client.db.workspaces.workspace('default').hosts.list)
        results = pd.DataFrame(targets)
        results = pd.DataFrame(targets, index=list(targets.keys()), columns=targets[target].keys())
        for host in targets.keys():
            results.loc[host] = targets[host]
        results.to_csv("hosts.csv", index=True, header=True)
        print("nmap found {} ".format(len(results.index.tolist())))
    except Exception as e:
        print(e)
    finally:
        return client
    # create a new dataframe where the index is the index of the targets and the columns are the keys of the target



