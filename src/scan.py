"""
scan a network (the user scans network subnet 192.168.1.0)
o E.g. user inputs the target subnet

Use Nmap or other vulnerability scanners to identify potential hosts and services to exploit on the
detected online IP addresses identified in the previous part. You may use embedded Nmap
within the Metasploit package or download the Nmap package separately. You may also
download additional vulnerability scripts for Nmap.
2. Use the Metasploit database to track results of Nmap scans and exploit attempts.
"""
import os

import nmap
import pandas as pd

from common.utils import cwd

# import netifaces
# import netaddr

targets = {}  # {"host": {"state": bool, "ports": [], "vulnerabilities": []}}


def scan_network(subnet_addr=None, verbose=False):
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

    print(f"Scanning network... {subnet_addr}")
    nm.scan(hosts=subnet_addr, arguments='-O --osscan-guess --osscan-limit -F --exclude 192.168.86.66', sudo=True, )

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
                        targets[host] = {"state": nm[host]['state'], "ports": [], "vulnerabilities": [],
                                         "os_name": "windows", "os_flavor": "7"}
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
                        targets[host] = {"state": True, "ports": [], "vulnerabilities": [], "os_name": "Windows 7",
                                         "os_flavor": "7"}
                        # os_type = nm[host]['osmatch'][0]['name']

        except Exception as e:
            print(e)
            continue

    return ip_list


def main(client):
    """
    Main function
    - scan network
    - save results to csv
    :param client:
    :return:
    """
    try:
        subnet_addr = input("Enter the subnet address: ")
        scan_network(subnet_addr, verbose=True)

        target = list(targets.keys())[0]
        results = pd.DataFrame(targets, index=list(targets.keys()), columns=targets[target].keys())

        for host in targets.keys():
            results.loc[host] = targets[host]

        results.to_csv(os.path.join(cwd, "../hosts.csv"), index=True, header=True)

    except IndexError as e:
        return f"NO RESULTS FOUND"
    except Exception as e:
        return f"Error ({type(e)}): {e}"
    else:
        return f"Nmap found {results.index.tolist()}. Results saved to {os.path.join(cwd, '../hosts.csv')}"
    # create a new dataframe where the index is the index of the targets and the columns are the keys of the target
