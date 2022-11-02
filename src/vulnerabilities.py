"""
check for vulnerable ports
"""
import json
import os
import subprocess

import nmap
import pandas
import pandas as pd
# from pymetasploit3 import *
from pymetasploit3.msfrpc import MsfRpcMethod, MsfRpcClient

from common.utils import start_metasploit

vulns_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../nmap-vulners/")
cwd = os.path.dirname(os.path.abspath(__file__))



# def db_nmap(client, nmap_str):
#     """
#     Run nmap scan on a list of hosts
#     :param hosts: list of hosts
#     :param ports: list of ports
#     :return: list of hosts
#     """
#     print("Running nmap")
#     print(nmap_str)
#     console = client.call(MsfRpcMethod.ConsoleCreate)
#     print("Console created")
#     client.call(MsfRpcMethod.ConsoleWrite, console, f"db_nmap {nmap_str}")
#     time.sleep(5)
#     print("Nmap finished")
#     print(client.call(MsfRpcMethod.ConsoleRead, console))
#     client.call(MsfRpcMethod.ConsoleDestroy, console)
#     time.sleep(5)
#     print("Console destroyed")
#     return client.call(MsfRpcMethod.ConsoleRead, console)
#     # client.call(MsfRpcMethod.ConsoleWrite, 'exit')



def check_vuln_directory():
    """
    Check if the vulnerability directory exists
    :return: True if exists, False otherwise
    """

    if not os.path.exists(vulns_path):
        # clone git clone https://github.com/vulnersCom/nmap-vulners.git
        # move to nmap-vulners
        p = subprocess.Popen(["git", "clone", "https://github.com/vulnersCom/nmap-vulners.git"])
        p.wait()
    return vulns_path





def get_vuln_hosts(client, hosts, script):
    """
    Get vulnerable hosts
    :param client:
    :param hosts: list of hosts
    :param ports: list of ports
    :return: list of vulnerable hosts
    """
    print("Loading Hosts...")
    # if hosts is None:
    #     # print(*pandas.read_csv("ip_list.csv").iterrows())
    #     hosts = pandas.read_csv(os.path.join(cwd, 'hosts.csv'), index_col=0, header=0)
    # print(hosts["ports"])
    print("Hosts loaded")

    # list of all hosts
    hosts_list = list(hosts)
    # concat all ports into 1 list
    # ports_list = []
    # for p in hosts["ports"]:
    #     ports_list += list(json.loads(p))
    # ports_list = set([str(p) for p in ports_list])

    print("Running nmap on hosts:", hosts_list)
    nmap_str = f"--script {script} -sV" #-sV -sC
    print("Nmap string:", nmap_str)
    nm = nmap.PortScanner()
    nm.scan(hosts=','.join(hosts_list), arguments=nmap_str, ports='-')#','.join(ports_list)
    print("command: ", nm.command_line())
    print(nm.all_hosts())
    # print(db_nmap(client, nmap_str))
    print("Nmap finished")
    print("Running db_nmap")
    print(client.db.workspaces.workspace('default').hosts.list)
    print("Finished db_nmap")
    return nm


def print_vuln_info(nm: nmap.PortScanner):
    """
    Print vulnerability info
    :param nm: nmap scan results
    :return: None
    """
    print("Printing vulnerability info")
    for host in nm.all_hosts():
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            lport = nm[host][proto].keys()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                if 'name' in nm[host][proto][port]:
                    print('name : %s' % nm[host][proto][port]['name'])
                if 'product' in nm[host][proto][port]:
                    print('product : %s' % nm[host][proto][port]['product'])
                if 'version' in nm[host][proto][port]:
                    print('version : %s' % nm[host][proto][port]['version'])
                if 'extrainfo' in nm[host][proto][port]:
                    print('extrainfo : %s' % nm[host][proto][port]['extrainfo'])
                if 'cpe' in nm[host][proto][port]:
                    print('cpe : %s' % nm[host][proto][port]['cpe'])
                if 'script' in nm[host][proto][port]:
                    print('script : %s' % nm[host][proto][port]['script'])
                if 'reason' in nm[host][proto][port]:
                    print('reason : %s' % nm[host][proto][port]['reason'])
                if 'conf' in nm[host][proto][port]:
                    print('conf : %s' % nm[host][proto][port]['conf'])
                if 'method' in nm[host][proto][port]:
                    print('method : %s' % nm[host][proto][port]['method'])
                if 'reason_ttl' in nm[host][proto][port]:
                    print('reason_ttl : %s' % nm[host][proto][port]['reason_ttl'])
                if 'version' in nm[host][proto][port]:
                    print('version : %s' % nm[host][proto][port]['version'])


    # add all hosts to db

    return None
def add_vulns_db(nm: nmap.PortScanner, hosts: pandas.DataFrame, client: MsfRpcClient):
    """
    Add vulnerabilities to db
    :param nm: nmap scan results
    :return: None
    """
    print("Adding hosts to db")
    for host in nm.all_hosts():
        # get os_name and os_flavor for host host in hosts dataframe
        os_name = hosts.loc[host, "os_name"]
        os_flavor = str(hosts.loc[host, "os_flavor"])

        print("Adding host:", host, "with os:", os_name, os_flavor)
        client.db.workspaces.workspace('default').hosts.report(host=host, state=nm[host].state(), os_name=os_name,
                                                               os_flavor=os_flavor, )
        # client.db.hosts.add(host, state=nm[host].state())
        for proto in nm[host].all_protocols():
            print('----------')
            print('Protocol : %s' % proto)

            lport = nm[host][proto].keys()
            print("lport:", lport)
            for port in lport:
                client.db.workspaces.workspace('default').services.report(host=host, port=port, proto=proto),
                print(nm[host][proto][port])
                # add vulns to db
                if 'script' in nm[host][proto][port]:
                    print("Adding vulns to db", nm[host][proto][port]['script'])
                    for script in nm[host][proto][port]['script']:
                        # Mandatory Arguments:
                        #         - host : the host where this vulnerability resides.
                        #         - name : the scanner-specific id of the vuln (e.g. NEXPOSE-cifs-acct-password-never-expires).
                        #
                        #         Optional Keyword Arguments:
                        #         - info : a human readable description of the vuln, free-form text.
                        #         - refs : an array of Ref objects or string names of references.
                        client.db.workspaces.workspace('default').vulns.report(host=host, name=script,
                                                                                 info=nm[host][proto][port]['script'][script])
    print("Finished adding hosts to db")
    return client







def main(client):
    try:
        # call bash command to start msfrpcd
        hosts = []
        if hosts == []:
            hosts = pandas.read_csv(os.path.join(cwd, '../hosts.csv'), index_col=0, header=0)
            host_list = hosts.index.tolist()
        else:
            host_list = hosts
        print(hosts)
        vuln_path = check_vuln_directory()
        nm = get_vuln_hosts(client, host_list, vuln_path)
        # print vulnerability information
        print_vuln_info(nm)
        # add vulns to db
        add_vulns_db(nm, hosts, client)
        hosts = nm.all_hosts()
        # print(nm.scanstats())
        # print(nm.command_line())
        # print(nm.csv())
        print( client.db.workspaces.workspace('default').hosts.list)
        print( client.db.workspaces.workspace('default').vulns.list)
    except Exception as e:
        print(type(e))
        print(e)
    finally:
        #gracefully disconnect from db


        # gracefully disconnect from msfrpcd
        # client.logout()
        # return to main
        return client


    # write nm to metasploit db
    # db_nmap(client, nmap_str)

    # print(client.call(MsfRpcMethod.ConsoleRead))

    # for host, attributes in hosts.iterrows():
    #     # call db_nmap -sV -sC -p445,139,3389 -oA nmap_results {host}

    # await console.execute(f"db_nmap -sV -sC -p445,139,3389 -O -oA nmap_results 192.168.56.132")
    # MsfRpcMethod.ConsoleWrite(f'db_nmap -sV -sC -p445,139,3389 -oA nmap_results {host}')
    #     print(attributes)
    #     print(host)
    #     print(attributes['ports'])
    #     ports = dict(attributes['ports']).keys()
    #     print(ports)
    #     print(
    # print(client.db.hosts.list)
    # console.call(MsfRpcMethod.ConsoleWrite, 'use exploit/windows/smb/ms17_010_eternalblue\n')
    # workspace_list = client.db.workspaces.list
    # print(workspace_list)
    # client.call(MsfRpcMethod.AuthLogout)
    # run db_nmap
    # client.call(MsfRpcMethod.AuthLogin, '123')
    # console = client.call(MsfRpcMethod.ConsoleCreate)
    # MsfRpcMethod.ConsoleWrite(console, 'db_nmap -sV -sC -p445,139,3389 -oA nmap_results {}'.format(ip_list))
