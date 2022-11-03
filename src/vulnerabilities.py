"""
check for vulnerable ports
"""
import json
import os
import subprocess
import time

import nmap
import pandas
import pandas as pd
# from pymetasploit3 import *
from pymetasploit3.msfrpc import MsfRpcMethod, MsfRpcClient

from common.utils import start_metasploit, cwd, clear_terminal, printd

vulns_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../nmap-vulners/")
cwd = os.path.dirname(os.path.abspath(__file__))



# def db_nmap(client, nmap_str):
#     """
#     Run nmap scan on a list of hosts
#     :param hosts: list of hosts
#     :param ports: list of ports
#     :return: list of hosts
#     """
#     printd("Running nmap")
#     printd(nmap_str)
#     console = client.call(MsfRpcMethod.ConsoleCreate)
#     printd("Console created")
#     client.call(MsfRpcMethod.ConsoleWrite, console, f"db_nmap {nmap_str}")
#     time.sleep(5)
#     printd("Nmap finished")
#     printd(client.call(MsfRpcMethod.ConsoleRead, console))
#     client.call(MsfRpcMethod.ConsoleDestroy, console)
#     time.sleep(5)
#     printd("Console destroyed")
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
    printd("Loading Hosts...")
    # if hosts is None:
    #     # printd(*pandas.read_csv("ip_list.csv").iterrows())
    #     hosts = pandas.read_csv(os.path.join(cwd, 'hosts.csv'), index_col=0, header=0)
    # printd(hosts["ports"])
    printd("Hosts loaded")

    # list of all hosts
    hosts_list = list(hosts)
    # concat all ports into 1 list
    # ports_list = []
    # for p in hosts["ports"]:
    #     ports_list += list(json.loads(p))
    # ports_list = set([str(p) for p in ports_list])

    printd("Running nmap on hosts:", hosts_list)
    nmap_str = f"--script {script} -sV --open" #-sV -sC
    printd("Nmap string:", nmap_str)
    nm = nmap.PortScanner()
    nm.scan(hosts=' '.join(hosts_list), arguments=nmap_str, ports='-')#','.join(ports_list)
    printd("command: ", nm.command_line())
    printd(nm.all_hosts())
    # printd(db_nmap(client, nmap_str))
    cid = client.consoles.list[0]['id']
    console = client.consoles.console(cid)
    # console.write(f"db_nmap {nmap_str} -p- {','.join(hosts_list)}")
    time.sleep(5)
    data = console.read()['data']
    printd(data)
    while data != "":
        data = console.read()['data']
        printd(data)
    printd("Nmap finished")
    printd("Running db_nmap")
    printd(client.db.workspaces.workspace('default').hosts.list)
    printd("Finished db_nmap")
    return nm


def printd_vuln_info(nm: nmap.PortScanner):
    """
    printd vulnerability info
    :param nm: nmap scan results
    :return: None
    """
    printd("printding vulnerability info")
    for host in nm.all_hosts():
        printd('Host : %s (%s)' % (host, nm[host].hostname()))
        printd('State : %s' % nm[host].state())
        for proto in nm[host].all_protocols():
            printd('----------')
            printd('Protocol : %s' % proto)

            lport = nm[host][proto].keys()
            for port in lport:
                printd('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
                if 'name' in nm[host][proto][port]:
                    printd('name : %s' % nm[host][proto][port]['name'])
                if 'product' in nm[host][proto][port]:
                    printd('product : %s' % nm[host][proto][port]['product'])
                if 'version' in nm[host][proto][port]:
                    printd('version : %s' % nm[host][proto][port]['version'])
                if 'extrainfo' in nm[host][proto][port]:
                    printd('extrainfo : %s' % nm[host][proto][port]['extrainfo'])
                if 'cpe' in nm[host][proto][port]:
                    printd('cpe : %s' % nm[host][proto][port]['cpe'])
                if 'script' in nm[host][proto][port]:
                    printd('script : %s' % nm[host][proto][port]['script'])
                if 'reason' in nm[host][proto][port]:
                    printd('reason : %s' % nm[host][proto][port]['reason'])
                if 'conf' in nm[host][proto][port]:
                    printd('conf : %s' % nm[host][proto][port]['conf'])
                if 'method' in nm[host][proto][port]:
                    printd('method : %s' % nm[host][proto][port]['method'])
                if 'reason_ttl' in nm[host][proto][port]:
                    printd('reason_ttl : %s' % nm[host][proto][port]['reason_ttl'])
                if 'version' in nm[host][proto][port]:
                    printd('version : %s' % nm[host][proto][port]['version'])


    # add all hosts to db

    return None
def add_vulns_db(nm: nmap.PortScanner, hosts: pandas.DataFrame, client: MsfRpcClient):
    """
    Add vulnerabilities to db
    :param nm: nmap scan results
    :return: None
    """
    printd("Adding hosts to db")
    for host in nm.all_hosts():
        printd(nm[host])
        # get os_name and os_flavor for host host in hosts dataframe
        os_name = hosts.loc[host, "os_name"]
        os_flavor = str(hosts.loc[host, "os_flavor"])

        printd("Adding host:", host, "with os:", os_name, os_flavor)
        client.db.workspaces.workspace('default').hosts.report(host=host, state=nm[host].state(), os_name=os_name,
                                                               os_flavor=os_flavor, )
        # client.db.hosts.add(host, state=nm[host].state())
        for proto in nm[host].all_protocols():
            printd('----------')
            printd('Protocol : %s' % proto)

            lport = nm[host][proto].keys()
            printd("lport:", lport)
            for port in lport:
                # Optional Keyword Arguments:
                #         - name : the application layer protocol (e.g. ssh, mssql, smb)
                #         - sname : an alias for the above
                client.db.workspaces.workspace('default').services.report(host=host, port=port, proto=proto, name=nm[host][proto][port]['name'], ),
                printd(nm[host][proto][port])
                # add vulns to db
                if 'script' in nm[host][proto][port]:
                    printd("Adding vulns to db", nm[host][proto][port]['script'])
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
    printd("Finished adding hosts to db")
    return client







def main(client):
    clear_terminal()
    try:
        # call bash command to start msfrpcd
        hosts = []
        if hosts == []:
            hosts = pandas.read_csv(os.path.join(cwd, '../hosts.csv'), index_col=0, header=0)
            host_list = hosts.index.tolist()
        else:
            host_list = hosts
        printd(hosts)
        vuln_path = check_vuln_directory()
        nm = get_vuln_hosts(client, host_list, vuln_path)
        # printd vulnerability information
        printd_vuln_info(nm)
        # add vulns to db
        add_vulns_db(nm, hosts, client)
        hosts = nm.all_hosts()
        # printd(nm.scanstats())
        # printd(nm.command_line())
        # printd(nm.csv())
        # printd( client.db.workspaces.workspace('default').hosts.list)
        # printd( client.db.workspaces.workspace('default').vulns.list)
    except Exception as e:
        return f"Error ({type(e)}): {e}"
    finally:
        #gracefully disconnect from db


        # gracefully disconnect from msfrpcd
        # client.logout()
        # return to main
        vulns = client.db.workspaces.workspace('default').vulns.list
        vulns_df = pandas.DataFrame(vulns, columns=list(vulns[0].keys()), index=[vuln['address'] for vuln in vulns])
        return vulns_df



