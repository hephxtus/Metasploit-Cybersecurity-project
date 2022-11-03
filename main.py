# This is a sample Python script.
import os
import time

from common.utils import create_header, split_string, cwd, printd, start_metasploit, clear_terminal
from pymetasploit3.msfrpc import MsfRpcMethod
from src import vulnerabilities, scan, exploit, interact  # , persistence, post_exploitation, cleanup


# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
VERBOSE = True

# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    """
    E.g. Press 1 (or automatically) scan a network (the user scans network subnet 192.168.1.0)
    o E.g. user inputs the target subnet
        The script shows the available and online target IPs/Systems within the subnet
        E.g. Press 2 (or Automatically) to start the process of vulnerability scanning and exploitation
    """
    exit = False
    TITLE = "NETWORK NUKE"
    MSG = "Welcome to the Network Nuke. Please select an option:"
    message = MSG




    try:
        client = start_metasploit()
        while not exit:
            if not VERBOSE:
                clear_terminal()
            printd(TITLE, header=True)

            printd(message, header=True)
            printd("0. reinitialize metasploit")
            printd("1. Scan a network")
            printd("2. Detect vulnerabilities in known hosts")
            printd("3. Exploit known vulnerabilities")
            printd("4. List all exploited hosts")
            printd("5. Exit")
            choice = input("Enter your choice: ")
            if choice == "0":
                client = start_metasploit()
                message = MSG
            if choice == "1":
                subnet_addr = str(input("Enter the subnet address: "))
                message = scan.main(client, subnet_addr)
            elif choice == "2":

                message = vulnerabilities.main(client)
            elif choice == "3":
                message = exploit.main(client, verbose=VERBOSE)
            elif choice == "4":
                message = interact.main(client)
            elif choice == "5":
                exit = True
            else:
                print("Invalid choice")
    finally:
        if client is not None:
            # client.db.disconnect()
            conlist = client.call(MsfRpcMethod.ConsoleList)
            print(conlist)
            for c in conlist['consoles']:
                cid = c['id']
                printd("Closing console: {}".format(cid))
                # client.consoles.console(cid).destroy()
            print(conlist)
            # client.call(MsfRpcMethod.ConsoleDestroy)
            client.call(MsfRpcMethod.AuthLogout)

    printd(create_header("Goodbye!"))

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
