# This is a sample Python script.
import common.utils
from pymetasploit3.msfrpc import MsfRpcMethod
from src import vulnerabilities, scan, exploit, interact
# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.


def print_hi(name):
    # Use a breakpoint in the code line below to debug your script.
    print(f'Hi, {name}')  # Press Ctrl+F8 to toggle the breakpoint.


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    """
    E.g. Press 1 (or automatically) scan a network (the user scans network subnet 192.168.1.0)
    o E.g. user inputs the target subnet
        The script shows the available and online target IPs/Systems within the subnet
        E.g. Press 2 (or Automatically) to start the process of vulnerability scanning and exploitation
    """

    exit = False
    try:
        client = common.utils.start_metasploit()
        while not exit:
            print("1. Scan a network")
            print("2. Detect vulnerabilities in known hosts")
            print("3. Exploit known vulnerabilities")
            print("4. List all exploited hosts")
            print("5. Exit")
            choice = input("Enter your choice: ")
            if choice == "1":
                scan.main(client)
            elif choice == "2":

                vulnerabilities.main(client)
            elif choice == "3":
                exploit.main(client)
            elif choice == "4":
                interact.main(client)
            elif choice == "5":
                exit = True
            else:
                print("Invalid choice")
    finally:
        if client is not None:
            client.db.disconnect()
            conlist = client.call(MsfRpcMethod.ConsoleList)
            print(conlist)
            client.call(MsfRpcMethod.ConsoleDestroy)
            client.call(MsfRpcMethod.AuthLogout)

    print_hi('PyCharm')

# See PyCharm help at https://www.jetbrains.com/help/pycharm/
