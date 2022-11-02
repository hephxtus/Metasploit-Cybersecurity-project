import subprocess
import time
# import pymetasploit3.pymetasploit3 as pymetasploit3
from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcMethod


def connect_to_msf(start_time, max_time, depth=0):
    p = None
    try:
        client = MsfRpcClient('123', port=55552)
        # client.call(MsfRpcMethod.AuthLogout)
        # client.call(MsfRpcMethod.AuthLogin, '123')

    except Exception as e:
        print(depth)
        print(start_time, time.time(), max_time)
        if start_time + max_time > time.time():
            print("waiting for msfrpcd to start")
            time.sleep(5)
            return connect_to_msf(start_time, max_time, depth + 1)
        else:
            raise TimeoutError("Could not connect to msfrpcd")
    return client
# global_positive_out = list()
# def read_console(console_data):
#     global global_positive_out
#     global global_console_status
#     global_console_status = console_data['busy']
#     if '[+]' in console_data['data']:
# 	sigdata = console_data['data'].rstrip().split('\n')
# 	for line in sigdata:
# 	    if '[+]' in line:
# 		global_positive_out.append(line)

def start_metasploit():
    """
    Start metasploit
    :return: True if started, False otherwise
    """
    client=None
    try:
        try:
            print("Attempting connection to msfrpcd")
            client = MsfRpcClient('123', port=55552)
            # client.call(MsfRpcMethod.AuthLogout)
            # client.call(MsfRpcMethod.AuthLogin, '123')
        except:
            print("Starting msfrpcd")
            p = subprocess.Popen(["msfrpcd", "-P", "123", "-U", "msf", "-S", "-f", "-p", "55552", "-a", "127.0.0.1"],
                                 stdout=subprocess.PIPE)
            # p.wait()
            # time.sleep(10)
            print(p.poll())

            client = connect_to_msf(time.time(), 60)
            print(p.poll())

        print("Creating console")
        client.call(MsfRpcMethod.ConsoleCreate)
        print("Console created")
        print("Console id:", client.call(MsfRpcMethod.ConsoleList))
        print("Creating database")
        # try:
        #     client.db.connect(username='msf', password='123', database='msf', port=55553, host="127.0.0.1")
        # except:
        subprocess.call(["/usr/bin/sudo", "msfdb", "init"])
        time.sleep(5)
        print(client.db.connect(username='msf', password='123', database='msf', port=55552, host="127.0.0.1"))

        print("Database created")
        try:
            print(client.db.status)
            print(client.db.status['db'])
        except Exception as e:
            print(e)
            print("Database does not exist, creating")
            # client.call(MsfRpcMethod.ConsoleWrite, "sudo msfdb init")
            # time.sleep(5)
        finally:
            pass

        print("connecting to db")
        print(client.db.status)
        print(client.db.workspaces.list)
        print(client.sessions.list)
        print("Connected to msfrpcd")

        return client
    except Exception as e:
        print(e)
        return client