import os
import subprocess
import time
# import pymetasploit3.pymetasploit3 as pymetasploit3
from pymetasploit3.msfrpc import MsfRpcClient, MsfRpcMethod

cwd = os.path.dirname(os.path.abspath(__file__))

DELAY = 0.15

def printd(message, delay=DELAY):
    """
    Print a message with a delay
    :param message:
    :param delay:
    :return:
    """
    time.sleep(delay)
    print(message)

    def create_header(msg) -> str:
        """
        Create a header for a message
        :param msg: the message
        :return: the header
        """
        # break message into lines of 30 characters
        max_len = 50
        border_thickness = 1
        offset = 1
        dist = border_thickness + offset
        lines = split_string(msg, max_len - dist * 2)
        # create a header
        # find the longest line
        longest_line = max(lines, key=len)
        header_size = len(longest_line) + dist * 2

        header = f"{'#' * header_size}\n" * border_thickness

        for line in lines:
            # find the size of the lin
            line_size = len(line)
            # calculate the number of spaces needed
            num_spaces = header_size - border_thickness * 2 - line_size
            padding = " " * int(num_spaces // 2)

            border = "#" * border_thickness
            text_area = f"{border}{padding}{line}{padding}{border}"
            if num_spaces % 2 != 0:
                text_area = text_area[:-border_thickness] + " " + text_area[-border_thickness:]

            # create the line
            header += f"{text_area}\n"

            # header += text_area
            # header += f"#{line}#\n"
        header += f"{'#' * header_size}\n" * border_thickness
        return header
        # add the message to the center of the text box

def create_header(msg) -> str:
    """
    Create a header for a message
    :param msg: the message
    :return: the header
    """
    # break message into lines of 30 characters
    max_len = 50
    border_thickness= 1
    offset = 1
    dist = border_thickness + offset
    lines = split_string(msg, max_len-dist*2)
    # create a header
    # find the longest line
    longest_line = max(lines, key=len)
    header_size = len(longest_line) + dist*2

    header = f"{'#' * header_size}\n" * border_thickness

    for line in lines:
        # find the size of the lin
        line_size = len(line)
        # calculate the number of spaces needed
        num_spaces = header_size - border_thickness * 2 - line_size
        padding = " " * int(num_spaces//2)

        border = "#" * border_thickness
        text_area = f"{border}{padding}{line}{padding}{border}"
        if num_spaces % 2 != 0:
            text_area = text_area[:-border_thickness] + " " + text_area[-border_thickness:]

        # create the line
        header += f"{text_area}\n"


        # header += text_area
        # header += f"#{line}#\n"
    header += f"{'#' * header_size}\n" * border_thickness
    return header
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

def clear_terminal():
    """
    Clear terminal
    :return:
    """
    os.system('cls' if os.name == 'nt' else 'clear')
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


def split_string(msg, max_len):
    """
    Split string into chunks of max_len
    :param msg: string to split
    :param max_len: max length of each chunk
    :return: list of chunks
    """
    return [msg[i:i + max_len] for i in range(0, len(msg), max_len)]


