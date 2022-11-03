import os
import time
import pandas

from common.utils import cwd, clear_terminal, printd
from pymetasploit3.msfrpc import MsfRpcClient

def show_table(client, exploited_hosts, hosts, vulns, sessions):

    # get all hosts

    # printd(sessions)
    # get all hosts from hosts.csv
    clear_terminal()
    hosts_real = pandas.read_csv(os.path.join(cwd, '../hosts.csv'), index_col=0, header=0)
    # printd(hosts_real.index.tolist())
    # remove hosts that are not in hosts.csv

    # remove hosts from db that are not in hosts.csv
    for host in hosts:
        if host['address'] not in hosts_real.index.tolist():
            client.db.workspaces.workspace('default').hosts.delete(address=host['address'])
    hosts = client.db.workspaces.workspace('default').hosts.list
    # get all hosts with vulns
    for host in hosts:
        if host['os_name'] is not None:
            exploited_hosts = exploited_hosts.append(
                {'IP': host['address'], 'OS': host['os_name'], 'Exploit': 'None', 'Status': 'Offline'},
                ignore_index=True)
        else:
            exploited_hosts = exploited_hosts.append(
                {'IP': host['address'], 'OS': 'Unknown', 'Exploit': 'None', 'Status': 'Offline'}, ignore_index=True)
    # get all hosts with exploits
    for vuln in vulns:
        if vuln['host'] is not None:
            exploited_hosts.loc[exploited_hosts['IP'] == vuln['host'], 'Exploit'] = vuln['name']
    # get all hosts with sessions
    for sid, session in sessions.items():
        # printd(sid)
        # printd('SESSION:', session.keys())
        exploited_hosts.loc[exploited_hosts['IP'] == session['session_host'], 'Status'] = 'Online'
        exploited_hosts.loc[exploited_hosts['IP'] == session['session_host'], 'Session ID'] = sid
        exploited_hosts.loc[exploited_hosts['IP'] == session['session_host'], 'Exploit'] = session['via_exploit']
        exploited_hosts.loc[exploited_hosts['IP'] == session['session_host'], 'shell'] = session['type']
        # set session id as index
    exploited_hosts.set_index('Session ID', inplace=True)
    # pretty printd table
    printd(exploited_hosts.to_string())

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
    # Session - This column refers to the session number. Sessions are assigned a number based on when the session is opened, the first of which is assigned an ID of 1. Clicking Session will allow you to pick which modules to run during the open sessions or use a terminal instead.
    # OS- Exploited host operating system.
    # Host - Name of the exploited host. Clicking the host will take you to a details page, where you can see the host status and detailed information about the target host.
    # Type - The session type opened. The session type will be either a shell or Meterpreter session.
    # Opened - The date and time the session was opened using format yyyy-mm-dd hr:mm:ss -timezone.
    # Description - The description of the credential type used to open the session with the host IP address. If the credential type is unknown, this is left blank.
    # Attack Module - Module used to exploit the target host and open a session. Clicking the module will take you a dedicated page where you can run the module on a target host and see more information about the module.
    # create table to show all hosts
    # get all console sessions
    # consoles = client.consoles.list
    # printd(consoles)
    # for console in consoles:
    #     cid = console['id']
    #     client.consoles.console(cid).write('sessions -l')
    #     time.sleep(1)
    #     printd(client.consoles.console(cid).read())
    exploited_hosts = pandas.DataFrame(columns=['Session ID', 'IP', 'OS', "shell", 'Exploit', 'Status'])

    hosts = client.db.workspaces.workspace('default').hosts.list
    vulns = client.db.workspaces.workspace('default').vulns.list
    sessions = client.sessions.list

    show_table(client, exploited_hosts, hosts, vulns, sessions)


    go_back = False
    while not go_back:
        try:
            printd(exploited_hosts)
            printd('1. Select host')
            printd('2. Go back')
            choice = input('Enter your choice: ')
            if choice == '1':
                while not go_back:
                    printd(exploited_hosts.index.tolist())
                    sid = input('Enter session id: ')
                    if sid in exploited_hosts.index.tolist():
                        s = client.sessions.session(sid)

                        while not go_back:
                            printd('1. Download file')
                            printd('2. Upload file')
                            printd('3. Run command')
                            printd('4. Shut down')
                            printd('5. Go back')
                            choice = input('Enter your choice: ')
                            if choice in ['1', '2', '3']:
                                # run command, download file, upload file

                                session_type = sessions[sid]['type']
                                prefix = '{}({}) {}>  '
                                while not go_back:
                                    # if s['type'] == 'shell':
                                    #     s = s.upgrade()
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
                                        break
                                    else:
                                        s.run_with_output(command)
                                        time.sleep(1)
                                        out = ''
                                        while len(out) == 0:
                                            time.sleep(1)
                                            out = s.read()

                                go_back = False
                            elif choice == '4':
                                # shut down
                                s.write('exit')
                                s.stop()
                                s.kill()
                                exploited_hosts.loc[sid, 'Status'] = 'Offline'
                                show_table(client, exploited_hosts, hosts, vulns, sessions)
                                break
                            elif choice == '5':
                                # go back
                                break
                            elif choice.lower() == 'exit':
                                return show_table(client, exploited_hosts, hosts, vulns, sessions)
                            else:
                                printd('Invalid choice')
                                break
                    elif choice.lower() == 'exit':
                        return show_table(client, exploited_hosts, hosts, vulns, sessions)
                    else:
                        break
            elif choice == '2':
                go_back = True
            elif choice.lower() == 'exit':
                return show_table(client, exploited_hosts, hosts, vulns, sessions)
            else:
                printd('Invalid choice')

        except Exception as e:
            return f"Error ({type(e)}): {e}"
        else:
            return show_table(client, exploited_hosts, hosts, vulns, sessions)





    # # printd sessions
    # # sessions = pandas.DataFrame(index=range(0, len(client.sessions.list)), columns=['id', 'type', 'info', 'via_payload', 'via_exploit', 'tunnel_peer', 'username', 'uuid', 'exploit_uuid', 'workspace', 'target_host', 'target_port', 'routes', 'arch', 'platform', 'tunnel_local', 'tunnel_peer', 'tunnel_port', 'tunnel_sub', 'tunnel_via_exploit', 'tunnel_via_payload', 'uuid', 'via_exploit', 'via_payload', 'workspace'])
    # cmd = input("enter a command: ")
    # printd("Sessions:")
    # for session in client.sessions.list:
    #     printd(session)
    # cid=[c['id'] for c in client.consoles.list]
    # for c in cid:
    #     printd(c)
    #     printd(client.consoles.console(c).read())
    #     client.consoles.console(c).write(cmd)
    #     time.sleep(1)
    #     printd(client.consoles.console(c).read())
    # console=client.consoles.console(cid)

    # console.read()
