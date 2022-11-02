import time
import pandas

from pymetasploit3.msfrpc import MsfRpcClient


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
    exploited_hosts = pandas.DataFrame(columns=['Session ID', 'IP', 'OS', 'Exploit', 'Status'])
    # get all hosts
    hosts = client.db.workspaces.workspace('default').hosts.list
    vulns = client.db.workspaces.workspace('default').vulns.list
    sessions = client.sessions.list

    # get all hosts with vulns
    for host in hosts:
        if host['os_name'] is not None:
            exploited_hosts = exploited_hosts.append({'IP': host['address'], 'OS': host['os_name'], 'Exploit': 'None', 'Status': 'Offline'}, ignore_index=True)
        else:
            exploited_hosts = exploited_hosts.append({'IP': host['address'], 'OS': 'Unknown', 'Exploit': 'None', 'Status': 'Offline'}, ignore_index=True)
    # get all hosts with exploits
    for vuln in vulns:
        if vuln['host'] is not None:
            exploited_hosts.loc[exploited_hosts['IP'] == vuln['host'], 'Exploit'] = vuln['name']
    # get all hosts with sessions
    for session in sessions:
        exploited_hosts.loc[exploited_hosts['IP'] == session['host'], 'Status'] = 'Online'
        exploited_hosts.loc[exploited_hosts['IP'] == session['host'], 'Session ID'] = session['id']
    # set session id as index
    exploited_hosts.set_index('Session ID', inplace=True)
    # pretty print table
    print(exploited_hosts.to_string())




    # # print sessions
    # # sessions = pandas.DataFrame(index=range(0, len(client.sessions.list)), columns=['id', 'type', 'info', 'via_payload', 'via_exploit', 'tunnel_peer', 'username', 'uuid', 'exploit_uuid', 'workspace', 'target_host', 'target_port', 'routes', 'arch', 'platform', 'tunnel_local', 'tunnel_peer', 'tunnel_port', 'tunnel_sub', 'tunnel_via_exploit', 'tunnel_via_payload', 'uuid', 'via_exploit', 'via_payload', 'workspace'])
    # cmd = input("enter a command: ")
    # print("Sessions:")
    # for session in client.sessions.list:
    #     print(session)
    # cid=[c['id'] for c in client.consoles.list]
    # for c in cid:
    #     print(c)
    #     print(client.consoles.console(c).read())
    #     client.consoles.console(c).write(cmd)
    #     time.sleep(1)
    #     print(client.consoles.console(c).read())
    # console=client.consoles.console(cid)

    # console.read()
