import psutil
import socket
import json
import pandas as pd
import os
from datetime import datetime
import graphviz

print('\033[34;1m' + """  

BBBBBBBBBBBBBBBBB   DDDDDDDDDDDDD                               1111111   
B::::::::::::::::B  D::::::::::::DDD                           1::::::1   
B::::::BBBBBB:::::B D:::::::::::::::DD                        1:::::::1   
BB:::::B     B:::::BDDD:::::DDDDD:::::D                       111:::::1   
  B::::B     B:::::B  D:::::D    D:::::Dvvvvvvv           vvvvvvv1::::1   
  B::::B     B:::::B  D:::::D     D:::::Dv:::::v         v:::::v 1::::1   
  B::::BBBBBB:::::B   D:::::D     D:::::D v:::::v       v:::::v  1::::1   
  B:::::::::::::BB    D:::::D     D:::::D  v:::::v     v:::::v   1::::l   
  B::::BBBBBB:::::B   D:::::D     D:::::D   v:::::v   v:::::v    1::::l   
  B::::B     B:::::B  D:::::D     D:::::D    v:::::v v:::::v     1::::l   
  B::::B     B:::::B  D:::::D     D:::::D     v:::::v:::::v      1::::l   
  B::::B     B:::::B  D:::::D    D:::::D       v:::::::::v       1::::l   
BB:::::BBBBBB::::::BDDD:::::DDDDD:::::D         v:::::::v     111::::::111
B:::::::::::::::::B D:::::::::::::::DD           v:::::v      1::::::::::1
B::::::::::::::::B  D::::::::::::DDD              v:::v       1::::::::::1
BBBBBBBBBBBBBBBBB   DDDDDDDDDDDDD                  vvv        111111111111

               
               
                   -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                   +        ..| BDv1 v1.0 |..             +
                   -                                      -
                   -              By: Hamoud Alharbi      -
                   +         Twitter: @Hamoud__2          +
                   -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
""" + '\033[0m')


                                      


def display_network_connections():
    connections = []
    # normal ports
    normal_ports = [80, 443, 22, 3389, 1433]
    for conn in psutil.net_connections():
        
        if conn.family == socket.AF_INET and (conn.type == socket.SOCK_STREAM or conn.type == socket.SOCK_DGRAM):
            try:
                proc = psutil.Process(conn.pid)
                name = proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                name = ''
            local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
            if conn.raddr:
                # Check if the remote port is suspicious or not
                if conn.raddr.port not in normal_ports:
                    remote_addr = f"\033[31m{conn.raddr.ip}:{conn.raddr.port}\033[0m"
                else:
                    remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}"
                fd = conn.fd
                try:
                    timestamp = os.path.getctime(f"/proc/self/fd/{fd}")
                except (OSError, TypeError):
                    timestamp = 0
                duration = datetime.now() - datetime.fromtimestamp(timestamp)
                duration_str = str(duration).split('.')[0]  # Remove microseconds
            else:
                remote_addr = ''
                duration_str = ''
            connections.append({
                'Local Address': local_addr,
                'Remote Address': remote_addr,
                'Status': conn.status,
                'PID': conn.pid or '',
                'Process Name': name,
                'Duration': duration_str
            })

    if len(connections) > 0:
        df = pd.DataFrame(connections)
        print(df)
    else:
        print('No TCP connections found.')

def create_baseline():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'exe', 'cpu_percent', 'memory_percent', 'ppid']):
        process_info = {
            'pid': proc.info['pid'],
            'name': proc.info['name'],
            'cmdline': proc.info['cmdline'] if proc.info['cmdline'] is not None else '',
            'username': proc.info['username'] if proc.info['username'] is not None else '',
            'exe': proc.info['exe'],
            'cpu_percent': proc.info['cpu_percent'],
            'memory_percent': proc.info['memory_percent'],
            'ppid': proc.info['ppid']
        }

        
        try:
            conn = psutil.Process(proc.info['pid']).connections()
            ports = []
            for c in conn:
                if c.status == psutil.CONN_LISTEN:
                    ports.append(c.laddr.port)
            process_info['ports'] = ports
        except psutil.AccessDenied:
            process_info['ports'] = []

        processes.append(process_info)

    
    services = []
    for service in psutil.win_service_iter():
        try:
            description = service.description()
        except FileNotFoundError:
            description = ""

        services.append({
            'name': service.name(),
            'status': service.status(),
            'display_name': service.display_name(),
            'description': description,
            'start_type': service.start_type(),
            'binpath': service.binpath(),
            'username': service.username(),
            'pid': service.pid(),
            'process_name': psutil.Process(service.pid()).name() if service.pid() else ''
        })

    baseline = {
        'processes': processes,
        'services': services
    }

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    baseline_file = f'baseline_{timestamp}.json'
    with open(baseline_file, 'w') as f:
        json.dump(baseline, f)

    print('Baseline created successfully.')

def get_baseline_files():
    return [f for f in os.listdir() if f.startswith('baseline_') and f.endswith('.json')]

def select_baseline_file():
    files = get_baseline_files()
    if not files:
        return None
    print("\nSelect a baseline file:")
    for i, file in enumerate(files):
        print(f"{i + 1}. {file}")
    while True:
        choice = input("Enter the file number: ")
        if choice.isdigit() and 1 <= int(choice) <= len(files):
            return files[int(choice) - 1]
        else:
            print("Invalid choice. Please try again.")

def display_process_tree(processes):
    dot = graphviz.Digraph()
    for proc in processes:
        dot.node(str(proc['pid']), proc['name'])
        if proc['ppid'] != None:
            dot.edge(str(proc['ppid']), str(proc['pid']))
    dot.render("process_tree", format="png", view=True)

def compare_baseline():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'cmdline', 'username', 'ppid']):
        processes.append({
            'pid': proc.info['pid'],
            'name': proc.info['name'],
            'cpu_percent': proc.info['cpu_percent'],
            'memory_percent': proc.info['memory_percent'],
            'cmdline': proc.info['cmdline'],
            'username': proc.info['username'],
            'ppid': proc.info['ppid']
        })

    baseline_file = select_baseline_file()
    if not baseline_file:
        print('No previous baseline found. Please create a baseline first.')
        return
    with open(baseline_file, 'r') as f:
        previous_baseline = json.load(f)

    if len(processes) != len(previous_baseline['processes']):
        print('The number of running processes has changed. Please create a new baseline.')
        return

    diff = []
    for i, proc in enumerate(processes):
        prev_proc = previous_baseline['processes'][i]
        cmdline_str = ' '.join(proc['cmdline']) if proc['cmdline'] is not None else ''
        if proc['name'] != prev_proc['name'] or \
           proc['cpu_percent'] > prev_proc['cpu_percent'] or \
           proc['memory_percent'] > prev_proc['memory_percent'] or \
           proc['ppid'] != prev_proc['ppid'] or \
           proc['username'] != prev_proc['username'] or \
           cmdline_str != prev_proc['cmdline']:
            diff.append({
                'Process Name': prev_proc['name'],
                'Current CPU %': proc['cpu_percent'],
                'Previous CPU %': prev_proc['cpu_percent'],
                'Current Mem %': proc['memory_percent'],
                'Previous Mem %': prev_proc['memory_percent'],
                'PPID': proc['ppid'],
                'Username': proc['username'],
                'Command Line': cmdline_str
            })

    if len(diff) > 0:
        df = pd.DataFrame(diff)
        df.to_csv('comparison_results.csv', index=False)
        print('There are differences between the current state and the previous baseline:')
        print(df)
        print("The comparison results have been saved to 'comparison_results.csv'.")
        print("\nDo you want to display the process tree for the current state? (y/n)")
        choice = input()
        if choice.lower() == 'y':
            display_process_tree(processes)
    else:
        print('No differences found between the current state and the previous baseline.')

def create_process_tree_and_compare():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'ppid']):
        processes.append({
            'pid': proc.info['pid'],
            'name': proc.info['name'],
            'cpu_percent': proc.info['cpu_percent'],
            'memory_percent': proc.info['memory_percent'],
            'ppid': proc.info['ppid']
        })

    baseline_file = select_baseline_file()
    if not baseline_file:
        print('No previous baseline found. Please create a baseline first.')
        return
    with open(baseline_file, 'r') as f:
        previous_baseline = json.load(f)

    if len(processes) != len(previous_baseline['processes']):
        print('The number of running processes has changed. Please create a new baseline.')
        return

    diff = []
    for i, proc in enumerate(processes):
        prev_proc = previous_baseline['processes'][i]
        if proc['name'] != prev_proc['name'] or \
           proc['cpu_percent'] > prev_proc['cpu_percent'] or \
           proc['memory_percent'] > prev_proc['memory_percent']:
            diff.append({
                'Process Name': prev_proc['name'],
                'Current CPU %': proc['cpu_percent'],
                'Previous CPU %': prev_proc['cpu_percent'],
                'Current Mem %': proc['memory_percent'],
                'Previous Mem %': prev_proc['memory_percent']
            })

    if len(diff) > 0:
        df = pd.DataFrame(diff)
        df.to_csv('comparison_results.csv', index=False)
        print('There are differences between the current state and the previous baseline:')
        print(df)
        print("\nDo you want to display the process tree for the current state? (y/n)")
        choice = input()
        if choice.lower() == 'y':
            display_process_tree(processes)
    else:
        print('No differences found between the current state and the previous baseline.')
        print("\nDo you want to display the process tree for the current state? (y/n)")
        choice = input()
        if choice.lower() == 'y':
            display_process_tree(processes)

def display_menu():
    print("1. Create baseline")
    print("2. Compare baseline")
    print("3. Create process tree and compare with previous baseline")
    print("4. Display network connections")
    print("5. Exit")
    return input("Please select an option: ")

while True:
    option = display_menu()
    if option == '1':
        create_baseline()
    elif option == '2':
        compare_baseline()
    elif option == '3':
        create_process_tree_and_compare()
    elif option == '4':
        display_network_connections()
    elif option == '5':
        print("Exiting...")
        break
    else:
        print("Invalid option. Please try again.")
