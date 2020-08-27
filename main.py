from flask import Flask, render_template
import nmap
import socket
import sys
from datetime import datetime
import csv

nm = nmap.PortScanner()
app = Flask(__name__)
scan_data = nm.scan(hosts="192.168.1.1-10", arguments='-sP')
target_hosts = nm.all_hosts()

with open('alive_hosts.csv', 'a') as f:
    for hosts in target_hosts:
        f.write(hosts + '\n')

# target_hosts = ping_sweep(hosts_input=input('Please enter hosts to scan: '),
#                           nmap_commands=input('Please enter arguments: '))
target_ports = [21, 80, 443]
ports_status = []
t1 = datetime.now()


def port_scanner():
    for host in target_hosts:
        print(f'\nScan Result of {host}: ')
        try:
            for port in target_ports:
                tcp_connect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = tcp_connect.connect_ex((host, port))
                if result == 0:
                    print(f'Port {port} Open')
                    ports_status.append('Open')
                else:
                    print(f'Port {port} Closed')
                    ports_status.append('Closed')
                tcp_connect.close()
            with open('scan_results.txt', 'a', newline='') as f1:
                writer = csv.writer(f1)
                writer.writerow(f"Scan Report of {host}:")
                writer.writerows(zip(target_ports, ports_status))
        except KeyboardInterrupt:
            print("You pressed Ctrl+C")
            sys.exit()
        except socket.gaierror:
            print('Hostname could not be resolved. Exiting')
            sys.exit()
        except socket.error:
            print("Couldn't connect to server")
            sys.exit()


port_scanner()
t2 = datetime.now()
total = t2 - t1
print(f'\nScanning Completed in: {total}s')


@app.route('/')
def index():
    return render_template('dashboard.html', content1=target_hosts)


if __name__ == '__main__':
    app.run(debug=True)
