import time
from pprint import pprint
from zapv2 import ZAPv2
import requests


target = 'https://www.facebook.com'
apiKey = 'changeme'
zap = ZAPv2(apikey=apiKey)


def spider():
    print(f'Spidering target {target}')
    
    scan_id = zap.spider.scan(target)
    
    while int(zap.spider.status(scan_id)) < 100:
        print(f'Spider progress %: {zap.spider.status(scan_id)}')
        time.sleep(2)
    
    print('Spider has completed!')
    print('\n'.join(map(str, zap.spider.results(scan_id))))


def passive_scan():
    while int(zap.pscan.records_to_scan) > 0:
        # Loop until the passive scan has finished
        print('Records to passive scan : ' + zap.pscan.records_to_scan)
        time.sleep(2)

    print('Passive Scan completed')


def passive_scan_results():
    # Print Passive scan results/alerts
    print('Hosts: {}'.format(', '.join(zap.core.hosts)))
    print('Alerts: ')
    pprint(zap.core.alerts())


def active_scan():
    print('Active Scanning target {}'.format(target))
    scan_id = zap.ascan.scan(target)
    while int(zap.ascan.status(scan_id)) < 100:
        # Loop until the scanner has finished
        print('Scan progress %: {}'.format(zap.ascan.status(scan_id)))
        time.sleep(5)

    print('Active Scan completed')


def active_scan_results():
    # Print vulnerabilities found by the scanning
    print('Hosts: {}'.format(', '.join(zap.core.hosts)))
    print('Alerts: ')
    pprint(zap.core.alerts(baseurl=target))


def scan_results():
    headers = {
        'Accept': 'application/json',
        'X-ZAP-API-Key': '76tu0np28dhqqhbqujuopi7jm3'
    }
    r = requests.get('http://localhost:8080/OTHER/core/other/htmlreport/', params={}, headers=headers)
    file = open('Final_Report.html', 'w')
    file.write(r.text)
    file.close()
    print("Scan Report has been exported successfully!")


spider()
passive_scan()
active_scan()
scan_results()
