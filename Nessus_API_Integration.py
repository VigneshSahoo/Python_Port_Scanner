import requests
import json
import pprint


accessKey = 'sampleaccesskey'
secretKey = 'samplesecretkey'

ip = 'localhost'
port = '8834'
username = 'username'
password = 'password'
hosts = '192.168.1.1'  # Targets to scan


def get_token(ip, port, username, password):
    url = f"https://{ip}:{port}/session"
    post_data = {
        'username': username,
        'password': password
    }

    response = requests.post(url, data=post_data, verify=False)
    if response.status_code == 200:
        data = json.loads(response.text)
        # print(data)
        return data["token"]


def get_scan_list():
    url = f"https://{ip}:{port}/scans"
    token = get_token(ip, port, username, password)
    if token:
        header = {
            'X-ApiKeys': f'accessKey={accessKey};secretKey={secretKey}',
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=header, verify=False)
        if response.status_code == 200:
            result = json.loads(response.text)
            # pprint.pprint(result)
            return result


def get_nessus_template_uuid(ip, port, template_name="advanced"):
    header = {
        'X-ApiKeys': f'accessKey={accessKey};secretKey={secretKey}',
        'Content-type': 'application/json',
        'Accept': 'text/plain'}

    api = f"https://{ip}:{port}/editor/scan/templates"
    response = requests.get(api, headers=header, verify=False)
    templates = json.loads(response.text)['templates']
    # pprint.pprint(templates)

    for template in templates:
        if template['name'] == template_name:
            # print(template['uuid'])
            return template['uuid']
    return None


# get_token(ip, port, username, password)
get_scan_list()


# template_uuid = get_nessus_template_uuid(ip, port)


def create_task(task_name, hosts):  # host is a list of multiple hosts that need to be scanned
    uuid = get_nessus_template_uuid(ip, port, "advanced")  # Get uuid of advanced policy
    if uuid is None:
        return False

    data = {"uuid": uuid, "settings": {
        "name": task_name,
        "enabled": False,
        "text_targets": hosts,
        "agent_group_id": []
    }}

    header = {
        'X-ApiKeys': f'accessKey={accessKey};secretKey={secretKey}',
        'Content-type': 'application/json',
        'Accept': 'text/plain'}

    api = f"https://{ip}:{port}/scans"
    response = requests.post(api, headers=header, data=json.dumps(data, ensure_ascii=False).encode("utf-8"),
                             verify=False)
    # print(response.text)
    # print(response.status_code)
    if response.status_code == 200:
        data = json.loads(response.text)
        if data["scan"] is not None:
            scan = data["scan"]
            # New task extension information record
            return scan["id"]  # Return task id


task_id = create_task('API_Test_Scan', hosts)


def start_task(task_id, hosts):
    header = {
        'X-ApiKeys': f'accessKey={accessKey};secretKey={secretKey}',
        'Content-type': 'application/json',
        'Accept': 'text/plain'}

    data = {
        "alt_targets": [hosts]  # Reassign scan address
    }

    api = f"https://{ip}:{port}/scans/{task_id}/launch"
    response = requests.post(api, data=data, verify=False, headers=header)
    if response.status_code != 200:
        return False
    else:
        return True


def stop_task(task_id):
    header = {
        'X-ApiKeys': f'accessKey={accessKey};secretKey={secretKey}',
        'Content-type': 'application/json',
        'Accept': 'text/plain'}

    api = f"https://{ip}:{port}/scans/{task_id}/stop"
    response = requests.post(api, headers=header, verify=False)
    if response.status_code == 200 or response.status_code == 409:  # According to the nessus api documentation,
        # 409 means the task is finished
        return True
    return False


def get_task_status(task_id):
    header = {
        "X-ApiKeys": f"accessKey={accessKey};secretKey={secretKey}",
        "Content-Type": "application/json",
        "Accept": "text/plain"
    }

    api = f"https://{ip}:{port}/scans/{task_id}"
    response = requests.get(api, headers=header, verify=False)
    # pprint.pprint(response.text)
    if response.status_code != 200:
        print('Task Not Found')
        return 2, "Data Error"

    data = json.loads(response.text)

    if data["info"]["status"] == "completed" or data["info"]["status"] == 'canceled':
        # Finished, update local task status
        return 1, "OK"
    else:
        print('Scan Not Completed')


get_task_status(6)
