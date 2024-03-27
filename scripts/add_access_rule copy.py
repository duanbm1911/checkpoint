from __future__ import print_function
from ipaddress import ip_network, IPv4Address
from requests.auth import HTTPBasicAuth
import sys, os, re, requests, json, time
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cpapi.mgmt_api import APIClient, APIClientArgs


dc_smc_server = 'ec2-18-143-77-148.ap-southeast-1.compute.amazonaws.com'
dr_smc_server = ''
username = 'admin'
password = 'Minhduan@123'
icms_username = 'admin'
icms_password = 'admin@123'
icms_url = 'http://127.0.0.1:8000/'


def is_subnet(subnet):
    try:
        ip_network(subnet)
        return True
    except:
        return False
    
def is_ipaddress(ip):
    try:
        IPv4Address(ip)
        return True
    except:
        return False
    
def is_domain(domain):
    regex = r"^(?!:\/\/)([a-zA-Z0-9-_]+(\.[a-zA-Z0-9-_]+)*\.[a-zA-Z]{2,63}|localhost)$"
    if re.match(regex, domain):
        return True
    else:
        return False

def create_host_object(session, host):
    name = f'IP_{host}'
    data = {
        'name': name,
        'ipv4-address': host
    }
    add_network_result = session.api_call("add-host", data)
    if add_network_result.success:
        return name
    
def create_network_object(session, subnet, prefix_len):
    name = f'Subnet_{subnet}'
    data = {
        'name': name,
        'subnet4': subnet,
        'mask-length4': int(prefix_len)
    }
    add_subnet_result = session.api_call("add-network", data)
    if add_subnet_result.success:
        return name
    
def create_domain_object(session, domain):
    data = {
        'name': domain,
        'servers': domain
    }
    add_domain_result = session.api_call("add-network", data)
    if add_domain_result.success:
        return domain
    
def create_time_object(session, date):
    name = date
    end_datetime = f'{date}T00:00:00'
    data = {
        'name': name,
        'end': {
            'iso-8601': end_datetime
        },
        'start-now': True
    }
    add_time_result = session.api_call("add-time", data)
    if add_time_result.success:
        return name
    
def create_service_object(session, service):
    port = str()
    if len(service.split('-')) == 2:
        port = service.split('-')[1]
    else:
        start_port = service.split('-')[1]
        end_port = service.split('-')[2]
        port = f'{start_port}-{end_port}'
    data = {
        'name': service,
        'port': port
    }
    if 'tcp' in service:
        add_service_result = session.api_call("add-service-tcp", data)
        if add_service_result.success:
            return service
    else:
        add_service_result = session.api_call("add-service-udp", data)
        if add_service_result.success:
            return service

def get_list_task(icms_username, icms_password):
    api = 'api/cm/checkpoint/get-list-task'
    url = icms_url + api
    res = requests.get(url=url, auth=HTTPBasicAuth(icms_username, icms_password))
    if res.ok:
        datalist = json.loads(res.text)['datalist']
        return {'status': 'success', 'datalist': datalist}
    else:
        return {'status': 'failed', 'message': res.text}
    
def update_task_status(icms_username, icms_password, policy_id, status, message):
    api = 'api/cm/checkpoint/update-task-status'
    url = icms_url + api
    data = {
        'policy_id': policy_id,
        'status': status,
        'message': message
    }
    res = requests.post(url=url, data=data, auth=HTTPBasicAuth(icms_username, icms_password), verify=False)
    if res.ok:
        return {'status': 'success'}
    else:
        return {'status': 'failed', 'message': res.text}

def check_host_object(session, host):
    obj = str()
    get_all_hosts = session.gen_api_query("show-hosts", details_level="full")
    for item in get_all_hosts:
        getlist = [i['name'] for i in item.data['objects'] if host == i['ipv4-address']]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_host_object(session, host)
        if obj is not None:
            return obj
    
def check_network_object(session, network):
    subnet = network.split('/')[0]
    prefix_len = network.split('/')[1]
    get_all_networks = session.gen_api_query("show-networks", details_level="full")
    for item in get_all_networks:
        getlist = [i['name'] for i in item.data['objects'] if i.get('subnet4') is not None and subnet == i['subnet4'] and int(prefix_len) == i['mask-length4']]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_network_object(session, subnet, prefix_len)
        if obj is not None:
            return obj

def check_domain_object(session, domain):
    get_all_domains = session.gen_api_query("show-networks", details_level="full")
    for item in get_all_domains:
        getlist = [i['name'] for i in item.data['objects'] if i.get('subnet4') is not None and subnet == i['subnet4'] and int(prefix_len) == i['mask-length4']]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_network_object(session, subnet, prefix_len)
        if obj is not None:
            return obj

def check_service_object(session, service):
    port = str()
    if len(service.split('-')) == 2:
        port = service.split('-')[1]
    else:
        start_port = service.split('-')[1]
        end_port = service.split('-')[2]
        port = f'{start_port}-{end_port}'
    if 'tcp' in service:
        get_all_services = session.gen_api_query("show-services-tcp", details_level="full")
        for item in get_all_services:
            getlist = [i['name'] for i in item.data['objects'] if port == i['port']]
        if len(getlist) > 0:
            return getlist[0]
        else:
            obj = create_service_object(session, service)
            if obj is not None:
                return obj
    else:
        get_all_services = session.gen_api_query("show-services-udp", details_level="full")
        for item in get_all_services:
            getlist = [i['name'] for i in item.data['objects'] if port == i['port']]
        if len(getlist) > 0:
            return getlist[0]
        else:
            obj = create_service_object(session, service)
            if obj is not None:
                return obj    
            
def check_time_object(session, date):
    get_all_times = session.gen_api_query("show-times", details_level="full")
    for item in get_all_times:
        getlist = [i['name'] for i in item.data['objects'] if date in i['end']['iso-8601'] and i['start-now'] == True]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_time_object(session, date)
        if obj is not None:
            return obj

def main():
    client_args = APIClientArgs(server=dc_smc_server)
    with APIClient(client_args) as session:
        if session.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)
        login_res = session.login(username, password)
        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)
        smc_server = str()
        get_list_task_result = get_list_task(icms_username, icms_password)
        if get_list_task_result['status'] == 'success':
            datalist = get_list_task_result['datalist']
            if datalist != []:
                for item in datalist:
                    policy_id = item[0]
                    site = item[1]
                    policy = item[2]
                    description = item[3]
                    source = item[4]
                    destination = item[5]
                    service = item[6]
                    schedule = item[7]
                    if site == 'SMC-DC':
                        smc_server = dc_smc_server
                    else:
                        smc_server = dr_smc_server
                    layer = f'{policy} Network'
                    for item in source:
                        if is_ipaddress(item) and item != 'any':
                            obj = check_host_object(session, item)
                            get_index = source.index(item)
                            source[get_index] = obj
                        elif is_subnet(item) and item != 'any':
                            obj = check_network_object(session, item)
                            get_index = source.index(item)
                            source[get_index] = obj
                        elif is_domain(item) and item != 'any':
                            obj = create_domain_object(session, item)
                            get_index = source.index(item)
                            source[get_index] = obj
                        elif item == 'any':
                            source = ['Any']
                        time.sleep(1)
                    for item in destination: 
                        if is_ipaddress(item) and item != 'any':
                            obj = check_host_object(session, item)
                            get_index = destination.index(item)
                            destination[get_index] = obj
                        elif is_subnet(item) and item != 'any':
                            obj = check_network_object(session, item)
                            get_index = destination.index(item)
                            destination[get_index] = obj
                        elif is_domain(item) and item != 'any':
                            obj = check_domain_object(session, item)
                            get_index = destination.index(item)
                            destination[get_index] = obj
                        elif 'any' in item:
                            destination = ['Any']
                        time.sleep(1)
                    for item in service:
                        if item != 'any':
                            obj = check_service_object(session, item)
                            get_index = service.index(item)
                            service[get_index] = obj
                        else:
                            service = ['Any']
                        time.sleep(1)
                    
                    if schedule != "":
                        obj = check_time_object(session, schedule)
                        if obj is not None:
                            schedule = obj 
                        
                    rule_data = {
                        "name": description,
                        "position": {
                            "top": "AUTO_CREATE_RULE"
                        },
                        "action": "Accept",
                        "destination": destination,
                        "source": source,
                        "layer": layer,
                        "service": service,
                        "time": schedule
                    }
                    print(rule_data)
                    add_access_rule = session.api_call('add-access-rule', rule_data)
                    if add_access_rule.success:
                        print('Create access rule success')
                        publish_res = session.api_call("publish", {})
                        if publish_res.success:
                            print("The changes were published successfully.")
                            install_policy = client.api_call("install-policy", {"policy-package": policy})
                            if install_policy.success:
                                print('Instaill policy success')
                            else:
                                print('Install policy failed: ', install_policy.error_message)
                        else:
                            print("Failed to publish the changes")
                    else:
                        error = add_access_rule.error_message
                        print(f'Create access rule failed - error: {error}')
                        
if __name__ == "__main__":
    main()