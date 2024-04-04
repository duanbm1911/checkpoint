from __future__ import print_function
from ipaddress import ip_network, IPv4Address
from requests.auth import HTTPBasicAuth
from cpapi.mgmt_api import APIClient, APIClientArgs
import sys
import os
import re
import requests
import json
import time
import argparse
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


parser = argparse.ArgumentParser()
parser.add_argument("username")
parser.add_argument("password")
parser.add_argument("icms_user")
parser.add_argument("icms_pass")
args = parser.parse_args()
username = args.username
password = args.password
icms_username = args.icms_user
icms_password = args.icms_pass

icms_url = 'https://icms.vpbank.com.vn/'
# icms_url = 'http://127.0.0.1:8000/'


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

def create_host_object(session, host, list_errors):
    name = f'IP_{host}'
    data = {
        'name': name,
        'ipv4-address': host
    }
    add_host_result = session.api_call("add-host", data)
    if add_host_result.success:
        return name
    else:
        list_errors.append(add_host_result.error_message)
    
def create_network_object(session, subnet, prefix_len, list_errors):
    name = f'NET_{subnet}/{prefix_len}'
    data = {
        'name': name,
        'subnet4': subnet,
        'mask-length4': int(prefix_len)
    }
    add_subnet_result = session.api_call("add-network", data)
    if add_subnet_result.success:
        return name
    else:
        list_errors.append(add_subnet_result.error_message)
    
def create_domain_object(session, domain, list_errors):
    data = {
        'name': domain,
        'is-sub-domain' : False
    }
    add_domain_result = session.api_call("add-dns-domain", data)
    if add_domain_result.success:
        return domain
    else:
        list_errors.append(add_domain_result.error_message)
    
def create_time_object(session, date, list_errors):
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
    else:
        list_errors.append(add_time_result.error_message)
    
def create_service_object(session, service, list_errors):
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
            list_errors.append(add_service_result.error_message)
    else:
        add_service_result = session.api_call("add-service-udp", data)
        if add_service_result.success:
            return service
        else:
            list_errors.append(add_service_result.error_message)

def get_list_task(icms_username, icms_password):
    try:
        api = 'api/cm/checkpoint/get-list-task'
        url = icms_url + api
        res = requests.get(url=url, auth=HTTPBasicAuth(icms_username, icms_password))
        if res.ok:
            data = json.loads(res.text)['data']
            return {'status': 'success', 'data': data}
        else:
            return {'status': 'failed', 'message': res.text}
    except Exception as error:
        return {'status': 'failed', 'message': error}

def update_task_status(icms_url, icms_username, icms_password, rule_id, status, message):
    try:
        api = 'api/cm/checkpoint/update-task-status'
        url = icms_url + api
        data = {
            'rule_id': rule_id,
            'status': status,
            'message': message
        }
        res = requests.post(url=url, data=data, auth=HTTPBasicAuth(icms_username, icms_password), verify=False)
        if res.ok:
            return {'status': 'success'}
        else:
            return {'status': 'failed', 'message': res.text}
    except Exception as error:
        return {'status': 'failed', 'message': error}
    
def check_host_object(session, host, list_errors):
    obj = str()
    get_all_hosts = session.gen_api_query("show-hosts", details_level="full")
    for item in get_all_hosts:
        getlist = [i['name'] for i in item.data['objects'] if host == i['ipv4-address']]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_host_object(session, host, list_errors)
        if obj is not None:
            return obj
    
def check_network_object(session, network, list_errors):
    subnet = network.split('/')[0]
    prefix_len = network.split('/')[1]
    get_all_networks = session.gen_api_query("show-networks", details_level="full")
    for item in get_all_networks:
        getlist = [i['name'] for i in item.data['objects'] if i.get('subnet4') is not None and subnet == i['subnet4'] and int(prefix_len) == i['mask-length4']]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_network_object(session, subnet, prefix_len, list_errors)
        if obj is not None:
            return obj

def check_domain_object(session, domain, list_errors):
    get_all_domains = session.gen_api_query("show-dns-domains", details_level="full")
    for item in get_all_domains:
        getlist = [i['name'] for i in item.data['objects'] if domain.lower() == i['name'].lower()]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_domain_object(session, domain, list_errors)
        if obj is not None:
            return obj

def check_service_object(session, service, list_errors):
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
            obj = create_service_object(session, service, list_errors)
            if obj is not None:
                return obj
    else:
        get_all_services = session.gen_api_query("show-services-udp", details_level="full")
        for item in get_all_services:
            getlist = [i['name'] for i in item.data['objects'] if port == i['port']]
        if len(getlist) > 0:
            return getlist[0]
        else:
            obj = create_service_object(session, service, list_errors)
            if obj is not None:
                return obj    
            
def check_time_object(session, date, list_errors):
    get_all_times = session.gen_api_query("show-times", details_level="full")
    for item in get_all_times:
        getlist = [i['name'] for i in item.data['objects'] if date in i['end']['iso-8601'] and i['start-now'] == True]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_time_object(session, date, list_errors)
        if obj is not None:
            return obj

def main():
    get_list_task_result = get_list_task(icms_username, icms_password)
    if get_list_task_result['status'] == 'success':
        data = get_list_task_result['data']
        for site, item in data.items():
            smc_server = item['smc']
            layer = item['layer']
            section = item['section']
            rules = item['rules']
            list_policy = list()
            list_result = list()
            list_policy_install_failed = list()
            if rules:
                client_args = APIClientArgs(server=smc_server)
                with APIClient(client_args) as session:
                    for item in rules:
                        rule_id = item[0]
                        policy = item[1]
                        description = item[2]
                        source = item[3]
                        destination = item[4]
                        service = item[5]
                        schedule = item[6]
                        policy_layer = f'{policy} {layer}'
                        list_errors = list()
                        update_task_status_result = update_task_status(
                            icms_username=icms_username,
                            icms_password=icms_password,
                            icms_url=icms_url,
                            rule_id=rule_id,
                            status='Processing',
                            message=''
                        )
                        if update_task_status_result['status'] == 'failed':
                            list_errors.append("Update task status: Processing to ICMS failed")
                        if session.check_fingerprint() is False:
                            list_errors.append("Check connectivity with the server")
                        else:
                            login_res = session.login(username, password)
                            if login_res.success is False:
                                list_errors.append(login_res.error_message)
                            else:
                                for item in source:
                                    if is_ipaddress(item) and item != 'any':
                                        obj = check_host_object(session=session, host=item, list_errors=list_errors)
                                        get_index = source.index(item)
                                        source[get_index] = obj
                                    elif is_subnet(item) and item != 'any':
                                        obj = check_network_object(session=session, network=item, list_errors=list_errors)
                                        get_index = source.index(item)
                                        source[get_index] = obj
                                    elif is_domain(item) and item != 'any':
                                        obj = check_domain_object(session=session, domain=f'.{item}', list_errors=list_errors)
                                        get_index = source.index(item)
                                        source[get_index] = obj
                                    elif item == 'any':
                                        source = ['Any']
                                    time.sleep(1)
                                for item in destination: 
                                    if is_ipaddress(item) and item != 'any':
                                        obj = check_host_object(session=session, host=item, list_errors=list_errors)
                                        get_index = destination.index(item)
                                        destination[get_index] = obj
                                    elif is_subnet(item) and item != 'any':
                                        obj = check_network_object(session=session, network=item, list_errors=list_errors)
                                        get_index = destination.index(item)
                                        destination[get_index] = obj
                                    elif is_domain(item) and item != 'any':
                                        obj = check_domain_object(session=session, domain=f'.{item}', list_errors=list_errors)
                                        get_index = destination.index(item)
                                        destination[get_index] = obj
                                    elif 'any' in item:
                                        destination = ['Any']
                                    time.sleep(1)
                                for item in service:
                                    if item != 'any':
                                        obj = check_service_object(session=session, service=item, list_errors=list_errors)
                                        get_index = service.index(item)
                                        service[get_index] = obj
                                    else:
                                        service = ['Any']
                                    time.sleep(1)
                                if schedule != "":
                                    obj = check_time_object(session=session, date=schedule, list_errors=list_errors)
                                    if obj is not None:
                                        schedule = obj
                                rule_data = {
                                    "name": description,
                                    "position": {
                                        "top": section
                                    },
                                    "action": "Accept",
                                    "destination": destination,
                                    "source": source,
                                    "layer": policy_layer,
                                    "service": service,
                                    "track": {
                                        "type": "log"
                                    }
                                }
                                if schedule:
                                    rule_data['time'] = schedule
                            if not list_errors:
                                add_access_rule = session.api_call('add-access-rule', rule_data)
                                if add_access_rule.success:
                                    publish_res = session.api_call("publish", {})
                                    if publish_res.success:
                                        list_policy.append(policy)
                                        list_result.append([rule_id, policy, 'Success', ''])
                                    else:
                                        error = publish_res.error_message
                                        list_result.append([rule_id, policy, 'Failed', f'Publish object failed - error: {error}'])
                                else:
                                    request_discard = session.api_call('discard', {})
                                    discard_error_message = str()
                                    if not request_discard.success:
                                        discard_error_message = request_discard.error_message
                                    error = add_access_rule.error_message
                                    if discard_error_message:
                                        list_result.append([rule_id, policy, 'Failed', f'Create rule failed - error: {error}\nDiscard failed error: {discard_error_message}'])
                                    else:
                                        list_result.append([rule_id, policy, 'Failed', f'Create rule failed - error: {error}'])
                            else:
                                list_result.append([rule_id, policy, 'Failed', list_errors])
                    for policy in set(list_policy):
                        install_policy = session.api_call("install-policy", {"policy-package": policy})
                        if install_policy.success:
                            print(f'Instaill policy: {policy} success')
                        else:
                            list_policy_install_failed.append(policy)
                            error = install_policy.error_message
                            print(f'\nInstall policy: {policy} failed - error: {error}')
            for item in list_result:
                rule_id = item[0]
                policy = item[1]
                status = item[2]
                message = item[3]
                if policy in list_policy_install_failed:
                    status = 'Failed'
                    message += f'Install policy: {policy} failed'
                update_task_status_result = update_task_status(
                    icms_username=icms_username,
                    icms_password=icms_password,
                    icms_url=icms_url,
                    rule_id=rule_id,
                    status=status,
                    message=message
                )
                if update_task_status_result['status'] == 'success':
                    print('Update to ICMS success')
                else:
                    error = update_task_status_result['message']
                    print(f'Update to ICMS failed- error: {error}')
    else:
        error = get_list_task_result['message']
        print(f'Get list task form ICMS failed - error: {error}')
                        
if __name__ == "__main__":
    main()