from __future__ import print_function
from ipaddress import ip_network, IPv4Address
from requests.auth import HTTPBasicAuth
import sys, os, re, requests, json
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from cpapi import APIClient, APIClientArgs


smc_server = ''
username = 'admin'
password = 'Minhduan@123'
icms_username = 'admin'
icms_password = 'admin@123'
icms_url = 'http://127.0.0.8:8000/'

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
    
def get_list_task():
    api = 'api/cm/checkpoint/get-list-task'
    url = icms_url + api
    res = requests.get(url=url, auth=HTTPBasicAuth(icms_username, icms_password))
    if res.ok:
        datalist = json.loads(res.text)['datalist']
        return {'status': 'success', 'datalist': datalist}
    else:
        return {'status': 'failed', 'message': res.text}


    
def main():
    client_args = APIClientArgs(server=smc_server)
    with APIClient(client_args) as client:
        rule_name = input("Enter the name of the access rule: ")
        if client.check_fingerprint() is False:
            print("Could not get the server's fingerprint - Check connectivity with the server.")
            exit(1)
        login_res = client.login(username, password)
        if login_res.success is False:
            print("Login failed:\n{}".format(login_res.error_message))
            exit(1)
        data = {}
        add_rule_response = client.api_call("add-access-rule", data)
        if add_rule_response.success:
            print("The rule: '{}' has been added successfully".format(rule_name))
            publish_res = client.api_call("publish", {})
            if publish_res.success:
                print("The changes were published successfully.")
                install_policy = client.api_call("install-policy", {"policy-package": "POLICY_01"})
                if install_policy.success:
                    print('Instaill policy success')
                else:
                    print('Install policy failed: ', install_policy.error_message)
            else:
                print("Failed to publish the changes.")
        else:
            print("Failed to add the access-rule: '{}', Error:\n{}".format(rule_name, add_rule_response.error_message))

if __name__ == "__main__":
    main()
