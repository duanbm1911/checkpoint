from ipaddress import ip_network, IPv4Address
from requests.auth import HTTPBasicAuth
from cpapi.mgmt_api import APIClient, APIClientArgs
import re
import requests
import json
import time
import argparse
import threading


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

icms_url = "http://127.0.0.1:8000/"


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


def is_user(user):
    obj = user.split("/")
    if len(obj) == 2 and "user" == obj[0] or "partner" == obj[0]:
        return True
    return False


def create_host_object(session, host, list_errors):
    name = f"IP_{host}"
    data = {"name": name, "ipv4-address": host, "ignore-warnings": True}
    add_host_result = session.api_call("add-host", data)
    if add_host_result.success:
        return name
    else:
        list_errors.append(add_host_result.error_message)


def create_network_object(session, subnet, prefix_len, list_errors):
    name = f"NET_{subnet}/{prefix_len}"
    data = {
        "name": name,
        "subnet4": subnet,
        "mask-length4": int(prefix_len),
        "ignore-warnings": True,
    }
    add_subnet_result = session.api_call("add-network", data)
    if add_subnet_result.success:
        return name
    else:
        list_errors.append(add_subnet_result.error_message)


def create_domain_object(session, domain, list_errors):
    data = {"name": domain, "is-sub-domain": False}
    add_domain_result = session.api_call("add-dns-domain", data)
    if add_domain_result.success:
        return domain
    else:
        list_errors.append(add_domain_result.error_message)


def create_time_object(session, date, list_errors):
    name = date
    end_datetime = f"{date}T23:59:59"
    data = {
        "name": name,
        "end": {"iso-8601": end_datetime},
        "end-never": False,
        "start-now": True,
        "ignore-warnings": True,
    }
    add_time_result = session.api_call("add-time", data)
    if add_time_result.success:
        return name
    else:
        list_errors.append(add_time_result.error_message)


def create_service_object(session, service, list_errors):
    port = str()
    if len(service.split("-")) == 2:
        port = service.split("-")[1]
    else:
        start_port = service.split("-")[1]
        end_port = service.split("-")[2]
        port = f"{start_port}-{end_port}"
    data = {"name": service, "port": port}
    if "tcp" in service:
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


def create_access_role_object(session, user_obj, list_errors):
    ad_domain = user_obj.split("/")[0]
    name = str(user_obj.split("/")[1]).lower()
    data = {"name": name, "users": {"selection": name}}
    if ad_domain == "user":
        data["users"]["source"] = "vpbank.com.vn"
    elif ad_domain == "partner":
        data["users"]["source"] = "vpbank.partner"
    add_access_role_result = session.api_call("add-access-role", data)
    if add_access_role_result.success:
        return name
    else:
        list_errors.append(add_access_role_result.error_message)


def get_list_rule(icms_username, icms_password):
    try:
        api = "api/cm/checkpoint/rule"
        url = icms_url + api
        res = requests.get(url=url, auth=HTTPBasicAuth(icms_username, icms_password))
        if res.ok:
            data = json.loads(res.text)["data"]
            return {"status": "success", "data": data}
        else:
            return {"status": "failed", "message": res.text}
    except Exception as error:
        return {"status": "failed", "message": error}


def update_task_status(icms_url, icms_username, icms_password, rule_id, status, message=""):
    try:
        api = "api/cm/checkpoint/update/rule-status"
        url = icms_url + api
        data = {"rule_id": rule_id, "status": status, "message": message}
        res = requests.post(
            url=url,
            data=data,
            auth=HTTPBasicAuth(icms_username, icms_password),
            verify=False,
        )
        if res.ok:
            return {"status": "success"}
        else:
            return {"status": "failed", "message": res.text}
    except Exception as error:
        return {"status": "failed", "message": error}


def check_host_object(session, host, list_errors):
    obj = str()
    data = {"filter": host}
    get_all_hosts = session.gen_api_query("show-hosts", details_level="full", payload=data)
    for item in get_all_hosts:
        getlist = [i["name"] for i in item.data["objects"] if host == i["ipv4-address"]]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_host_object(session, host, list_errors)
        if obj is not None:
            return obj


def check_network_object(session, network, list_errors):
    subnet = network.split("/")[0]
    prefix_len = network.split("/")[1]
    data = {"filter": subnet}
    get_all_networks = session.gen_api_query("show-networks", details_level="full", payload=data)
    for item in get_all_networks:
        getlist = [
            i["name"]
            for i in item.data["objects"]
            if i.get("subnet4") is not None
            and subnet == i["subnet4"]
            and int(prefix_len) == i["mask-length4"]
        ]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_network_object(session, subnet, prefix_len, list_errors)
        if obj is not None:
            return obj


def check_domain_object(session, domain, list_errors):
    data = {"filter": domain}
    get_all_domains = session.gen_api_query("show-dns-domains", details_level="full", payload=data)
    for item in get_all_domains:
        getlist = [i["name"] for i in item.data["objects"] if domain.lower() == i["name"].lower()]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_domain_object(session, domain, list_errors)
        if obj is not None:
            return obj


def check_service_object(session, service, list_errors):
    port = str()
    if len(service.split("-")) == 2:
        port = service.split("-")[1]
    else:
        start_port = service.split("-")[1]
        end_port = service.split("-")[2]
        port = f"{start_port}-{end_port}"
    if "tcp" in service:
        get_all_services = session.gen_api_query("show-services-tcp", details_level="full")
        for item in get_all_services:
            getlist = [i["name"] for i in item.data["objects"] if port == i["port"]]
        if len(getlist) > 0:
            return getlist[0]
        else:
            obj = create_service_object(session, service, list_errors)
            if obj is not None:
                return obj
    else:
        get_all_services = session.gen_api_query("show-services-udp", details_level="full")
        for item in get_all_services:
            getlist = [i["name"] for i in item.data["objects"] if port == i["port"]]
        if len(getlist) > 0:
            return getlist[0]
        else:
            obj = create_service_object(session, service, list_errors)
            if obj is not None:
                return obj


def check_time_object(session, date, list_errors):
    get_all_times = session.gen_api_query("show-times", details_level="full")
    for item in get_all_times:
        getlist = [
            i["name"]
            for i in item.data["objects"]
            if date in i["end"]["iso-8601"] and i["start-now"] == True
        ]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_time_object(session, date, list_errors)
        if obj is not None:
            return obj


def check_access_role_object(session, user_obj, list_errors):
    user = str(user_obj.split("/")[1]).lower()
    data = {"filter": user}
    get_all_access_roles = session.gen_api_query(
        "show-access-roles", details_level="full", payload=data
    )
    for item in get_all_access_roles:
        getlist = [i["name"] for i in item.data["objects"] if user == str(i["name"]).lower()]
    if len(getlist) > 0:
        return getlist[0]
    else:
        obj = create_access_role_object(session, user_obj, list_errors)
        if obj is not None:
            return obj


def install_policy(session, policy, list_install_failed):
    install_policy = session.api_call("install-policy", {"policy-package": policy})
    if not install_policy.success:
        try:
            error = install_policy.error_message
            list_install_failed.append({"policy": policy, "error": error})
        except:
            list_install_failed.append({"policy": policy, "error": 'An error occurred while installing policy, please choose "Install-Only" to try again'})


def main():
    get_list_rule_result = get_list_rule(icms_username, icms_password)
    if get_list_rule_result["status"] == "success":
        data = get_list_rule_result["data"]
        for site, item in data.items():
            smc_server = item["smc"]
            layer = item["layer"]
            rules = item["rules"]
            list_policy = list()
            list_result = list()
            list_thread = list()
            list_rule_install_failed = list()
            if rules:
                client_args = APIClientArgs(server=smc_server)
                with APIClient(client_args) as session:
                    if session.check_fingerprint() is False:
                        print(f"Connect to SMC: {site}-{smc_server} failed")
                    else:
                        login = session.login(username, password)
                        if not login.success:
                            error = login.error_message
                            print(f"Login to SMC: {site}-{smc_server} failed - error: {error}")
                        else:
                            for item in rules:
                                rule_id = item[0]
                                policy = item[1]
                                gateways = item[2]
                                description = item[3]
                                source = item[4]
                                destination = item[5]
                                service = item[6]
                                schedule = item[7]
                                section = item[8]
                                status = item[9]
                                policy_layer = f"{policy} {layer}"
                                list_errors = list()
                                update_task_status_result = update_task_status(
                                    icms_username=icms_username,
                                    icms_password=icms_password,
                                    icms_url=icms_url,
                                    rule_id=rule_id,
                                    status="Processing",
                                )
                                if update_task_status_result["status"] == "failed":
                                    error = update_task_status_result["message"]
                                    list_errors.append(
                                        "Update rule status to ICMS failed - error: {error}"
                                    )
                                else:
                                    if status == "Created":
                                        for item in source:
                                            if not list_errors:
                                                if is_ipaddress(item) and item != "any":
                                                    obj = check_host_object(
                                                        session=session,
                                                        host=item,
                                                        list_errors=list_errors,
                                                    )
                                                    get_index = source.index(item)
                                                    source[get_index] = obj
                                                elif is_subnet(item) and item != "any":
                                                    obj = check_network_object(
                                                        session=session,
                                                        network=item,
                                                        list_errors=list_errors,
                                                    )
                                                    get_index = source.index(item)
                                                    source[get_index] = obj
                                                elif is_domain(item) and item != "any":
                                                    obj = check_domain_object(
                                                        session=session,
                                                        domain=f".{item}",
                                                        list_errors=list_errors,
                                                    )
                                                    get_index = source.index(item)
                                                    source[get_index] = obj
                                                elif is_user(item) and item != "any":
                                                    obj = check_access_role_object(
                                                        session=session,
                                                        user_obj=item,
                                                        list_errors=list_errors,
                                                    )
                                                    get_index = source.index(item)
                                                    source[get_index] = obj
                                                elif item == "any":
                                                    source = ["Any"]
                                                time.sleep(1)
                                        for item in destination:
                                            if not list_errors:
                                                if is_ipaddress(item) and item != "any":
                                                    obj = check_host_object(
                                                        session=session,
                                                        host=item,
                                                        list_errors=list_errors,
                                                    )
                                                    get_index = destination.index(item)
                                                    destination[get_index] = obj
                                                elif is_subnet(item) and item != "any":
                                                    obj = check_network_object(
                                                        session=session,
                                                        network=item,
                                                        list_errors=list_errors,
                                                    )
                                                    get_index = destination.index(item)
                                                    destination[get_index] = obj
                                                elif is_domain(item) and item != "any":
                                                    obj = check_domain_object(
                                                        session=session,
                                                        domain=f".{item}",
                                                        list_errors=list_errors,
                                                    )
                                                    get_index = destination.index(item)
                                                    destination[get_index] = obj
                                                elif is_user(item) and item != "any":
                                                    obj = check_access_role_object(
                                                        session=session,
                                                        user_obj=item,
                                                        list_errors=list_errors,
                                                    )
                                                    get_index = destination.index(item)
                                                    destination[get_index] = obj
                                                elif "any" in item:
                                                    destination = ["Any"]
                                                time.sleep(1)
                                        for item in service:
                                            if not list_errors:
                                                if item != "any":
                                                    obj = check_service_object(
                                                        session=session,
                                                        service=item,
                                                        list_errors=list_errors,
                                                    )
                                                    get_index = service.index(item)
                                                    service[get_index] = obj
                                                else:
                                                    service = ["Any"]
                                                time.sleep(1)
                                        if schedule != "":
                                            if not list_errors:
                                                obj = check_time_object(
                                                    session=session,
                                                    date=schedule,
                                                    list_errors=list_errors,
                                                )
                                                if obj is not None:
                                                    schedule = obj
                                        if not list_errors:
                                            # init data
                                            rule_data = {
                                                "name": description,
                                                "position": {"top": section},
                                                "action": "Accept",
                                                "destination": destination,
                                                "source": source,
                                                "layer": policy_layer,
                                                "service": service,
                                                "track": {"type": "log"},
                                                "install-on": gateways,
                                                "ignore-errors": True,
                                                "ignore-warnings": True
                                            }
                                            if schedule:
                                                rule_data["time"] = schedule
                                            # create rule
                                            add_access_rule = session.api_call(
                                                "add-access-rule", rule_data
                                            )
                                            if add_access_rule.success:
                                                # publish objects
                                                publish_res = session.api_call("publish", {})
                                                if publish_res.success:
                                                    list_policy.append(policy)
                                                    list_result.append(
                                                        [rule_id, policy, "Success", ""]
                                                    )
                                                else:
                                                    error = publish_res.error_message
                                                    list_result.append(
                                                        [
                                                            rule_id,
                                                            policy,
                                                            "Failed",
                                                            f"Publish object failed - error: {error}",
                                                        ]
                                                    )
                                            else:
                                                request_discard = session.api_call("discard", {})
                                                discard_error_message = str()
                                                if not request_discard.success:
                                                    discard_error_message = (
                                                        request_discard.error_message
                                                    )
                                                error = add_access_rule.error_message
                                                if discard_error_message:
                                                    list_result.append(
                                                        [
                                                            rule_id,
                                                            policy,
                                                            "Failed",
                                                            f"Create rule failed - error: {error}\nDiscard failed: {discard_error_message}",
                                                        ]
                                                    )
                                                else:
                                                    list_result.append(
                                                        [
                                                            rule_id,
                                                            policy,
                                                            "Failed",
                                                            f"Create rule failed - error: {error}",
                                                        ]
                                                    )
                                        else:
                                            list_result.append(
                                                [rule_id, policy, "Failed", list_errors]
                                            )
                                    elif status == "Install-Only":
                                        list_policy.append(policy)
                                        list_result.append([rule_id, policy, "Success", ""])
                            # install policy
                            for policy in set(list_policy):
                                th = threading.Thread(
                                    target=install_policy,
                                    args=(session, policy, list_rule_install_failed),
                                )
                                th.daemon = True
                                th.start()
                                list_thread.append(th)
                                time.sleep(5)
                            for i in range(len(set(list_policy))):
                                list_thread[i].join()
                # update status to icms
                for item in list_result:
                    rule_id = item[0]
                    policy = item[1]
                    status = item[2]
                    message = item[3]
                    for item in list_rule_install_failed:
                        if item.get("policy") is not None and item["policy"] == policy:
                            error = item["error"]
                            status = "Failed"
                            message += f"Install policy: {policy} failed - error: {error}"
                    update_task_status_result = update_task_status(
                        icms_username=icms_username,
                        icms_password=icms_password,
                        icms_url=icms_url,
                        rule_id=rule_id,
                        status=status,
                        message=message,
                    )
                    if update_task_status_result["status"] == "success":
                        print("Update rule status to ICMS success")
                    else:
                        error = update_task_status_result["message"]
                        print(f"Update rule status to ICMS success - error: {error}")
    else:
        error = get_list_rule_result["message"]
        print(f"Get list task form ICMS failed - error: {error}")


if __name__ == "__main__":
    main()
