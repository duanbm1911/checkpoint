from requests.auth import HTTPBasicAuth
from cpapi.mgmt_api import APIClient, APIClientArgs
import requests
import json
import argparse

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


def get_list_site():
    try:
        api = "api/cm/checkpoint/site"
        url = icms_url + api
        res = requests.get(url=url, auth=HTTPBasicAuth(icms_username, icms_password))
        if res.ok:
            datalist = json.loads(res.text)["datalist"]
            return {"status": "success", "datalist": datalist}
        else:
            return {"status": "failed", "message": res.text}
    except Exception as error:
        return {"status": "failed", "message": error}


def update_rule_section(datalist):
    try:
        api = "api/cm/checkpoint/update/rule-section"
        url = icms_url + api
        res = requests.post(
            url=url,
            json=datalist,
            auth=HTTPBasicAuth(icms_username, icms_password),
            verify=False,
        )
        if res.ok:
            return {"status": "success"}
        else:
            return {"status": "failed", "message": res.text}
    except Exception as error:
        return {"status": "failed", "message": error}


def main():
    list_policy = list()
    results = {}
    get_list_site_result = get_list_site()
    if get_list_site_result["status"] == "success":
        datalist = get_list_site_result["datalist"]
        for item in datalist:
            smc_server = item["smc"]
            list_policy = item["policy"]
            client_args = APIClientArgs(server=smc_server)
            with APIClient(client_args) as session:
                login = session.login(username, password)
                if login.success:
                    for policy in list_policy:
                        data = {"name": f"{policy} Network"}
                        rule_bases = session.gen_api_query(
                            "show-access-rulebase",
                            payload=data,
                            container_keys="rulebase",
                        )
                        for rule in rule_bases:
                            if rule.data.get("rulebase") is not None:
                                results[policy] = [
                                    i["name"]
                                    for i in rule.data["rulebase"]
                                    if i.get("name") is not None
                                ]
                else:
                    error = login.error_message
                    print(f"Login to SMC: {smc_server} failed - error: {error}")
        update_rule_section_result = update_rule_section(datalist=results)
        if update_rule_section_result["status"] == "success":
            print("Update list section to ICMS success")
        else:
            error = update_rule_section_result["error"]
            print(f"Update list section to ICMS failed - error: {error}")
    else:
        error = get_list_site_result["error"]
        print(f"Get list site from ICMS failed - error: {error}")


if __name__ == "__main__":
    main()
