import requests
import json

base_url = ''
username = ''
password = ''

def get_login_token(base_url, username, password):
    api = ''
    url = base_url + api
    headers = {
        'Content'
    }
    data = {
        'user': username,
        'password': password
    }
    data = json.dumps(data)
    r = requests.post(url=url, data=data,headers=)