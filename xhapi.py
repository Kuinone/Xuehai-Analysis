import requests
import hashlib
import time
import json

def sign(method, url, request_body=None, auth_header=None):
    signature_key="eptim]q34imt5b]-q04i5q=fdkfjfsadlkjfasdfrt573df4pltoy]-pn965498d"
    timestamp = str(int(time.time() * 1000))
    raw_sign_string = f"{method}{url}{timestamp}{signature_key}"
    if method not in ["GET", "DELETE"] and request_body and len(request_body.encode('utf-8')) < 1048576:
        raw_sign_string += request_body
    if auth_header:
        raw_sign_string += f"Authorization: {auth_header}"
    sign = hashlib.md5(raw_sign_string.encode('utf-8')).hexdigest()
    if "?" in url:
        final_url = f"{url}&sign={sign}&t={timestamp}"
    else:
        final_url = f"{url}?sign={sign}&t={timestamp}"
    return final_url
def xrequest(method, url, payload_dict, extra_headers=None, auth=None, device_id="R52TA0K08HJ"):
    user_agent = f"com.xh.zhitongyunstu/v3.125.04.20251125S (SM-P200; android; 9; {device_id})"
    url = "https://zty.yunzuoye.net/api" + url
    headers = {
        "Content-Type": "application/json",
        "Accept": "*/*",
        "User-Agent": user_agent
    }
    for key, value in extra_headers.items():
        headers[key] = value
    if auth is not None:
        headers["Authorization"] = f"Bearer {auth}"
    payload_data = json.dumps(payload_dict, separators=(',', ':'))
    final_url = sign(method, url, request_body=payload_data, auth_header=auth)
    if method == "GET":
        res = requests.get(final_url, headers=headers)
    elif method == "DELETE":
        res = requests.delete(final_url, headers=headers)
    elif method == "PATCH":
        res = requests.patch(final_url, headers=headers, data=payload_data)
    elif method == "POST":
        res = requests.post(final_url, headers=headers, data=payload_data)
    return res
