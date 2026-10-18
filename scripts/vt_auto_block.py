import json
import sys
import os
import requests
import subprocess

def check_vt_ip(ip_address,api_key):
    url=f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"

    headers={
        "x-apikey":api_key
    }
    try:
        response=requests.get(url,headers=headers, timeout=5)
        if response.status_code==200:
            data=response.json()
            malicious_count=data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            return malicious_count
        else:
            print(f"[ERROR] API responded with a status code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Connection error with VirusTotal {e}")
        return None


def block_ip(ip_address,malicious_count):
    if  malicious_count is not None and malicious_count > 3:
        print(f"[DANGER] IP {ip_address} identified as malicious ({malicious_count} detections). Initiating block ...")
        rule_name = f"SOC_Block_Malicious_IP_{ip_address}"
        command = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip_address}"
        ]
        result=subprocess.run(command, capture_output=True,text=True )
        if result.returncode==0:
            print(f"[SUCCESS] The address {ip_address} has been blocked in the firewall!")
        else:
            print(f"[ERROR] Failed to block IP. Error: {result.stderr}")
    else:
        print(f"[CLEAN] IP {ip_address} is safe, {malicious_count} detections")


def send_to_webhook_malicious_ip(event,url):
    ip_addr = event.get("src_ip", "Unknown")
    try:
        requests.post(url,json=event,timeout=5)
        print(f"[INFO] Information about the blocking of IP address {ip_addr} has been sent to the webhook")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Failed to send data to the webhook: {e}")


def extracting_ip_addresses_and_block(input_file,webhook):
    try:
        with open(input_file,"r",encoding="utf-8") as f:
            events=json.load(f)
    except Exception as e:
        print(f"[ERROR] Couldn't open JSON file: {e}")
        sys.exit(1)
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("[ERROR] API key missing. Set the VT_API_KEY environment variable before running the script.")
        sys.exit(1)
    for event in events:
        ip_addr = event.get("src_ip","Unknown")
        if not ip_addr.startswith(("10.","192.168.","172.16.")):
            malicious_count=check_vt_ip(ip_addr,api_key)
            block_ip(ip_addr,malicious_count)
            if malicious_count is not None and malicious_count>3:
                send_to_webhook_malicious_ip(event,webhook)
        else:
            print(f"Skipping VT check for private IP: {ip_addr}")

if len(sys.argv)<3:
    print("Usage: python vt_auto_block.py <path_to_json_file> <webhook_url>")
    sys.exit(1)

extracting_ip_addresses_and_block(sys.argv[1], sys.argv[2])



