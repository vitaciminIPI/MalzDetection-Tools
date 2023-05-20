import re
import requests
import json
import hashlib
import sys
from time import sleep

class UtilitiesMalz:
    def isValidIPv4(self, ip_str):
        # check apakah string berformat ipv4
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        if re.match(pattern, ip_str):
            return True
        else:
            return False

    def findAnchestor(self, pslist, pid):
        pidlist = pslist["PID"]
        ppidlist = pslist["PPID"]
        pidTemp = pid
        anchestor = 0
        
        while True:
            pidIdx = pidlist.index(pidTemp)
            ppid = ppidlist[pidIdx]
            if ppid not in pidlist:
                anchestor = pidlist[pidIdx]
                break 
            pidTemp = ppid

        return anchestor

    def checksumVT(self, clientAPI, fileHash):
        if clientAPI:
            try:
                print("\\-->[*] SHA256 SUM : " + fileHash)
                url = "https://www.virustotal.com/api/v3/files/" + fileHash
                headers = {
                    'x-apikey' : clientAPI
                }
                response = requests.get(url, headers=headers)
                responseCode = response.status_code
                json_resp = json.loads(response.text)

                if responseCode == 200:
                    print("")
                    print("")
                    print("")
                    
                    print("--- scanner analysis status ---")
                    print("//--> [*] Malicious : " + str(json_resp['data']['attributes']['last_analysis_stats']['malicious']) + " %")
                    print("//--> [*] Harmless : " + str(json_resp['data']['attributes']['last_analysis_stats']['harmless']) + " %")
                    print("//--> [*] Undetected : " + str(json_resp['data']['attributes']['last_analysis_stats']['undetected']) + " %")
                    print("//--> [*] Suspicious : " + str(json_resp['data']['attributes']['last_analysis_stats']['suspicious']) + " %")
                    print("//--> [*] Failure : " + str(json_resp['data']['attributes']['last_analysis_stats']['failure']) + " %")
                    print("//--> [*] Timeout : " + str(json_resp['data']['attributes']['last_analysis_stats']['timeout']) + " %")
                    print("//--> [*] Confirmed-Timeout : " + str(json_resp['data']['attributes']['last_analysis_stats']['confirmed-timeout']) + " %")
                    print("//--> [*] Type-Unsupported : " + str(json_resp['data']['attributes']['last_analysis_stats']['type-unsupported']) + " %")

                    print("")
                    print("")
                    print("")

                    mal = json_resp['data']['attributes']['last_analysis_stats']['malicious']
                    
                    if mal != 0:
                        print("--- scanner malware classification ---")
                        print("//--> [*] Suggested threat label : " + str(json_resp['data']['attributes']['popular_threat_classification']['suggested_threat_label']))
                        threatCategory = list(json_resp['data']['attributes']['popular_threat_classification']['popular_threat_category'])
                        malType = (str(json_resp['data']['attributes']['popular_threat_classification']['suggested_threat_label']))

                        for category in threatCategory:
                            print("//--> [*] Category : " + category["value"])
                            print("//--> [*] Count : " + str(category["count"]))
                        
                        return True, malType
                    
                    return False, None

                else:
                    print("\\--> [!] Error")
                    print(json_resp['error']['message'])

            except ConnectionError as e:
                print(f"[!] Error : {e}")
        else:
            print('[!] Error : Invalid ClientAPIKey')
            sys.exit()

    def getFileHash(self, pathFile):
        try:
            with open(pathFile, 'rb') as f:
                data = f.read()
                sha256 = hashlib.sha256(data).hexdigest()
                return sha256
        except FileNotFoundError as e:
            print(e)
            return ""

    def addressCheck(self, address):
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{address}"
            header = {
                "x-apikey" : self.clientAPI
            }
            response = requests.get(url, headers=header)
            responseCode = response.status_code
            json_resp = json.loads(response.text)

            if responseCode == 200:
                return json_resp
            else:
                print(f"[!] Error : {json_resp['error']['message']}")
        except:
            print("[!] Error : connection timeout")

    def checkNetwork(self, netscan):
        try:
            temp = netscan["ForeignAddr"]
            filteredIp = []
            
            print("[+] Filtering IP Address")
            
            # Filter ipv6 menggunakan regex
            ipv6_regex = re.compile("^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
            
            for addr in temp:
                if addr == '*' or addr == '0.0.0.0' or addr == '::' or ipv6_regex.match(addr) or addr == '127.0.0.1':
                    continue
                else:
                    # filteredIp.append(addr)
                    if self.isValidIPv4(addr):
                        filteredIp.append(addr)

            # print(filteredIp)
            # Kalo ada IP
            if filteredIp:
                
                lenOfFilteredIp = len(filteredIp)
                maliciousIp = []

                print("[+] Checking IP Address status")
                uniqueIp = list(set(filteredIp))
                # print(uniqueIp)

                for ip in uniqueIp:
                    if lenOfFilteredIp >= 5: #Biar ga kena rate limit submit public API samples
                        sleep(16)

                    status = self.addressCheck(ip)
                    maliciousInt = status['data']['attributes']['last_analysis_stats']['malicious']
                    harmlessInt = status['data']['attributes']['last_analysis_stats']['harmless']
                    undetectedInt = status['data']['attributes']['last_analysis_stats']['undetected']
                    suspiciousInt = status['data']['attributes']['last_analysis_stats']['suspicious']
                    timeoutInt = status['data']['attributes']['last_analysis_stats']['timeout']

                    print(f"////----> [*] IP Address : {ip}")
                    print("//--> [*] Malicious : " + str(maliciousInt) + " %")
                    print("//--> [*] Harmless : " + str(harmlessInt) + " %")
                    print("//--> [*] Undetected : " + str(undetectedInt) + " %")
                    print("//--> [*] Suspicious : " + str(suspiciousInt) + " %")
                    print("//--> [*] Timeout : " + str(timeoutInt) + " %")

                    if maliciousInt != 0:
                        maliciousIp.append(ip)
                
                return maliciousIp
        except Exception as e:
            print(f"[!] Error : {e}")
