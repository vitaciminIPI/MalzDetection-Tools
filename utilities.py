import re
import requests
import json
import hashlib
import sys
from datetime import datetime
import os
import vol2 as v
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
                        if mal >= 10:
                            print("--- scanner malware classification ---")
                            print("//--> [*] Suggested threat label : " + str(json_resp['data']['attributes']['popular_threat_classification']['suggested_threat_label']))
                            threatCategory = list(json_resp['data']['attributes']['popular_threat_classification']['popular_threat_category'])
                            malType = (str(json_resp['data']['attributes']['popular_threat_classification']['suggested_threat_label']))

                            for category in threatCategory:
                                print("//--> [*] Category : " + category["value"])
                                print("//--> [*] Count : " + str(category["count"]))
                            
                            return True, malType
                        return True, None
                    return False, None
                else:
                    print("\\--> [!] Error")
                    print(json_resp['error']['message'])
                    return False, None

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

    def addressCheck(self, clientAPI, address):
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{address}"
            header = {
                "x-apikey" : clientAPI
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

    def checkNetwork(self, netscan, clientAPI):
        try:
            temp = netscan["ForeignAddr"]
            filteredIp = []
            
            print("[+] Filtering IP Address")
            
            ipv6_regex = re.compile("^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
            
            for addr in temp:
                if addr == '*' or addr == '0.0.0.0' or addr == '::' or ipv6_regex.match(addr) or addr == '127.0.0.1':
                    continue
                else:
                    if self.isValidIPv4(addr):
                        filteredIp.append(addr)

            if filteredIp:
                lenOfFilteredIp = len(filteredIp)
                maliciousIp = []

                print("[+] Checking IP Address status")
                uniqueIp = list(set(filteredIp))

                for ip in uniqueIp:
                    if lenOfFilteredIp >= 5:
                        sleep(16)

                    status = self.addressCheck(clientAPI, ip)
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

    def checkHiddenProc(self, psscan):
        try:
            exitTime = psscan['ExitTime']
            idxExits = []

            for idx, time in enumerate(exitTime):
                if time != 'N/A':
                    idxExits.append(idx)

            ppidExits = [psscan['PPID'][idx] for idx in idxExits]
            ppidFound = list(set(ppidExits))
            
            return ppidFound
        except Exception as e:
            print(f"[!] Error : {e}")

    def checkProcDup(self, pslist):
        try:
            procList = pslist["ImageFileName"]
            dup = []
            indcs = []

            for idx, element in enumerate(procList):
                if procList.count(element) > 1:
                    if element not in dup:
                        dup.append(element)
                        indcs.append([idx])
                    else:
                        indcs[dup.index(element)].append(idx)
            
            return dup, indcs

        except Exception as e:
            print(f"[!] Error : {e}")

    def checkInjectCode(self, malfind):
        try:
            pidInjectedCode = malfind['PID']
            uniquePid = list(set(pidInjectedCode))

            return uniquePid
        except Exception as e:
            print(e)

    def createDirs(self, outputpath, mode):
        currentDate= datetime.now()
        formattedDate = currentDate.strftime("%Y-%d-%m-%H%M%S")
        dirname =  mode + "-" + "Dump-" + formattedDate
        newdirpath = os.path.join(outputpath, dirname)
        os.mkdir(newdirpath)
        return newdirpath

    def getChild(self, pslist, pid):
        ppidlist = pslist['PPID']

        idxPid = []
        print(ppidlist)
        for idx, ppid in enumerate(ppidlist):
            # print(pid)
            if ppid == pid:
                idxPid.append(idx)

        return idxPid

    # Cari pid bermasalahnya saja
    # sisanya sperti nyari anchestor dan child di masing" class 
    def entry(self, filepath, outputpath, clientAPI):
        entryData = {
            "is_network" : False,
            "is_spoof" : False,
            "is_hidden_proc" : False,
            "is_injected_code" : False,
            "pid" : [],
            "process_name" : [],
            "exe_name" : [],
            "malware_types" : []
        }

        print("[!] Checking Entry")
        print("[!] Checking in network connection")

        netscan = v.run("windows.netscan.NetScan", filepath, outputpath, []).copy()
        pidOfNet = netscan['PID']
        maliciousIp = self.checkNetwork(netscan, clientAPI)

        if maliciousIp:
            entryData['is_network'] = True
            entryData["ipv4"] = maliciousIp
            foreignAddr = netscan['ForeignAddr']
            idxIp = [foreignAddr.index(addr) for addr in foreignAddr if addr in maliciousIp]
            
            maliciousPid = [pidOfNet[idx] for idx in idxIp]
            uniquePid = list(set(maliciousPid))
            entryData['pid'] = uniquePid

            return entryData
        
        else: # Check proc spoofing
            pslist = v.run("windows.pslist.PsList", filepath, outputpath, []).copy()
            dup, indcs = self.checkProcDup(pslist)
            anchestorindcs = []
            malsPid = []

            if dup:
                anchestorindcs = indcs
                pidOfSpoof = []

                for i, _ in enumerate(dup):
                    for idx, idxOfPid in enumerate(indcs[i]):
                        anchestorPid = pslist['PPID'][idxOfPid]
                        anchestorindcs[i][idx] = anchestorPid

                for indx, process in enumerate(dup):
                    uniqueList = set(anchestorindcs[indx])
                    sizeListUnique  = len(uniqueList)
                    
                    if process == "csrss.exe" or process == "System" or process == "wininit.exe" or process == "winlogon.exe" or process == "explorer.exe":
                        for pid in anchestorindcs[indx]:
                            if pid in pslist['PID']:
                                ppidIdx = pslist["PID"].index(pid)
                                ppid = pslist["PPID"][ppidIdx] 
                                if ppid in pslist["PID"]:
                                    if indx not in pidOfSpoof:
                                        pidOfSpoof.append(pid)
                    else:
                        if sizeListUnique >= 2:
                            for pid in anchestorindcs[indx]:
                                pidOfSpoof.append(pid)
                        elif sizeListUnique == 1:
                            continue
                        else:
                            print("[!] Error : Somethings wrong")

                newdirpath = self.createDirs(outputpath, "Exe")

                # dump
                for pid in pidOfSpoof:
                    print(f"Dumping pid {pid}")
                    v.run("windows.pslist.PsList", self.filepath, newdirpath, [None, pid, True])

                folder_path = newdirpath
                file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                print("[+] Checking file to virus total")
    
                for file_name in os.listdir(folder_path):
                    file_path = os.path.join(folder_path, file_name)
                    if os.path.isfile(file_path):
                        for pid in pidOfSpoof:
                            pidstr = str(pid)
                            if pidstr in file_name:
                                if file_count >= 5:
                                    sleep(15)
        
                                if not file_name.startswith("."):
                                    file_hash = self.getFileHash(file_path)
                                    
                                    print(f"\-->[*] File Name : {file_name} ")
                                    ismals, typeMals = self.checksumVT(clientAPI, file_hash)
                                    
                                    if ismals:
                                        malsPid.append(pid)
                                        idx = pslist["PID"].index(pid)
                                        procname = pslist["ImageFileName"][idx]
                                        entryData["process_name"].append(procname)
                                        entryData["pid"].append(pid)
                                        entryData["exe_name"].append(file_name)
                                        entryData["malware_types"].append(typeMals)
                
                if malsPid:
                    entryData['is_spoof'] = True
                    
                    return entryData
                else: # Check hidden proc
                    file_list = os.listdir(newdirpath)
                    hidMals = []

                    # apus hasil dump yang bukan indikasi
                    for file_name in file_list:
                        file_path = os.path.join(newdirpath, file_name)
                        if os.path.isfile(file_path):
                            os.remove(file_path)

                    psscan = v.run("windows.psscan.PsScan", filepath, outputpath, [])
                    hiddenProc = self.checkHiddenProc(psscan)
                    
                    if hiddenProc:
                        # dump process
                        for pid in hiddenProc:
                            v.run("windows.pslist.PsList", filepath, newdirpath, [None, pid, True])

                        # cek vt
                        for file_name in os.listdir(newdirpath):
                            file_path = os.path.join(newdirpath, file_name)
                            if os.path.isfile(file_path):
                                for pid in hiddenProc:
                                    pidstr = str(pid)
                                    if pidstr in file_name:
                                        if file_count >= 5:
                                            sleep(15)
                
                                        if not file_name.startswith("."):
                                            file_hash = self.getFileHash(file_path)
                                            
                                            print(f"\-->[*] File Name : {file_name} ")
                                            ismals, typeMals = self.checksumVT(clientAPI, file_hash)
                                            
                                            if ismals:
                                                hidMals.append(pid)
                                                idx = pslist["PID"].index(pid)
                                                procname = pslist["ImageFileName"][idx]
                                                entryData["process_name"].append(procname)
                                                entryData["pid"].append(pid)
                                                entryData["exe_name"].append(file_name)
                                                entryData["malware_types"].append(typeMals)
                        
                        if hidMals:
                            entryData['is_hidden_proc'] = True

                            return entryData
                        
                        else: # Check injected Code
                            injectedMals = []
                            malfind = v.run("windows.malfind.Malfind", filepath, outputpath, []).copy()
                            susPid = self.checkInjectCode(malfind)
                            
                            newdirpath = self.createDirs(outputpath, "Exe")

                            for pid in uniquePid:
                                v.run("windows.pslist.PsList", filepath, newdirpath, [None, pid, True])
                            
                            folder_path = newdirpath
                            file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])                

                            for file_name in os.listdir(newdirpath):
                                file_path = os.path.join(newdirpath, file_name)
                                if os.path.isfile(file_path):
                                    for pid in susPid:
                                        pidstr = str(pid)
                                        if pidstr in file_name:
                                            if file_count >= 5:
                                                sleep(15)

                                            if not file_name.startswith("."):
                                                file_hash = self.getFileHash(file_path)
                                                
                                                print(f"\-->[*] File Name : {file_name} ")
                                                ismals, typeMals = self.checksumVT(clientAPI, file_hash)
                                                
                                                if ismals:
                                                    injectedMals.append(pid)
                                                    idx = pslist["PID"].index(pid)
                                                    procname = pslist["ImageFileName"][idx]
                                                    entryData["process_name"].append(procname)
                                                    entryData["pid"].append(pid)
                                                    entryData["exe_name"].append(file_name)
                                                    entryData["malware_types"].append(typeMals)
                                
                                if injectedMals:
                                    entryData['is_injected_code'] = True
                                    
                                    return entryData
                                else:
                                    file_list = os.listdir(newdirpath)
                                    for file_name in file_list:
                                        file_path = os.path.join(newdirpath, file_name)
                                        if os.path.isfile(file_path):
                                            os.remove(file_path)

                                    print("[!] Nothing suspicious")
                                    return None