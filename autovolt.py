import os, json
import vol2
import requests
import re 
import hashlib
import sys
from time import sleep

FILE_PATH = "wanncry.vmem"
REGISTRY_KEY = ["MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE", "CURRENTCONTROLSET\\CONTROL\\HIVELIST", "CONTROLSET002\\CONTROL\\SESSION MANAGER", "CURRENTCONTROLSET\\SERVICES", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNSERVICESONCE", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNSERVICES", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\NOTIFY", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\USERINIT", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\SHELL"]
LEGAL_PROCNAME = ["System", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "svchost.exe", "lsass.exe", "winlogon.exe", "explorer.exe", "taskhostw.exe", "RuntimeBroker.exe"]
IS_SPOOF = False
IS_MALICIOUS = False
OUTPUT_PATH = "./dumped"
MALICIOUS_DATA = {
    "ipv4" : [],
    "pid" : [],
    "sus_pid" : [],
    "hidden_pid" : [],
    "process_name" : [],
    "is_spoof" : False,
    "registry" : [],
    "exe_name" : [],
    "malware_types" : []
}

def isValidIPv4(ip_str):
    # check apakah string berformat ipv4
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    if re.match(pattern, ip_str):
        return True
    else:
        return False

def findAnchestor(pslist, pid):
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

def checksumVT(fileHash):
    global IS_SPOOF, IS_MALICIOUS, MALICIOUS_DATA
    
    clientAPIKey = "3e7b7c1801535998c249f13d8bfe6b5739ffbc1eaeb4ffe26341f46812d4041e"
    # clientAPIKey = "abea8b6da5856997aef0d511b155df9c541536d841c438693b2fb560486474a4"

    IS_SPOOF = False
    IS_MALICIOUS = False
    if clientAPIKey:
        try:
            print("\\-->[*] SHA256 SUM : " + fileHash)
            url = "https://www.virustotal.com/api/v3/files/" + fileHash
            headers = {
                'x-apikey' : clientAPIKey
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
                    IS_SPOOF = True
                    IS_MALICIOUS = True
                    print("--- scanner malware classification ---")
                    print("//--> [*] Suggested threat label : " + str(json_resp['data']['attributes']['popular_threat_classification']['suggested_threat_label']))
                    threatCategory = list(json_resp['data']['attributes']['popular_threat_classification']['popular_threat_category'])
                    MALICIOUS_DATA["malware_types"].append(str(json_resp['data']['attributes']['popular_threat_classification']['suggested_threat_label']))

                    for category in threatCategory:
                        print("//--> [*] Category : " + category["value"])
                        print("//--> [*] Count : " + str(category["count"]))

            else:
                print("\\--> [!] Error")
                print(json_resp['error']['message'])

        except ConnectionError as e:
            print(f"[!] Error : {e}")
    else:
        print('[!] Error : Invalid ClientAPIKey')
        sys.exit()
    return IS_MALICIOUS

def getFileHash(pathFile):
    try:
        with open(pathFile, 'rb') as f:
            data = f.read()
            sha256 = hashlib.sha256(data).hexdigest()
            return sha256
    except FileNotFoundError as e:
        print(e)
        return ""

def addressCheck(address):
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{address}"
        header = {
            "x-apikey" : "3e7b7c1801535998c249f13d8bfe6b5739ffbc1eaeb4ffe26341f46812d4041e"
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

def main():
    if os.path.isfile(FILE_PATH):
        try:
            # check file path
            print("[*] Checking output path. . .")
            if not os.path.exists(OUTPUT_PATH):
                print("[!] Folder path not found")
                print(f"[*] Creating folder in path {OUTPUT_PATH}")
                os.makedirs(OUTPUT_PATH)

            print("[+] Scanning the Network using Netscan")
            netscan = vol2.run("windows.netscan.NetScan", FILE_PATH, OUTPUT_PATH, [])

            temp = netscan["ForeignAddr"]
            filteredIp = []
            
            print("[+] Filtering IP Address")
            
            # Filter ipv6 menggunakan regex
            ipv6_regex = re.compile("^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
            for addr in temp:
                if addr == '*' or addr == '0.0.0.0' or addr == '::' or ipv6_regex.match(addr):
                    continue
                else:
                    # filteredIp.append(addr)
                    if isValidIPv4(addr):
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

                    status = addressCheck(ip)
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
                        MALICIOUS_DATA["ipv4"].append(ip)
                        maliciousIp.append(ip)
                
                # ['83.212.99.68', '204.11.50.131', '94.130.200.167', '131.188.40.189']
                # print(maliciousIp)

                indexOfMaliciousIP = []
                maliciousPID = []
                
                # cek apakah terdeteksi malicious
                if maliciousIp:
                    print("[+] Getting index")
                    
                    # Get malicious index
                    for ad in temp:
                        if ad in maliciousIp:
                            # get index of malicious ip
                            # [7, 36, 37, 39]
                            indexOfMaliciousIP.append(temp.index(ad))
                    
                    print(f"idx of mals : {indexOfMaliciousIP}")

                    # Get all malicious PID to find the ancestor
                    for idx in indexOfMaliciousIP:
                        index = netscan["PID"][idx]
                        maliciousPID.append(index)
                    
                    # print(f"malicious pid : {maliciousPID}")
                    # PID: [2092, 2092, 2092, 2092]
                    # print(f"PID: {maliciousPID}")
                    print("[+] Getting malicious PID")
                    # # PID: [2092]
                    uniquePID = list(set(maliciousPID))

                    # print(uniquePID)
                    # # Run pslist plugin
                    print("[+] Scanning running process. . .")
                    pslist = vol2.run("windows.pslist.PsList", FILE_PATH, OUTPUT_PATH, [])
                    # print(pslist)
                    
                    ppidList = []
                    notOrphan = True
                    
                    print("[+] Find the parent process. . .")
                    # Find the parent process and the child process
                    for pid in uniquePID:
                        # print(pid)
                        # dapetin indx dari 2092
                        idx = pslist["PID"].index(pid)
                        # dapetin ppid dari 2092 -> 2340
                        ppid = pslist["PPID"][idx]
                        
                        # klo ada ppid di pid
                        if ppid in pslist["PID"]:
                            
                            # cari top nya
                            while notOrphan:
                                if ppid in pslist["PID"]:
                                    # masukin ke list [2340]
                                    ppidList.append(ppid)
                                    # ambil ppid sblmnya jadi pid: pid skrg 2340
                                    pidTemp = ppid
                                    # dapetin idx dari pid 2340
                                    pidIdx = pslist["PID"].index(pidTemp)
                                    # ubah ppid jadi 2464
                                    ppid = pslist["PPID"][pidIdx]
                                else:
                                    notOrphan = False
                        else:
                            continue

                    # Cek apakah ada proses yang terlewat 
                    anchestorPid = ppidList[-1]
                    listPPID = pslist["PPID"]
                    lenlistPPID = len(listPPID)
                    
                    print("[+] Getting all process from anchestor")
                    
                    for idx in range(lenlistPPID):
                        # klo sama dgn anchestorpid
                        if listPPID[idx] == anchestorPid:
                            susPID = pslist["PID"][idx]
                            # cek punya child proses
                            if susPID in listPPID:
                                # cari idx dengan comprehension loop
                                childIdxList = [idx for idx in range(lenlistPPID) if listPPID[idx] == susPID]
                                # assign pid ke ppid list
                                for child in childIdxList:
                                    pidTemp = pslist["PID"][child]
                                    if pidTemp not in ppidList:
                                        ppidList.append(pidTemp)
                            # klo ga punya child proses
                            else:
                                if susPID not in ppidList:
                                    ppidList.append(susPID)
                        else:
                            continue
                    
                    # gabungan PID dari network hingga ancestor dan anakannya
                    maliciousList = ppidList + uniquePID
                    
                    print(maliciousList)

                    # adding to dict
                    for pid in maliciousList:
                        MALICIOUS_DATA["sus_pid"].append(pid)

                    # print(pslist["PID"])
                    
                    print("[+] Finding suspicious process that already exit")

                    psscan = vol2.run("windows.psscan.PsScan", FILE_PATH, OUTPUT_PATH, [])

                    scanPPID = psscan["PPID"]
                    lenPPIDList = len(scanPPID)
                    hiddenPIDScan = []

                    for idx in range(lenPPIDList):
                        if scanPPID[idx] in maliciousList:
                            if scanPPID[idx] not in hiddenPIDScan:
                                MALICIOUS_DATA["hidden_pid"].append(scanPPID[idx])
                                hiddenPIDScan.append(scanPPID[idx])
                    
                    if hiddenPIDScan:
                        print(f"Hidden Process : {hiddenPIDScan}")

                    # print(maliciousList)
                    listCMD = {}
                    listDLL = {}
                    listHandles = {}
                    print("[+] Getting all cmd arguments. . .")

                    # print(listCMD) [1340, 2464, 1340, 2340, 2464, 2464, 1340]

                    for malz in maliciousList:
                        # print(malz)
                        # run cmd line
                        cmdline = vol2.run("windows.cmdline.CmdLine", FILE_PATH, OUTPUT_PATH, [malz])
                        
                        if not listCMD:
                            # saved cmdline
                            listCMD.update(cmdline)
                        else:
                            for key in listCMD.keys():
                                if key in cmdline:
                                    listCMD[key].append(cmdline[key][0])
                        # MALICIOUS_DATA["cmdline"].append(cmdline["Args"])
                    
                    print("[+] Getting all DLL from malicious process. . .")

                    for malz in maliciousList:
                        dll = vol2.run("windows.dlllist.DllList", FILE_PATH, OUTPUT_PATH, [malz, False])
                        
                        if not listDLL:
                            listDLL.update(dll)
                        else:
                            for key in listDLL.keys():
                                if key in dll:
                                    listDLL[key].append(dll[key][0])

                        # MALICIOUS_DATA["dlllist"].append(dll["Path"])

                    print("[+] Getting all handles from malicious process. . .")

                    # tambahin handles ke malicious data nanti
                    for malz in maliciousList:
                        handles = vol2.run("windows.handles.Handles", FILE_PATH, OUTPUT_PATH, [malz])

                        if not listHandles:
                            listHandles.update(handles)
                        else:
                            for key in listHandles.keys():
                                if key in handles:
                                    listHandles[key].append(handles[key][0])

                    # Cek persistence mechanism
                    # Cek dilakukan dengan cara mengecek registry key
                    # Yang biasanya ditempati malware
                    # Ex : MICROSOFT\WINDOWS\CURRENTVERSION\RUN
                    print("[+] Checking registry. . .")

                    # tambahin printkey ke malicious data nanti
                    for reg in REGISTRY_KEY:
                        printkey = vol2.run("windows.registry.printkey.PrintKey", FILE_PATH, OUTPUT_PATH, [reg])

                        typeLen = len(printkey["Type"])

                        for i in range(typeLen):
                            if printkey["Type"][i] != "Key":
                                sublist = [printkey[key][i] for key in printkey.keys()]
                                MALICIOUS_DATA["registry"].append(sublist)

                    # dump process
                    print("[+] Start to dump the process")

                    for malz in maliciousList:
                        print(f"[+] Dumping process {malz}")
                        vol2.run("windows.pslist.PsList", FILE_PATH, OUTPUT_PATH, [None, malz, True])

                    # iterate isi directory
                    folder_path = OUTPUT_PATH
                    # cek berapa banyak file
                    file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                    print("[+] Checking file to virus total")

                    pslist = vol2.run("windows.pslist.PsList", FILE_PATH, OUTPUT_PATH, [])
                    # ambil hash dan cek ke virus total
                    for file_name in os.listdir(folder_path):
                        file_path = os.path.join(folder_path, file_name)
                        if os.path.isfile(file_path):
                            for pid in maliciousList:
                                pidstr = str(pid)
                                # klo ada pid di file name
                                if pidstr in file_name:
                                    if file_count >= 5:
                                        sleep(15)
                                    if not file_name.startswith("."):
                                        file_hash = getFileHash(file_path)
                                        # cek ke vt
                                        print(f"\-->[*] File Name : {file_name} ")
                                        ismal = checksumVT(file_hash)
                                        if ismal:
                                            idx = pslist["PID"].index(pid)
                                            procname = pslist["ImageFileName"][idx]
                                            MALICIOUS_DATA["process_name"].append(procname)
                                            MALICIOUS_DATA["pid"].append(pid)
                                            MALICIOUS_DATA["exe_name"].append(file_name)
                                    break
                
                print(MALICIOUS_DATA)

                sys.exit()                           
            

            """



            
                KALO MISALKAN TIDAK ADA YANG MENCURIGAKAN DI IP

            


            """

            # Kalo gada filtered IP dan malicious ip
            # else:
            pslist = vol2.run("windows.pslist.PsList", FILE_PATH, [])
            procList = pslist["Image"]
            dup = []
            indcs = []
            anchestorindcs = []
            pidlist = pslist["PID"]
            malsPid = []

            # iterate image name
            for idx, element in enumerate(procList):
                if procList.count(element) > 1:
                    if element not in dup:
                        dup.append(element)
                        indcs.append([idx])
                    else:
                        indcs[dup.index(element)].append(idx)

            # jika tidak ada duplikat process name
            if not dup:
                print("[+] Everything's fine :)")
                sys.exit()
            # klo ada duplikat process name
            else:
                MALICIOUS_DATA["sus_pid"].append(dup)
                anchestorindcs = indcs
                pidOfSpoof = []
                for i, dups in enumerate(dup):
                    print(f"Checking process : {dups}")
                    # check anchestor pid
                    # lalu masukkan ke dalam list
                    for idx, idxOfPid in enumerate(indcs[i]):
                        pid = pidlist[idxOfPid]
                        anchestorPid = findAnchestor(pslist, pid)
                        anchestorindcs[i][idx] = anchestorPid
                        print(f"Anchestor of pid {pid} : {anchestorPid}")

                for indx, process in enumerate(dup):
                    # cek process yg tidak punya parent
                    print(f"Check process : {process}")
                    uniqueList = set(anchestorindcs[indx])
                    sizeListUnique  = len(uniqueList)
                    
                    if process == "csrss.exe" or process == "System" or process == "wininit.exe" or process == "winlogon.exe" or process == "explorer.exe":
                        # cek apakah pid mereka ada dalam pslist
                        # jika ada, spoof
                        for pid in anchestorindcs[indx]:
                            ppidIdx = pslist["PID"].index(pid)
                            ppid = pslist["PPID"][ppidIdx] # dapetin ppid
                            # cek klo ppid ada di pid
                            # pasti spoof
                            if ppid in pslist["PID"]:
                                # isSpoof = True
                                if indx not in pidOfSpoof:
                                    pidOfSpoof.append(pid)
                    else:
                        # cek apakah pid ada yang berbeda
                        # klo cuma 2 atau memungkinkan malicious
                        if sizeListUnique >= 2:
                            # isSpoof = True
                            for pid in anchestorindcs[indx]:
                                pidOfSpoof.append(pid)
                        elif sizeListUnique == 1:
                            continue
                        else:
                            print("[!] Error : Somethings wrong")
                
                print(f"idx spoof : {pidOfSpoof}")
                
                # cek k vt apakah beneran spoof
                folder_path = "./dumped/"
                for pid in pidOfSpoof:
                    print(f"Dumping pid {pid}")
                    vol2.run("windows.pslist.PsList", FILE_PATH, OUTPUT_PATH, [None, pid, True])

                # iterate isi directory
                # cek berapa banyak file
                file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                print("[+] Checking file to virus total")
                # ambil hash dan cek ke virus total
                for file_name in os.listdir(folder_path):
                    file_path = os.path.join(folder_path, file_name)
                    if os.path.isfile(file_path):
                        for pid in pidOfSpoof:
                            pidstr = str(pid)
                            if file_count >= 5:
                                sleep(15)
                            # bukan hidden file
                            if not file_name.startswith("."):
                                file_hash = getFileHash(file_path)
                                # cek ke vt
                                print(f"\-->[*] File Name : {file_name} ")
                                ismals = checksumVT(file_hash)
                                if ismals:
                                    malsPid.append(pid)
                                    MALICIOUS_DATA["pid"].append()                        

            # klo ada spoof
            # lanjut benerin ntr
            if malsPid:
                for pid in malsPid:
                    print("Getting commandline")
                    cmdline = vol2.run("windows.cmdline.CmdLine", FILE_PATH, [pid])
                    print("Getting dll") 
                    dll = vol2.run("windows.dlllist.DllList", FILE_PATH, [pid, False])
                    print("Getting handles")
                    handles = vol2.run("windows.handles.Handles", FILE_PATH, [pid])
                    print("Checking registry")
                    printkey = vol2.run("windows.registry.printkey.PrintKey", FILE_PATH, [REGISTRY_KEY[0]])
                sys.exit()
            # klo gada spoof
            # pisahin legitimate process
            # dump sisanya
            else:
                temp = pslist
                # hapus legitimate windows process dari list
                for proc in LEGAL_PROCNAME:
                    if proc in pslist["Image"]:
                        while True:
                            if proc not in temp["Image"]:
                                break
                            index = temp["Image"].index(proc)
                            print(f"Idx : {index}, Process name : {proc}")
                            temp["Image"].remove(proc)
                            temp["PID"].pop(index)
                            temp["PPID"].pop(index)
                            temp["Offset"].pop(index)
                            temp["Threads"].pop(index)
                            temp["Handles"].pop(index)
                            temp["SessionId"].pop(index)
                            temp["Wow64"].pop(index)
                            temp["CreateTime"].pop(index)
                            temp["ExitTime"].pop(index)
                            temp["FileOutPut"].pop(index)
                
                # dump semua process
                for pid in temp["PID"]:
                    vol2.run("windows.pslist.PsList", FILE_PATH, [None, pid, True])
        except Exception as e:
            print(f"[!] Error: {e}")
    else:
        print(f"[!] Error: {FILE_PATH} file not found")

if __name__ == '__main__':
    main()