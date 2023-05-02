from volatility3.framework import contexts
from volatility3.framework import automagic
from volatility3 import framework
from volatility3.framework import interfaces
from volatility3.cli import PrintedProgress, MuteProgress
from volatility3.framework import plugins
from volatility3.cli import CommandLine as cmd
from volatility3.cli import text_renderer, volargparse
from volatility3.framework import interfaces
import os, json
from typing import Dict, Type, Union, Any
from urllib import parse, request
from volatility3.framework.configuration import requirements
import vol2
import requests
import re 
from time import sleep

FILE_PATH = "wanncry.vmem"
REGISTRY_KEY = ["MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE", "CURRENTCONTROLSET\\CONTROL\\HIVELIST", "CONTROLSET002\\CONTROL\\SESSION MANAGER", "CURRENTCONTROLSET\\SERVICES", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNSERVICESONCE", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNSERVICES", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\NOTIFY", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\USERINIT", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\SHELL"]

def intToHex(listOfData):
     lenOfData = len(listOfData)

     for idx in range(lenOfData):
        listOfData[idx] = hex(listOfData[idx]) 

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
            print("[+] Scanning the Network using Netscan")
            netscan = vol2.run("windows.netscan.NetScan", FILE_PATH, [1340])
            temp = netscan["ForeignAddress"]
            filteredIp = []
            
            print("[+] Filtering IP Address")

            # Filter ipv6 menggunakan regex
            ipv6_regex = re.compile("^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$")
            for addr in temp:
                if addr == '*' or addr == '0.0.0.0' or addr == '::' or ipv6_regex.match(addr):
                    continue
                else:
                    filteredIp.append(addr)

            lenOfFilteredIp = len(filteredIp)
            maliciousIp = []

            print("[+] Checking IP Address status")
            uniqueIp = list(set(filteredIp))
            # print(uniqueIp)

            for ip in uniqueIp:
                if lenOfFilteredIp >= 5: #Biar ga kena rate limit submit public API samples
                    sleep(16)
                
                # print(ip)

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
                
                # Get all malicious PID to find the ancestor
                for idx in indexOfMaliciousIP:
                    maliciousPID.append(netscan["PID"][idx])
                
                # PID: [2092, 2092, 2092, 2092]
                # print(f"PID: {maliciousPID}")
                print("[+] Getting malicious PID")
                # PID: [2092]
                uniquePID = list(set(maliciousPID))

                # Run pslist plugin
                print("[+] Scanning running process. . .")
                pslist = vol2.run("windows.pslist.PsList", FILE_PATH, [])
                
                ppidList = []
                notOrphan = True
                
                print("[+] Find the parent process. . .")
                # Find the parent process and the child process
                for pid in uniquePID:
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

                print("[+] Finding suspicious process that already exit")

                psscan = vol2.run("windows.psscan.PsScan", FILE_PATH, [])

                scanPPID = psscan["PPID"]
                lenPPIDList = len(scanPPID)
                hiddenPIDScan = []

                for idx in range(lenPPIDList):
                    if scanPPID[idx] in maliciousList:
                        if scanPPID[idx] not in hiddenPIDScan:
                            hiddenPIDScan.append(scanPPID[idx])
                
                print(f"Hidden Process : {hiddenPIDScan}")

                # print(maliciousList)
                listCMD = {}
                listDLL = {}
                listHanldes = {}
                print("[+] Getting all cmd arguments. . .")

                # print(listCMD) [1340, 2464, 1340, 2340, 2464, 2464, 1340]

                for malz in maliciousList:
                    # run cmd line
                    cmdline = vol2.run("windows.cmdline.CmdLine", FILE_PATH, [malz])
                    # saved cmdline
                    listCMD.update(cmdline)
                
                print("[+] Getting all DLL from malicious process. . .")

                for malz in maliciousList:
                    dll = vol2.run("windows.dlllist.DllList", FILE_PATH, [malz])
                    listDLL.update(dll)

                intToHex(listDLL["Size"])
                intToHex(listDLL["Name"])

                # print(listDLL)

                print("[+] Getting all handles from malicious process. . .")

                for malz in maliciousList:
                    handles = vol2.run("windows.handles.Handles", FILE_PATH, [malz])
                    listHanldes.update(handles)
                
                # to hex : handles value, type, name
                intToHex(listHanldes["HandleValue"])
                intToHex(listHanldes["Type"])
                intToHex(listHanldes["Name"])

                # Cek persistence mechanism
                # Cek dilakukan dengan cara mengecek registry key
                # Yang biasanya ditempati malware
                # Ex : MICROSOFT\WINDOWS\CURRENTVERSION\RUN
                print("[+] Checking registry. . .")


                printkey = vol2.run("windows.registry.printkey.PrintKey", FILE_PATH, [REGISTRY_KEY[0]])
                intToHex(printkey["Time Hive"])
                # print(printkey)

                

            else:  # jika tidak ada malicious ip
                pass
        except Exception as e:
            print(f"[!] Error: {e}")
    else:
        print(f"[!] Error: {FILE_PATH} file not found")

if __name__ == '__main__':
    main()