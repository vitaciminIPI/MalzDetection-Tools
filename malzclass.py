from abc import ABC, abstractmethod
import json
import re
import requests
import hashlib
import sys
import vol2 as v
import os
from time import sleep
from utilities import UtilitiesMalz

class MalwareAttributes(ABC):
    maliciousData = {
        "info" : {},
        "ipv4" : [],
        "pid" : [],
        "sus_pid" : [],
        "hidden_pid" : [],
        "process_name" : [],
        "is_spoof" : False,
        "registry" : [],
        "exe_name" : [],
        "malware_types" : [],
        "dict_dlllist" : {},
        "dict_cmdline" : {},
        "dict_handles" : {}
    }

    registryKey = ["MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE", "CURRENTCONTROLSET\\CONTROL\\HIVELIST", "CONTROLSET002\\CONTROL\\SESSION MANAGER", "CURRENTCONTROLSET\\SERVICES", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNSERVICESONCE", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNSERVICES", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\NOTIFY", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\USERINIT", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\SHELL"]
    legalProcName = ["System", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "svchost.exe", "lsass.exe", "winlogon.exe", "explorer.exe", "taskhostw.exe", "RuntimeBroker.exe"]
    clientAPI = "3e7b7c1801535998c249f13d8bfe6b5739ffbc1eaeb4ffe26341f46812d4041e"
    # clientAPIKey = "abea8b6da5856997aef0d511b155df9c541536d841c438693b2fb560486474a4"

    def __init__(self, filepath, outputpath):
         self.filepath = filepath
         self.outputpath = outputpath

    @abstractmethod
    def run(self):
        pass

class TrojanMalz(MalwareAttributes, UtilitiesMalz):
    
    def run(self):
        pass

class RansomMalz(MalwareAttributes, UtilitiesMalz):

    def run(self):
        if os.path.isfile(self.filepath): 
            try:
                if not os.path.exists(self.outputpath):
                    os.makedirs(self.outputpath)

                infoImage = v.run("windows.info.Info", self.filepath, self.outputpath, [])
                self.maliciousData["info"].update(infoImage)
                
                netscan = v.run("windows.netscan.NetScan", self.filepath, self.outputpath, [])
                temp = netscan["ForeignAddr"]

                maliciousIp = self.checkNetwork(netscan)

                if maliciousIp:
                    self.maliciousData['ipv4'] = maliciousIp
                    indexOfMaliciousIP = []
                    maliciousPID = []
                    
                    if maliciousIp:
                        print("[+] Getting index")
                        
                        for ad in temp:
                            if ad in maliciousIp:
                                indexOfMaliciousIP.append(temp.index(ad))
                        
                        print(f"idx of mals : {indexOfMaliciousIP}")

                        for idx in indexOfMaliciousIP:
                            index = netscan["PID"][idx]
                            maliciousPID.append(index)
                        
                        print("[+] Getting malicious PID")
                        
                        uniquePID = list(set(maliciousPID))

                        print("[+] Scanning running process. . .")
                        pslist = v.run("windows.pslist.PsList", self.filepath, self.outputpath, [])
                        
                        ppidList = []
                        notOrphan = True
                        
                        print("[+] Find the parent process. . .")
                        for pid in uniquePID:
                            idx = pslist["PID"].index(pid)
                            ppid = pslist["PPID"][idx]
                            
                            if ppid in pslist["PID"]:
                                
                                while notOrphan:
                                    if ppid in pslist["PID"]:
                                        ppidList.append(ppid)
                                        pidTemp = ppid
                                        pidIdx = pslist["PID"].index(pidTemp)
                                        ppid = pslist["PPID"][pidIdx]
                                    else:
                                        notOrphan = False
                            else:
                                continue

                        anchestorPid = ppidList[-1]
                        listPPID = pslist["PPID"]
                        lenlistPPID = len(listPPID)
                        
                        print("[+] Getting all process from anchestor")
                        
                        for idx in range(lenlistPPID):
                            if listPPID[idx] == anchestorPid:
                                susPID = pslist["PID"][idx]
                                if susPID in listPPID:
                                    childIdxList = [idx for idx in range(lenlistPPID) if listPPID[idx] == susPID]
                                    for child in childIdxList:
                                        pidTemp = pslist["PID"][child]
                                        if pidTemp not in ppidList:
                                            ppidList.append(pidTemp)
                                else:
                                    if susPID not in ppidList:
                                        ppidList.append(susPID)
                            else:
                                continue

                        maliciousList = ppidList + uniquePID
                        
                        print(maliciousList)

                        for pid in maliciousList:
                            self.maliciousData["sus_pid"].append(pid)
                        
                        print("[+] Finding suspicious process that already exit")

                        psscan = v.run("windows.psscan.PsScan", self.filepath, self.outputpath, [])

                        scanPPID = psscan["PPID"]
                        lenPPIDList = len(scanPPID)
                        hiddenPIDScan = []

                        for idx in range(lenPPIDList):
                            if scanPPID[idx] in maliciousList:
                                if scanPPID[idx] not in hiddenPIDScan:
                                    self.maliciousData["hidden_pid"].append(scanPPID[idx])
                                    hiddenPIDScan.append(scanPPID[idx])
                        
                        if hiddenPIDScan:
                            print(f"Hidden Process : {hiddenPIDScan}")

                        listCMD = {}
                        listDLL = {}
                        listHandles = {}
                        print("[+] Getting all cmd arguments. . .")

                        for malz in maliciousList:
                            cmdline = v.run("windows.cmdline.CmdLine", self.filepath, self.outputpath, [malz])
                            
                            if not listCMD:
                                listCMD.update(cmdline)
                            else:
                                for key in listCMD.keys():
                                    if key in cmdline:
                                        listCMD[key].append(cmdline[key][0])
                        
                        self.maliciousData["dict_cmdline"] = listCMD
                        print("[+] Getting all DLL from malicious process. . .")

                        for malz in maliciousList:
                            dll = v.run("windows.dlllist.DllList", self.filepath, self.outputpath, [malz, False])
                            
                            if not listDLL:
                                listDLL.update(dll)
                            else:
                                for key in listDLL.keys():
                                    if key in dll:
                                        listDLL[key].append(dll[key][0])

                        self.maliciousData["dict_dlllist"] = listDLL

                        print("[+] Getting all handles from malicious process. . .")

                        for malz in maliciousList:
                            handles = v.run("windows.handles.Handles", self.filepath, self.outputpath, [malz])

                            if not listHandles:
                                listHandles.update(handles)
                            else:
                                for key in listHandles.keys():
                                    if key in handles:
                                        listHandles[key].append(handles[key][0])

                        self.maliciousData["dict_handles"] = listHandles
                        print("[+] Checking registry. . .")

                        for reg in self.registryKey:
                            printkey = v.run("windows.registry.printkey.PrintKey", self.filepath, self.outputpath, [reg])

                            typeLen = len(printkey["Type"])

                            for i in range(typeLen):
                                if printkey["Type"][i] != "Key":
                                    sublist = [printkey[key][i] for key in printkey.keys()]
                                    self.maliciousData["registry"].append(sublist)

                        self.maliciousData["dict_handles"] = listHandles

                        print("[+] Start to dump the process")

                        for malz in maliciousList:
                            print(f"[+] Dumping process {malz}")
                            v.run("windows.pslist.PsList", self.filepath, self.outputpath, [None, malz, True])

                        folder_path = self.outputpath
                        file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                        print("[+] Checking file to virus total")

                        pslist = v.run("windows.pslist.PsList", self.filepath, self.outputpath, [])
                        
                        for file_name in os.listdir(folder_path):
                            file_path = os.path.join(folder_path, file_name)
                            if os.path.isfile(file_path):
                                for pid in maliciousList:
                                    pidstr = str(pid)
                                    if pidstr in file_name:
                                        if file_count >= 5:
                                            sleep(15)
                                        if not file_name.startswith("."):
                                            file_hash = self.getFileHash(file_path)
                                            print(f"\-->[*] File Name : {file_name} ")
                                            ismal, typemalz = self.checksumVT(self.clientAPI, file_hash)
                                            if ismal:
                                                idx = pslist["PID"].index(pid)
                                                procname = pslist["ImageFileName"][idx]
                                                self.maliciousData["process_name"].append(procname)
                                                self.maliciousData["pid"].append(pid)
                                                self.maliciousData["exe_name"].append(file_name)
                                                self.maliciousData["malware_types"].append(typemalz)
                                        break
                    
                    print(self.maliciousData)

                    sys.exit()  

            except Exception as e:
                print(f"[!] Error : {e} ")
        else:
            print(f"[!] Error: {self.outputpath} file not found")

class WormMalz(MalwareAttributes, UtilitiesMalz):

    def run(self):
        if os.path.isfile(self.filepath): 
            try:
                if not os.path.exists(self.outputpath):
                    os.makedirs(self.outputpath)

                infoImage = v.run("windows.info.Info", self.filepath, self.outputpath, [])
                self.maliciousData["info"].update(infoImage)

                pslist = v.run("windows.pslist.PsList", self.filepath, self.outputpath, [])
                procList = pslist["ImageFileName"]
                dup = []
                indcs = []
                anchestorindcs = []
                pidlist = pslist["PID"]
                malsPid = []

                # iterate image name
                
                print("[!] find duplicate")

                for idx, element in enumerate(procList):
                    if procList.count(element) > 1:
                        if element not in dup:
                            dup.append(element)
                            indcs.append([idx])
                        else:
                            indcs[dup.index(element)].append(idx)


                # klo ada duplikat process name
                if dup:
                    print(f"[!] get duplicate pid : {dup}")
                    self.maliciousData["sus_pid"].append(dup)
                    anchestorindcs = indcs
                    pidOfSpoof = []
                    for i, dups in enumerate(dup):
                        print(f"Checking process : {dups}")
                        # check anchestor pid
                        # lalu masukkan ke dalam list
                        for idx, idxOfPid in enumerate(indcs[i]):
                            pid = pidlist[idxOfPid]
                            anchestorPid = self.findAnchestor(pslist, pid)
                            anchestorindcs[i][idx] = anchestorPid
                            # print(f"Anchestor of pid {pid} : {anchestorPid}")

                    print("[!] Checking process")
                    for indx, process in enumerate(dup):
                        # cek process yg tidak punya parent
                        # print(f"Check process : {process}")
                        uniqueList = set(anchestorindcs[indx])
                        sizeListUnique  = len(uniqueList)
                        
                        # proses" tertentu tidak memiliki parent
                        # apabila ada proses name yang ada dibawah ini memiliki parent
                        # tandai
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
                    for pid in pidOfSpoof:
                        print(f"Dumping pid {pid}")
                        v.run("windows.pslist.PsList", self.filepath, self.outputpath, [None, pid, True])

                    # iterate isi directory
                    # cek berapa banyak file
                    folder_path = "./dumped/"
                    file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                    print("[+] Checking file to virus total")
                    # ambil hash dan cek ke virus total
                    for file_name in os.listdir(folder_path):
                        file_path = os.path.join(folder_path, file_name)
                        if os.path.isfile(file_path):
                            for pid in pidOfSpoof:
                                pidstr = str(pid)
                                if pidstr in file_name:
                                    if file_count >= 5:
                                        sleep(15)
                                    # bukan hidden file
                                    if not file_name.startswith("."):
                                        file_hash = self.getFileHash(file_path)
                                        # cek ke vt
                                        print(f"\-->[*] File Name : {file_name} ")
                                        ismals, typeMals = self.checksumVT(self.clientAPI, file_hash)
                                        
                                        if ismals:
                                            malsPid.append(pid)
                                            idx = pslist["PID"].index(pid)
                                            procname = pslist["ImageFileName"][idx]
                                            self.maliciousData["process_name"].append(procname)
                                            self.maliciousData["pid"].append(pid)
                                            self.maliciousData["exe_name"].append(file_name)
                                            self.maliciousData["malware_types"].append(typeMals)
                    
                    # klo ada spoof
                    # proses pid
                    if malsPid:
                        listCMD = {}
                        listDLL = {}
                        listHandles = {}

                        self.maliciousData["is_spoof"] = True

                        print("[+] Getting all cmd arguments. . .")
                        for pid in malsPid:
                            cmdline = v.run("windows.cmdline.CmdLine", self.filepath, self.outputpath, [pid])

                            if not listCMD:
                                # saved cmdline
                                listCMD.update(cmdline)
                            else:
                                for key in listCMD.keys():
                                    if key in cmdline:
                                        listCMD[key].append(cmdline[key][0])
                        
                        self.maliciousData["dict_cmdline"] = listCMD

                        print("[+] Getting all DLL from malicious process. . .")
                        for pid in malsPid:
                            dll = v.run("windows.dlllist.DllList", self.filepath, self.outputpath, [pid, False])
                            
                            if not listDLL:
                                listDLL.update(dll)
                            else:
                                for key in listDLL.keys():
                                    if key in dll:
                                        listDLL[key].append(dll[key][0])
                        
                        self.maliciousData["dict_dlllist"] = listDLL

                        print("[+] Getting all handles from malicious process. . .")
                        for pid in malsPid:
                            handles = v.run("windows.handles.Handles", self.filepath, self.outputpath, [pid])

                            if not listHandles:
                                listHandles.update(handles)
                            else:
                                for key in listHandles.keys():
                                    if key in handles:
                                        listHandles[key].append(handles[key][0])

                        self.maliciousData["dict_handles"] = listHandles

                        print("[+] Checking registry. . .")

                        for reg in self.registryKey:
                            printkey = v.run("windows.registry.printkey.PrintKey", self.filepath, self.outputpath, [reg])
                            typeLen = len(printkey["Type"])

                            for i in range(typeLen):
                                if printkey["Type"][i] != "Key":
                                    sublist = [printkey[key][i] for key in printkey.keys()]
                                    self.maliciousData["registry"].append(sublist)

                        sys.exit()
                print("[!] File is benign")
            except Exception as e:
                print(f"[!] Error : {e}")

        else:
            print(f"[!] Error: {self.outputpath} file not found")