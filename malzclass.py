import vol2 as v
import os
import copy
from abc import ABC, abstractmethod
from time import sleep
from utilities import UtilitiesMalz
from datetime import datetime

# BERESIN CLASS LOCKBIT DAN METASPLOIT

class MalwareAttributes(ABC):
    maliciousData = {
        "info" : {},
        "ipv4" : [],
        "pid" : [],
        "sus_pid" : [],
        "hidden_pid" : [],
        "process_name" : [],
        "registry" : [],
        "exe_name" : [],
        "mod_name" : [],
        "injected_code" : [],
        "malware_types" : [],
        "dict_dlllist" : {},
        "dict_cmdline" : {},
        "dict_handles" : {},
        "dict_malfind" : {},
        "iocs" : {}
    }
 
    registryKey = ["MICROSOFT\\WINDOWS NT\\CURRENTVERSION\\WINLOGON", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNONCE", "CURRENTCONTROLSET\\CONTROL\\HIVELIST", "CONTROLSET002\\CONTROL\\SESSION MANAGER", "CURRENTCONTROLSET\\SERVICES", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNSERVICESONCE", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUNSERVICES", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\NOTIFY", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\USERINIT", "MICROSOFT\\WINDOWS\\CURRENTVERSION\\WINLOGON\\SHELL"]
    legalProcName = ["System", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "svchost.exe", "lsass.exe", "winlogon.exe", "explorer.exe", "taskhostw.exe", "RuntimeBroker.exe"]
    # clientAPI = "3e7b7c1801535998c249f13d8bfe6b5739ffbc1eaeb4ffe26341f46812d4041e"
    clientAPI = "abea8b6da5856997aef0d511b155df9c541536d841c438693b2fb560486474a4"

    def __init__(self, filepath, outputpath):
         self.filepath = filepath
         self.outputpath = outputpath

    @abstractmethod
    def run(self):
        pass

class Emotet(MalwareAttributes, UtilitiesMalz):
    
    def run(self):
        if os.path.isfile(self.filepath):
            try:
                if not os.path.exists(self.outputpath):
                    os.makedirs(self.outputpath)

                infoImage = v.run("windows.info.Info", self.filepath, self.outputpath, []).copy()
                self.maliciousData["info"].update(infoImage)
                
                netscan = v.run("windows.netscan.NetScan", self.filepath, self.outputpath, []).copy()
                temp = netscan["ForeignAddr"]

                maliciousIp = self.checkNetwork(netscan, self.clientAPI)

                if maliciousIp:
                    self.maliciousData['ipv4'] = maliciousIp
                    indexOfMaliciousIP = []
                    maliciousPID = []
                    
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
                    self.maliciousData['pid'] = maliciousList

                    listCMD = {}
                    listDLL = {}
                    listMalfind = {}

                    print("[+] Getting all cmd arguments. . .")
                    for pid in maliciousList:
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
                    for pid in maliciousList:
                        dll = v.run("windows.dlllist.DllList", self.filepath, self.outputpath, [pid, False]).copy()
                        
                        if not listDLL:
                            listDLL.update(dll)
                        else:
                            for key in listDLL.keys():
                                if key in dll:
                                    listDLL[key].append(dll[key][0])
                    
                    self.maliciousData["dict_dlllist"] = listDLL

                    print("[+] Running Malfind plugin. . . ")

                    for pid in maliciousList:
                        malfind = v.run("windows.malfind.Malfind", self.filepath, self.outputpath, [pid, False])

                        if not listCMD:
                            # saved cmdline
                            listMalfind.update(cmdline)
                        else:
                            for key in listMalfind.keys():
                                if key in malfind:
                                    listMalfind[key].append(malfind[key][0])

                    self.maliciousData['dict_malfind'] = listMalfind

                    return self.maliciousData
                else:
                    print("[!] File is benign")
                    return None
            except Exception as e:
                print(f"[!] Error : {e}")
        else:
            print("[!] Error: File not found")

class WannaCry(MalwareAttributes, UtilitiesMalz):

    def run(self):
        if os.path.isfile(self.filepath): 
            try:
                if not os.path.exists(self.outputpath):
                    os.makedirs(self.outputpath)

                infoImage = v.run("windows.info.Info", self.filepath, self.outputpath, []).copy()
                self.maliciousData["info"].update(infoImage)

                netscan = v.run("windows.netscan.NetScan", self.filepath, self.outputpath, []).copy()
                temp = netscan["ForeignAddr"]

                maliciousIp = self.checkNetwork(netscan, self.clientAPI)

                if maliciousIp:
                    self.maliciousData['ipv4'] = maliciousIp
                    indexOfMaliciousIP = []
                    maliciousPID = []
                    
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
                    pslist = v.run("windows.pslist.PsList", self.filepath, self.outputpath, []).copy()
                    
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

                    for pid in maliciousList:
                        self.maliciousData["sus_pid"].append(pid)
                    
                    print("[+] Finding suspicious process that already exit")

                    psscan = v.run("windows.psscan.PsScan", self.filepath, self.outputpath, []).copy()

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
                    listLdrMod = {}
                    print("[+] Getting all cmd arguments. . .")

                    for malz in maliciousList:
                        cmdline = v.run("windows.cmdline.CmdLine", self.filepath, self.outputpath, [malz]).copy()
                        
                        if not listCMD:
                            listCMD.update(cmdline)
                        else:
                            for key in listCMD.keys():
                                if key in cmdline:
                                    listCMD[key].extend(cmdline[key])
                    
                    self.maliciousData["dict_cmdline"] = listCMD
                    print("[+] Getting all DLL from malicious process. . .")

                    for malz in maliciousList:
                        dll = v.run("windows.dlllist.DllList", self.filepath, self.outputpath, [malz, False]).copy()
                        
                        if not listDLL:
                            listDLL.update(dll)
                        else:
                            for key in listDLL.keys():
                                if key in dll:
                                    listDLL[key].extend(dll[key])

                    self.maliciousData["dict_dlllist"] = listDLL

                    print("[+] Getting ldr modules. . .")

                    # Check ldr modules
                    for malz in maliciousList:
                        ldrmod = v.run("windows.ldrmodules.LdrModules", self.filepath, self.outputpath, [malz]).copy()

                        if not listLdrMod:
                            listLdrMod.update(ldrmod)
                        else:
                            for key in listLdrMod.keys():
                                if key in ldrmod:
                                    listLdrMod[key].extend(ldrmod[key])
                    
                    # finding iocs in dlllist
                    ldrModIOC = []
                    for name in listLdrMod['MappedPath']:
                        if "WannaCry" in name or "WanaDecryptor" in name or name.endswith(".mui") or "Tor" in name:
                            ldrModIOC.append(name)
                    
                    if ldrModIOC:
                        self.maliciousData['iocs']['ldrmod'] = ldrModIOC
                    
                    print(ldrModIOC)
                    print("[+] Getting all handles from malicious process. . .")

                    for malz in maliciousList:
                        handles = v.run("windows.handles.Handles", self.filepath, self.outputpath, [malz]).copy()

                        if not listHandles:
                            listHandles.update(handles)
                        else:
                            for key in listHandles.keys():
                                if key in handles:
                                    listHandles[key].extend(handles[key])

                    self.maliciousData["dict_handles"] = listHandles
                    
                    # finding ioc in handles
                    handleIOC = []

                    for name in listHandles['Name']:
                        if name.endswith('.eky') or name.endswith('.WNCRYT'):
                            handleIOC.append(name)
                        if name  == "MsWinZonesCacheCounterMutexA" or name == "MsWinZonesCacheCounterMutexA0":
                            handleIOC.append(name)
                        if "tor" in name:
                            handleIOC.append(name)  

                    if handleIOC:
                        self.maliciousData['iocs']['handles'] = handleIOC

                    print("[+] Checking registry. . .")

                    for reg in self.registryKey:
                        try:
                            printkey = v.run("windows.registry.printkey.PrintKey", self.filepath, self.outputpath, [reg]).copy()

                            typeLen = len(printkey["Type"])

                            for i in range(typeLen):
                                if printkey["Type"][i] != "Key":
                                    sublist = [printkey[key][i] for key in printkey.keys()]
                                    self.maliciousData["registry"].append(sublist)
                        except:
                            continue

                    newdirpath = self.createDirs(self.outputpath, "Exe")

                    print("[+] Start to dump the process")

                    for malz in maliciousList:
                        print(f"[+] Dumping process {malz}")
                        v.run("windows.pslist.PsList", self.filepath, newdirpath, [None, malz, True])

                    folder_path = newdirpath
                    file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                    print("[+] Checking file to virus total")
                    count = 1

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
                                        print(f"Submit VT Progress : {count}/{file_count}")
                                        print(f"\-->[*] File Name : {file_name} ")
                                        count += 1 
                                        ismal, typemalz = self.checksumVT(self.clientAPI, file_hash)
                                        if ismal:
                                            idx = pslist["PID"].index(pid)
                                            procname = pslist["ImageFileName"][idx]
                                            self.maliciousData["process_name"].append(procname)
                                            self.maliciousData["pid"].append(pid)
                                            self.maliciousData["exe_name"].append(file_name)
                                            self.maliciousData["malware_types"].append(typemalz)
                                    break
                    return self.maliciousData
                else:
                    print("[!] File is benign")
                    return None
            except Exception as e:
                print(f"[!] Error : {e} ")
        else:
            print(f"[!] Error: {self.outputpath} file not found")

class StuxNet(MalwareAttributes, UtilitiesMalz):

    def run(self):
        if os.path.isfile(self.filepath): 
            try:
                if not os.path.exists(self.outputpath):
                    os.makedirs(self.outputpath)

                infoImage = v.run("windows.info.Info", self.filepath, self.outputpath, []).copy()
                self.maliciousData["info"].update(infoImage)

                pslist = v.run("windows.pslist.PsList", self.filepath, self.outputpath, []).copy()
                pidList = pslist['PID']

                print("[+] Checking duplicate process name")
                dup, indcs = self.checkProcDup(pslist)
                anchestorindcs = [[]]
                malsPid = []


                if dup:
                    print("[!] Getting sus pid")
                    lenOfIdcs = len(indcs)
                    for idx in range(lenOfIdcs):
                        for pid in indcs[idx]:
                            self.maliciousData['sus_pid'] = pid

                    anchestorindcs = copy.deepcopy(indcs)
                    pidOfSpoof = []

                    for i, _ in enumerate(dup):
                        for idx, idxOfPid in enumerate(indcs[i]):
                            anchestorPid = pslist['PPID'][idxOfPid]
                            anchestorindcs[i][idx] = anchestorPid

                    print("[+] Check anomaly in duplicate process name")
                    for indx, process in enumerate(dup):
                        uniqueList = set(anchestorindcs[indx])
                        sizeListUnique  = len(uniqueList)
                        
                        if process == "csrss.exe" or process == "System" or process == "wininit.exe" or process == "winlogon.exe" or process == "explorer.exe":
                            for i, pid in enumerate(anchestorindcs[indx]):
                                if pid in pslist['PID']:
                                    ppidIdx = pslist["PID"].index(pid)
                                    ppid = pslist["PPID"][ppidIdx] 
                                    if ppid in pslist["PID"]:
                                        if indx not in pidOfSpoof:
                                            indcsPtr = indcs[indx][i]
                                            pidmal = pidList[indcsPtr]
                                            pidOfSpoof.append(pidmal)
                        else:
                            if sizeListUnique >= 2:
                                for i, pid in enumerate(anchestorindcs[indx]):
                                    indcsPtr = indcs[indx][i]
                                    pidmal = pidList[indcsPtr]
                                    pidOfSpoof.append(pidmal)
                            elif sizeListUnique == 1:
                                continue
                            else:
                                print("[!] Error : Somethings wrong")

                    newdirpath = self.createDirs(self.outputpath, "Exe")

                    # dump
                    for pid in pidOfSpoof:
                        print(f"Dumping pid {pid}")
                        v.run("windows.pslist.PsList", self.filepath, newdirpath, [None, pid, True])

                    folder_path = newdirpath
                    file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                    print("[+] Checking file to virus total")
                    count = 1
        
                    for file_name in os.listdir(folder_path):
                        file_path = os.path.join(folder_path, file_name)
                        if os.path.isfile(file_path):
                            for pid in pidOfSpoof:
                                pidstr = str(pid)
                                if pidstr in file_name:
                                    if file_count >= 5:
                                        sleep(15)
                                    if not file_name.startswith("."):
                                        try:
                                            file_hash = self.getFileHash(file_path)
                                            print(f"Submit VT Progress : {count}/{file_count}")
                                            print(f"\-->[*] File Name : {file_name} ")
                                            ismals, typeMals = self.checksumVT(self.clientAPI, file_hash)
                                            count += 1
                                            if ismals and typeMals:
                                                malsPid.append(pid)
                                                idx = pslist["PID"].index(pid)
                                                procname = pslist["ImageFileName"][idx]
                                                self.maliciousData["process_name"].append(procname)
                                                self.maliciousData["pid"].append(pid)
                                                self.maliciousData["exe_name"].append(file_name)
                                                self.maliciousData["malware_types"].append(typeMals)
                                        except Exception as e:
                                            print(e)

                    if malsPid:
                        listCMD = {}
                        listDLL = {}
                        listHandles = {}

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
                            try:
                                printkey = v.run("windows.registry.printkey.PrintKey", self.filepath, self.outputpath, [reg])
                                typeLen = len(printkey["Type"])

                                for i in range(typeLen):
                                    if printkey["Type"][i] != "Key":
                                        sublist = [printkey[key][i] for key in printkey.keys()]
                                        self.maliciousData["registry"].append(sublist)
                            except Exception as e:
                                print(e)
                            
                        return self.maliciousData
                        # newdirpath = self.createDirs(self.outputpath, "Mod")
                        
                        # dump
                        # print("[*] Dumping modules")
                        # v.run("windows.modules.Modules", self.filepath, newdirpath, [True])

                        # folder_path = newdirpath
                        # file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                        # print("[+] Checking file to virus total")
                        # for file_name in os.listdir(folder_path):
                        #     file_path = os.path.join(folder_path, file_name)
                        #     if os.path.isfile(file_path):
                        #         if file_count >= 5:
                        #             sleep(15)
                        #         if not file_name.startswith("."):
                        #             try:
                        #                 file_hash = self.getFileHash(file_path)
                        #                 print(f"\-->[*] File Name : {file_name} ")
                        #                 ismal, typemalz = self.checksumVT(self.clientAPI, file_hash)

                        #                 if ismal and typemalz:
                        #                     self.maliciousData['malware_types'] = typemalz
                        #                     self.maliciousData['mod_name'].append(file_name)
                        #             except Exception as e:
                        #                 print(e)
                else:
                    print("[!] File is benign")
                    return None
            except Exception as e:
                print(f"[!] Error : {e}")
        else:
            print(f"[!] Error: {self.outputpath} file not found")

class LockBit(MalwareAttributes, UtilitiesMalz):

    def run(self):
        if os.path.isfile(self.filepath):
            try:
                if not os.path.exists(self.outputpath):
                    os.makedirs(self.outputpath)

                infoImage = v.run("windows.info.Info", self.filepath, self.outputpath, []).copy()
                self.maliciousData["info"].update(infoImage)

                malfind = v.run("windows.malfind.Malfind", self.filepath, self.outputpath, []).copy()
                
                malPidList = list(set(malfind['PID']))

                newdirpath = self.createDirs(self.outputpath, "Exe")

                for pid in malPidList:
                    print(f"Dumping pid {pid}")
                    v.run("windows.pslist.PsList", self.filepath, newdirpath, [False, pid, True])

                folder_path = newdirpath
                file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                print("[+] Checking file to virus total")
    
                for file_name in os.listdir(folder_path):
                    file_path = os.path.join(folder_path, file_name)
                    if os.path.isfile(file_path):
                        if file_count >= 5:
                            sleep(15)
                        if not file_name.startswith("."):
                            file_hash = self.getFileHash(file_path)
                            print(f"\-->[*] File Name : {file_name} ")
                            ismal, typemalz = self.checksumVT(self.clientAPI, file_hash)

                            if ismal:
                                self.maliciousData['malware_types'] = typemalz
                                self.maliciousData['mod_name'].append(file_name)

                    
            except Exception as e:
                print(f"[!] Error : {e}")
        else:
            print(f"[!] Error: {self.outputpath} file not found")
        
class MetasPreter(MalwareAttributes, UtilitiesMalz):

    def run(self):
        if os.path.isfile(self.filepath):
            try:
                infoImage = v.run("windows.info.Info", self.filepath, self.outputpath, []).copy()
                self.maliciousData["info"].update(infoImage)
                
                print("[+] Running Malfind plugin")
                malfind = v.run("windows.malfind.Malfind", self.filepath, self.outputpath, []).copy()

                malPidList = list(set(malfind['PID']))
                
                # dump injected code

                newdirpath = self.createDirs(self.outputpath, "Mal")

                for pid in malPidList:
                    print(f"Dumping pid {pid}")
                    v.run("windows.malfind.Malfind", self.filepath, newdirpath, [pid, True])

                folder_path = newdirpath
                file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                print("[+] Checking file to virus total")

                maliciousPidList = []
                count = 1

                for file_name in os.listdir(folder_path):
                    file_path = os.path.join(folder_path, file_name)
                    if os.path.isfile(file_path):
                        for pid in malPidList:
                            pidstr = str(pid)    
                            if pidstr in file_name:
                                if file_count >= 5:
                                    sleep(15)
                                if not file_name.startswith("."):
                                    file_hash = self.getFileHash(file_path)
                                    print(f"Submit VT Progress : {count}/{file_count}")
                                    print(f"\-->[*] File Name : {file_name} ")
                                    ismal, typemalz = self.checksumVT(self.clientAPI, file_hash)
                                    count +=1 

                                    if ismal:
                                        maliciousPidList.append(pid)
                                        self.maliciousData['pid'].append(pidstr)
                                        self.maliciousData['malware_types'] = typemalz
                                        self.maliciousData['injected_code'].append(file_name)

                if maliciousPidList:
                    # yang hit dari vt = 704, 3732
                    # maliciousPidList = [704, 3732]
                    idxChild = []

                    print(f"maliciouspidlist : {maliciousPidList}")

                    pslist = v.run("windows.pslist.PsList", self.filepath, self.outputpath, []).copy()
                    listPPID = pslist['PPID']
                    lenlistPPID = len(listPPID)
                    pidPsList = pslist['PID']

                    print("[+] Get child")
                    
                    # get child
                    for pid in maliciousPidList:
                        temp = self.getChild(pslist, pid)
                        idxChild += temp

                    # print(idxChild)
                    idxChild = list(set(idxChild))

                    print("[+] Get child pid from pslist")
                    for idx in idxChild:
                        pid = pidPsList[idx]
                        maliciousPidList.append(pid)

                    print(f"malicious pidlist {maliciousPidList}")

                    # get parent
                    ppidList = []
                    notOrphan = True
                    
                    print("[+] Find the parent PID. . .")
                    for pid in maliciousPidList:
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

                    # print(ppidList)
                    # Cari process yang merupakan child proc dari ancestor
                    anchestorPid = ppidList[-1]              
                    print("[+] Getting all process from anchestor")
                    
                    for idx in range(lenlistPPID):
                        if pidPsList[idx] == anchestorPid:
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
                    
                    
                    # ppidlist = [2720, 2840, 2848, 1180, 3732, 704, 3756]
                    maliciousPidList += ppidList
                    # print(f"malicious pid list : {maliciousPidList}")
                    # [704, 2720, 2848, 1352, 3756, 2840, 3732, 4056, 1180]
                    uniqueMalList = list(set(maliciousPidList))

                    # print(f"unique pid {uniqueMalList}")

                    self.maliciousData["sus_pid"] = uniqueMalList

                    # VirusTotal analysis
                    # dump exe terlebih dahulu

                    newdirpath = self.createDirs(self.outputpath, "Exe")

                    for mal in uniqueMalList:
                        v.run("windows.pslist.PsList", self.filepath, newdirpath, [False, mal, True])

                    folder_path = newdirpath
                    file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                    print("[+] Checking file to virus total")

                    hitPid = []

                    for file_name in os.listdir(folder_path):
                        file_path = os.path.join(folder_path, file_name)
                        if os.path.isfile(file_path):
                            for pid in uniqueMalList:
                                pidstr = str(pid)
                                if pidstr in file_name:    
                                    if file_count >= 5:
                                        sleep(15)
                                    if not file_name.startswith("."):
                                        file_hash = self.getFileHash(file_path)
                                        print(f"\-->[*] File Name : {file_name} ")
                                        ismal, typemalz = self.checksumVT(self.clientAPI, file_hash)

                                        if ismal:
                                            hitPid.append(pid)
                                            self.maliciousData['pid'].append(pidstr)
                                            self.maliciousData['malware_types'] = typemalz
                                            self.maliciousData['exe_name'].append(file_name)
                    
                    # kalo ada hit pid
                    # Volatility analysis
                    # hitPid = [704, 2720, 2848, 1352, 3756, 2840, 3732, 4056, 1180]
                    # hitPid = [704, 2720, 2848, 1352, 4056]

                    if hitPid:
                        print("[+] Volatility Analysis")

                        print("[+] Checking Network Connections")

                        netscan = v.run("windows.netscan.NetScan", self.filepath, newdirpath, []).copy()
                        netPort = netscan['ForeignPort']
                        
                        print("[+] Checking Foreign Port")
                        metas_port = [port for port in netPort if port == 4444]
                        
                        if metas_port:
                            self.maliciousData['metas_port'] = metas_port[0]
                        
                        print("[+] Checking Foreign Address")
                        maliciousIp = self.checkNetwork(netscan, self.clientAPI)

                        if maliciousIp:
                            self.maliciousData['ipv4'] = maliciousIp

                        listCMD = {}
                        # listDLL = {}
                        # listHandles = {}
                        print("[+] Getting all cmd arguments. . .")

                        for malz in hitPid:
                            cmdline = v.run("windows.cmdline.CmdLine", self.filepath, newdirpath, [malz]).copy()
                            
                            if not listCMD:
                                listCMD.update(cmdline)
                            else:
                                for key in listCMD.keys():
                                    if key in cmdline:
                                        listCMD[key].append(cmdline[key][0])
                        
                        self.maliciousData["dict_cmdline"] = listCMD
                        # print("[+] Getting all DLL from malicious process. . .")

                        # for malz in hitPid:
                        #     dll = v.run("windows.dlllist.DllList", self.filepath, newdirpath, [malz, False]).copy()
                            
                        #     if not listDLL:
                        #         listDLL.update(dll)
                        #     else:
                        #         for key in listDLL.keys():
                        #             if key in dll:
                        #                 listDLL[key].append(dll[key][0])

                        # self.maliciousData["dict_dlllist"] = listDLL

                        # print("[+] Getting all handles from malicious process. . .")

                        # for malz in hitPid:
                        #     handles = v.run("windows.handles.Handles", self.filepath, newdirpath, [malz]).copy()

                        #     if not listHandles:
                        #         listHandles.update(handles)
                        #     else:
                        #         for key in listHandles.keys():
                        #             if key in handles:
                        #                 listHandles[key].append(handles[key][0])

                        # self.maliciousData["dict_handles"] = listHandles
                        # print("[+] Checking registry. . .")

                        # for reg in self.registryKey:
                        #     try:
                        #         printkey = v.run("windows.registry.printkey.PrintKey", self.filepath, newdirpath, [reg]).copy()

                        #         typeLen = len(printkey["Type"])

                        #         for i in range(typeLen):
                        #             if printkey["Type"][i] != "Key":
                        #                 sublist = [printkey[key][i] for key in printkey.keys()]
                        #                 self.maliciousData["registry"].append(sublist)
                        #     except:
                        #         continue

                        # self.maliciousData["dict_handles"] = listHandles
                        
                return self.maliciousData

            except Exception as e:
                print(f"[!] Error : {e}")
        else:
            print(f"[!] Error: {self.outputpath} file not found")