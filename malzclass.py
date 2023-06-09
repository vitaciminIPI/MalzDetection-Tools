import vol2 as v
import os
import copy
from abc import ABC, abstractmethod
from time import sleep
from utilities import UtilitiesMalz
from datetime import datetime


class MalwareAttributes(ABC):
    """
    A class used to create blueprint of malware in general

    ...
    
    Attributes
    ----------
    maliciousData : dict
        a dictionary to store all data related to malware indications
    registryKey : list
        a list of registry keys to be checked
    legalProcName : list
        a list of known legal process in windows systems
    clientAPI : str
        a string that holds the VirusTotal client API key

    Methods
    -------
    run(self)
        Start to hunt malware with volatility
    """

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
    clientAPI = "3e7b7c1801535998c249f13d8bfe6b5739ffbc1eaeb4ffe26341f46812d4041e"
    # clientAPI = "abea8b6da5856997aef0d511b155df9c541536d841c438693b2fb560486474a4"

    def __init__(self, filepath, outputpath):
        """
        Parameters
        ----------
        filepath : str
            A full path to file memory
        outputpath: str
            A full path to directory output
        """
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
                    
                    # print(f"idx of mals : {indexOfMaliciousIP}")

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

class WannaCryV1(MalwareAttributes, UtilitiesMalz):
    """
    A class to analyse WannaCry Ransomware

    ...

    Methods
    -------
    run(self)
        Start to hunt WannaCry Ranswomare and return a dictionary of iocs
    """

    def run(self):
        # Check if filepath is a file
        # if it is not, error
        if os.path.isfile(self.filepath): 
            try:
                # if the outputpath not found, create directory with the path
                if not os.path.exists(self.outputpath):
                    os.makedirs(self.outputpath)

                infoImage = v.run("windows.info.Info", self.filepath, self.outputpath, []).copy()
                self.maliciousData["info"].update(infoImage)
            
                netscan = v.run("windows.netscan.NetScan", self.filepath, self.outputpath, []).copy()
                temp = netscan["ForeignAddr"]
                
                # find malicious ip
                maliciousIp = self.checkNetwork(netscan, self.clientAPI)

                # if victims connect to malicious address, get the pid
                # if it not, stop
                if maliciousIp:
                    self.maliciousData['ipv4'] = maliciousIp
                    indexOfMaliciousIP = []
                    maliciousPID = []
                    
                    print("[+] Getting index")
                    
                    for ad in temp:
                        if ad in maliciousIp:
                            indexOfMaliciousIP.append(temp.index(ad))
                    
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

                    # check if there is process with ppid in maliciousList and store the pid
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

                    # Analyze pid in maliciousList with cmdline plugin
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

                    # Analyze pid in maliciousList with dlllist plugin
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

                    # Analyze pid in maliciousList with ldr modules plugin
                    for malz in maliciousList:
                        ldrmod = v.run("windows.ldrmodules.LdrModules", self.filepath, self.outputpath, [malz]).copy()

                        if not listLdrMod:
                            listLdrMod.update(ldrmod)
                        else:
                            for key in listLdrMod.keys():
                                if key in ldrmod:
                                    listLdrMod[key].extend(ldrmod[key])
                    
                    self.maliciousData['ldrmod'] = listLdrMod
                    
                    ldrModIOC = []

                    # find the wannacry file from the result of ldrmod and store it to dictionary
                    for name in listLdrMod['MappedPath']:
                        if "WannaCry" in name or "WanaDecryptor" in name or name.endswith(".mui") or "Tor" in name:
                            ldrModIOC.append(name)
                    
                    if ldrModIOC:
                        self.maliciousData['iocs']['ldrmod'] = ldrModIOC

                    print("[+] Scanning file objects")
                    filescan = v.run("windows.filescan.FileScan", self.filepath, self.outputpath, []).copy()
                    fileName = filescan['Name']
                    filescanIOC = []
                    self.maliciousData['filescan'] = filescan
                    self.maliciousData['iocs']['wanna_file'] = []

                    # find for wannacry file objects from the result of filescan and store it to dictionary
                    for name in fileName:
                        if "WNCRY" in name or "tor\\lock" in name or ".eky" in name:
                            if "WNCRY" in name:
                                self.maliciousData['iocs']['wanna_file'].append(name)
                            filescanIOC.append(name)
                    
                    if filescanIOC:
                        self.maliciousData['iocs']['filescan'] = filescanIOC
                    
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
                    
                    handleIOC = []
                    self.maliciousData['iocs']['mutex'] = []
                    self.maliciousData['iocs']['wanna_path'] = []
                    
                    # find the malicious handles from the result of handles
                    for name in listHandles['Name']:
                        if name.endswith('.eky') or name.endswith('.WNCRYT'):
                            handleIOC.append(name)
                        if name  == "MsWinZonesCacheCounterMutexA" or name == "MsWinZonesCacheCounterMutexA0":
                            self.maliciousData['iocs']['mutex'].append(name)
                            handleIOC.append(name)
                        if "tor\\lock" in name:
                            self.maliciousData['iocs']['wanna_path'].append(name)
                            handleIOC.append(name)  

                    if handleIOC:
                        self.maliciousData['iocs']['handles'] = handleIOC

                    print("[+] Checking registry. . .")

                    # find the malicious registry key
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
                    
                    # create new directory
                    newdirpath = self.createDirs(self.outputpath, "Exe")

                    print("[+] Start to dump the process")

                    # dump pid
                    for malz in maliciousList:
                        print(f"[+] Dumping process {malz}")
                        v.run("windows.pslist.PsList", self.filepath, newdirpath, [None, malz, True])

                    folder_path = newdirpath
                    file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                    print("[+] Checking file to virus total")
                    count = 1

                    # send dumped file to virustotal
                    for file_name in os.listdir(folder_path):
                        file_path = os.path.join(folder_path, file_name)
                        if os.path.isfile(file_path):
                            for pid in maliciousList:
                                pidstr = str(pid)
                                if pidstr in file_name:
                                    if file_count >= 5:
                                        sleep(16)
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
                    # return dictionay of maliciousData
                    return self.maliciousData
                else:
                    print("[!] File is benign")
                    return None
            except Exception as e:
                print(f"[!] Error : {e} ")
        else:
            print(f"[!] Error: {self.outputpath} file not found")

class StuxNet(MalwareAttributes, UtilitiesMalz):
    """
    A class to analyse Stuxnet Worms

    ...

    Methods
    -------
    run(self)
        Start to hunt Stuxnet Worms and return a dictionary of iocs
    """
    def run(self):
        # Check if filepath is a file
        # if it is not, error
        if os.path.isfile(self.filepath): 
            try:
                # if the outputpath not found, create directory with the path  
                if not os.path.exists(self.outputpath):
                    os.makedirs(self.outputpath)

                infoImage = v.run("windows.info.Info", self.filepath, self.outputpath, []).copy()
                self.maliciousData["info"].update(infoImage)

                pslist = v.run("windows.pslist.PsList", self.filepath, self.outputpath, []).copy()
                pidList = pslist['PID']

                print("[+] Checking duplicate process name")
                # checking the duplicate process name
                dup, indcs = self.checkProcDup(pslist)
                anchestorindcs = [[]]
                malsPid = []

                # if there is duplicate name, get the process name and pid
                # if there is not, stop
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
                    # Loop through proces name and pid
                    for indx, process in enumerate(dup):
                        uniqueList = set(anchestorindcs[indx])
                        sizeListUnique  = len(uniqueList)
                        # if there is parent process csrss, system, wininit, winlogon and explorer.exe, store the pid
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
                            # if the difference of ppid is equal or greater than 2, store the ppid
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

                    # send dumped file to virustotal
                    for file_name in os.listdir(folder_path):
                        file_path = os.path.join(folder_path, file_name)
                        if os.path.isfile(file_path):
                            for pid in pidOfSpoof:
                                pidstr = str(pid)
                                if pidstr in file_name:
                                    if file_count >= 5:
                                        sleep(16)
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

                    # if there is malicious pid, continue to analyze
                    # if there is no malicious pid, stop
                    if malsPid:
                        print("[+] Checking SSDT")
                        ssdt = v.run("windows.ssdt.SSDT", self.filepath, self.outputpath, []).copy()
                        ssdtModule = ssdt['Module']                 
                        self.maliciousData['ssdt'] = ssdt       
                        self.maliciousData['iocs']['ssdt_module'] = []
                        self.maliciousData['iocs']['ssdt_symbol'] = []
                        # find if there is malicious api 
                        for idx, mods in enumerate(ssdtModule):
                            if "PROCMON" in mods and ssdt['Symbol'][idx] != "-":
                                self.maliciousData['iocs']['ssdt_module'].append(mods)
                                self.maliciousData['iocs']['ssdt_symbol'].append(ssdt['Symbol'][idx])


                        print("[+] Checking Callbacks")
                        callbacks = v.run("windows.callbacks.Callbacks", self.filepath, self.outputpath, []).copy()
                        cbModules = callbacks['Module']
                        self.maliciousData['callbacks'] = callbacks
                        cbMalMod = []

                        # find stuxnet modules in callbacks
                        for idx, mod in enumerate(cbModules):
                            if mod == "mrxcls1":
                                cbMalMod.append(mod)
                        
                        if cbMalMod:
                            self.maliciousData['iocs']['callbacks'] = cbMalMod
                        
                        print("[+] Checking Modules")
                        modules = v.run("windows.modules.Modules", self.filepath, self.outputpath, []).copy()
                        self.maliciousData['modules'] = modules
                        modName = modules['Name']
                        listMalMod = []

                        # find all modules that correlated with stuxnet
                        for name in modName:
                            if "mrx" in name:
                                listMalMod.append(name)

                        if listMalMod:
                            self.maliciousData['iocs']['stuxnet_modules'] = listMalMod

                        # dump modules
                        newdirpath = self.createDirs(self.outputpath, "Mod")
                        v.run("windows.modules.Modules", self.filepath, newdirpath, [True])

                        folder_path = newdirpath
                        file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                        print("[+] Checking file to virus total")
                        count = 1

                        self.maliciousData['mod_name'] = []

                        # send dumped file to virustotal
                        for file_name in os.listdir(folder_path):
                            file_path = os.path.join(folder_path, file_name)
                            if os.path.isfile(file_path):
                                print(f"[+] File Name : {file_name} {count}/{file_count}")
                                if not file_name.startswith(".") and "mrx" in file_name:
                                    try:
                                        file_hash = self.getFileHash(file_path)
                                        print(f"Submit VT Progress : {count}/{file_count}")
                                        print(f"\-->[*] File Name : {file_name} ")
                                        ismals, typeMals = self.checksumVT(self.clientAPI, file_hash)
                                        
                                        if ismals and typeMals:
                                            self.maliciousData["mod_name"].append(file_name)
                                            self.maliciousData["mod_mals_types"].append(typeMals)
                                    except Exception as e:
                                        print(e)
                                count += 1
                        
                        newdirpath = self.createDirs(self.outputpath, "Mal")

                        print("[+] Dumping injected code")

                        # dump malfind with the malicious pid
                        for pid in malsPid:
                            print(f"Dumping {pid}")
                            v.run("windows.malfind.Malfind", self.filepath, newdirpath, [pid, True])
                    
                    # return dictionay of maliciousData
                    return self.maliciousData
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
    """
    A class to analyse Shell Trojan

    ...

    Methods
    -------
    run(self)
        Start to hunt Metasploit trojan shell and return a dictionary of iocs
    """
    def run(self):
        # Check if filepath is a file
        # if it is not, error
        if os.path.isfile(self.filepath):
            try:
                # if the outputpath not found, create directory with the path 
                if not os.path.exists(self.outputpath):
                    os.makedirs(self.outputpath)

                infoImage = v.run("windows.info.Info", self.filepath, self.outputpath, []).copy()
                self.maliciousData["info"].update(infoImage)
                
                print("[+] Running Malfind plugin")
                malfind = v.run("windows.malfind.Malfind", self.filepath, self.outputpath, []).copy()

                # get all pid in malfind
                malPidList = list(set(malfind['PID']))
                
                # dump injected code

                newdirpath = self.createDirs(self.outputpath, "Mal")
                
                malfind = v.run("windows.malfind.Malfind", self.filepath, newdirpath, [])
                self.maliciousData['malfind'] = malfind

                # dump the pid in malpidlist
                for pid in malPidList:
                    print(f"Dumping pid {pid}")
                    v.run("windows.malfind.Malfind", self.filepath, newdirpath, [pid, True])

                folder_path = newdirpath
                file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                print("[+] Checking file to virus total")

                maliciousPidList = []
                count = 1

                # send dumped file to virustotal
                for file_name in os.listdir(folder_path):
                    file_path = os.path.join(folder_path, file_name)
                    if os.path.isfile(file_path):
                        for pid in malPidList:
                            pidstr = str(pid)    
                            if pidstr in file_name:
                                if file_count >= 5:
                                    sleep(16)
                                if not file_name.startswith("."):
                                    file_hash = self.getFileHash(file_path)
                                    print(f"Submit VT Progress : {count}/{file_count}")
                                    print(f"\-->[*] File Name : {file_name} ")
                                    ismal, typemalz = self.checksumVT(self.clientAPI, file_hash)
                                    count +=1 

                                    if ismal:
                                        if pidstr not in self.maliciousData['pid']:
                                            maliciousPidList.append(pid)
                                            self.maliciousData['pid'].append(pid)
                                            self.maliciousData['malware_types'].append(typemalz)
                                            self.maliciousData['injected_code'].append(file_name)

                # if there is malicious pid, continue analyse
                # if there is no malicious pid, stop
                if maliciousPidList:
                    # yang hit dari vt = 704, 3732
                    # maliciousPidList = [704, 3732]
                    idxChild = []

                    pslist = v.run("windows.pslist.PsList", self.filepath, self.outputpath, []).copy()
                    listPPID = pslist['PPID']
                    lenlistPPID = len(listPPID)
                    pidPsList = pslist['PID']
                    malzChildPid = []

                    print("[+] Get child")
                    
                    # get child process from the pid
                    for pid in maliciousPidList:
                        temp = self.getChild(pslist, pid)
                        idxChild += temp

                    idxChild = list(set(idxChild))

                    print("[+] Get child pid from pslist")
                    for idx in idxChild:
                        pid = pidPsList[idx]
                        malzChildPid.append(pid)
                        maliciousPidList.append(pid)

                    # if there is child, store pid
                    if malzChildPid:
                        self.maliciousData['reverse_shell'] = malzChildPid

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

                    # find process that is child process from anchestor
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
                    
                    maliciousPidList += ppidList
                    uniqueMalList = list(set(maliciousPidList))
                    self.maliciousData["sus_pid"] = uniqueMalList

                    newdirpath = self.createDirs(self.outputpath, "Exe")

                    # dump pid
                    for mal in uniqueMalList:
                        v.run("windows.pslist.PsList", self.filepath, newdirpath, [False, mal, True])

                    folder_path = newdirpath
                    file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                    print("[+] Checking file to virus total")

                    hitPid = []

                    # send file to virustotal
                    for file_name in os.listdir(folder_path):
                        file_path = os.path.join(folder_path, file_name)
                        if os.path.isfile(file_path):
                            for pid in uniqueMalList:
                                pidstr = str(pid)
                                if pidstr in file_name:    
                                    if file_count >= 5:
                                        sleep(16)
                                    if not file_name.startswith("."):
                                        file_hash = self.getFileHash(file_path)
                                        print(f"\-->[*] File Name : {file_name} ")
                                        ismal, typemalz = self.checksumVT(self.clientAPI, file_hash)

                                        if ismal:
                                            hitPid.append(pid)
                                            if pidstr not in self.maliciousData['pid']:
                                                self.maliciousData['pid'].append(pid)
                                                self.maliciousData['malware_types'].append(typemalz)
                                                self.maliciousData['exe_name'].append(file_name)
                    
                    # if there is malicious pid, continue analysis
                    # if there is no malicious pid, stop
                    if hitPid:
                        print("[+] Volatility Analysis")

                        print("[+] Checking Network Connections")

                        netscan = v.run("windows.netscan.NetScan", self.filepath, newdirpath, []).copy()
                        netPort = netscan['ForeignPort']
                        netStat = netscan['State']
                        netForeign = netscan['ForeignAddr']
                        metas_port_idx = 0

                        print("[+] Checking Foreign Port")
                        # check if there is default port from metasploit and store port, tcp_state and foreignaddress to dictionary
                        for idx, port in enumerate(netPort):
                            if port == 4444:
                                metas_port_idx = idx
                        if metas_port_idx:
                            metas_port = netPort[metas_port_idx]
                            metas_state = netStat[metas_port_idx]
                            metas_connectAddr = netForeign[metas_port_idx]

                            self.maliciousData['metas_port'] = metas_port
                            self.maliciousData['metas_tcp_state'] = metas_state
                            self.maliciousData['metas_connect'] = metas_connectAddr
                        
                        print("[+] Checking Foreign Address")

                        # if there is hit pid from 
                        maliciousIp = self.checkNetwork(netscan, self.clientAPI)

                        if maliciousIp:
                            self.maliciousData['ipv4'] = maliciousIp
                
                # return dictionay of maliciousData
                return self.maliciousData

            except Exception as e:
                print(f"[!] Error : {e}")
        else:
            print(f"[!] Error: {self.outputpath} file not found")

class WannaCryV2(MalwareAttributes, UtilitiesMalz):
    """
    A class to analyse WannaCry Ransomware

    ...

    Methods
    -------
    run(self)
        Start to hunt WannaCry Ranswomare and return a dictionary of iocs
    """
    def run(self):
        # Check if filepath is a file
        # if it is not, error
        if os.path.isfile(self.filepath):
            try:
                # if the outputpath not found, create directory with the path 
                if not os.path.exists(self.outputpath):
                    os.makedirs(self.outputpath)

                infoImage = v.run("windows.info.Info", self.filepath, self.outputpath, []).copy()
                self.maliciousData["info"].update(infoImage)

                pslist = v.run("windows.pslist.PsList", self.filepath, self.outputpath, []).copy()
                pscopy = pslist
                pslistName = pslist['ImageFileName']
                pslistPpid = pscopy['PPID']
                susIdx = []
                susPidList = []

                print("[+] Find @WanaDecryptor")
                # find signature files of wannacry and store the pid and index
                for idx, name in enumerate(pslistName):
                    if "@WanaDecryptor" in name:
                        susIdx.append(idx)
                        self.maliciousData['pid'].append(pslist['PID'][idx])
                        susPidList.append(pslist['PID'][idx])
                        self.maliciousData['process_name'].append(pslist['ImageFileName'][idx])
                
                isParent = True
                
                # get child
                for idx in susIdx:
                    pid = pslist['PID'][idx]
                    # find child
                    while isParent:
                        if pid in pslistPpid:
                            idx = pslistPpid.index(pid)
                            pid = pslist['PID'][idx]
                            susPidList.append(pid)
                            susIdx.append(idx)
                            pslistPpid[idx] = 0
                        else:
                            isParent = False

                # get parent
                ppidList = []
                notOrphan = True
                tempIdx = []

                print("[+] Find the parent")
                for idx in susIdx:
                    ppid = pslist["PPID"][idx]
                    
                    if ppid in pslist["PID"]:
                        while notOrphan:
                            if ppid in pslist["PID"]:
                                if ppid not in susPidList:
                                    ppidList.append(ppid)
                                pidTemp = ppid
                                pidIdx = pslist["PID"].index(pidTemp)
                                if pidIdx not in susIdx:
                                    tempIdx.append(pidIdx)
                                ppid = pslistPpid[pidIdx]
                            else:
                                notOrphan = False
                    else:
                        continue
                
                susIdx += tempIdx
                susPidList += ppidList

                print("[+] Finding Process that using SMB Port")
                netscan = v.run("windows.netscan.NetScan", self.filepath, self.outputpath, [])
                foreignPort = netscan['ForeignPort']
                netPid = netscan['PID']
                netOwner = netscan['Owner']
                
                # finding port 445 in network
                for idx, port in enumerate(foreignPort):
                    if port == 445:
                        pid = netPid[idx]
                        self.maliciousData['smb_port'] = port
                        if pid not in self.maliciousData['pid']:
                            self.maliciousData['process_name'].append(netOwner[idx])
                            self.maliciousData['pid'].append(pid)
                            self.maliciousData['smb_pid'] = pid
                            pslistPidIdx = pslist['PID'].index(pid)
                            susPidList.append(pid)
                            susIdx.append(pslistPidIdx)

                # create new dirpath
                newdirpath = self.createDirs(self.outputpath, "Exe")

                # dump all suspid
                print("[+] Dumping sus process")
                for pid in susPidList:
                    print(f"[*] Dumping {pid}")
                    v.run("windows.pslist.PsList", self.filepath, newdirpath, [False, pid, True])

                folder_path = newdirpath
                file_count = len([name for name in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, name))])
                print("[+] Checking file to virus total")

                maliciousPidList = []
                count = 1

                # send dumped file to virustotal
                for file_name in os.listdir(folder_path):
                    file_path = os.path.join(folder_path, file_name)
                    if os.path.isfile(file_path):
                        for pid in susPidList:
                            pidstr = str(pid)    
                            if pidstr in file_name:
                                if file_count >= 5:
                                    sleep(16)
                                if not file_name.startswith("."):
                                    file_hash = self.getFileHash(file_path)
                                    print(f"Submit VT Progress : {count}/{file_count}")
                                    print(f"\-->[*] File Name : {file_name} ")
                                    ismal, typemalz = self.checksumVT(self.clientAPI, file_hash)
                                    count +=1 

                                    if ismal:
                                        maliciousPidList.append(pid)
                                        self.maliciousData['pid'].append(pid)
                                        self.maliciousData['malware_types'].append(typemalz)
                                        self.maliciousData['exe_name'].append(file_name)
                                    
                                break
                
                # if there is malicious pid, continue analysis
                # if there is no malicious pid, stop
                if maliciousPidList:
                    psscan = v.run("windows.psscan.PsScan", self.filepath, self.outputpath, []).copy()

                    scanPPID = psscan["PPID"]
                    lenPPIDList = len(scanPPID)
                    hiddenPIDScan = []

                    # check if there is process with ppid in maliciousList and store the pid
                    for idx in range(lenPPIDList):
                        if scanPPID[idx] in maliciousPidList:
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

                    # Analyze pid in maliciousList with cmdline plugin
                    for malz in maliciousPidList:
                        cmdline = v.run("windows.cmdline.CmdLine", self.filepath, self.outputpath, [malz]).copy()
                        
                        if not listCMD:
                            listCMD.update(cmdline)
                        else:
                            for key in listCMD.keys():
                                if key in cmdline:
                                    listCMD[key].extend(cmdline[key])
                    
                    self.maliciousData["dict_cmdline"] = listCMD
                    print("[+] Getting all DLL from malicious process. . .")

                    # Analyze pid in maliciousList with dlllist plugin
                    for malz in maliciousPidList:
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
                    for malz in maliciousPidList:
                        ldrmod = v.run("windows.ldrmodules.LdrModules", self.filepath, self.outputpath, [malz]).copy()

                        if not listLdrMod:
                            listLdrMod.update(ldrmod)
                        else:
                            for key in listLdrMod.keys():
                                if key in ldrmod:
                                    listLdrMod[key].extend(ldrmod[key])

                    self.maliciousData['ldrmod'] = listLdrMod

                    ldrModIOC = []
                    # find the wannacry file from the result of ldrmod and store it to dictionary
                    for name in listLdrMod['MappedPath']:
                        if "WannaCry" in name or "WanaDecryptor" in name or name.endswith(".mui") or "Tor" in name:
                            ldrModIOC.append(name)
                    
                    if ldrModIOC:
                        self.maliciousData['iocs']['ldrmod'] = ldrModIOC
                    
                    print("[+] Scanning file objects")
                    filescan = v.run("windows.filescan.FileScan", self.filepath, self.outputpath, [])
                    fileName = filescan['Name']
                    filescanIOC = []
                    self.maliciousData['filescan'] = filescan
                    self.maliciousData['iocs']['wanna_file'] = []

                    # find for wannacry file objects from the result of filescan and store it to dictionary
                    for name in fileName:
                        if "WNCRY" in name or "tor\\lock" in name or ".eky" in name:
                            if "WNCRY" in name:
                                self.maliciousData['iocs']['wanna_file'].append(name)
                            filescanIOC.append(name)
                    
                    if filescanIOC:
                        self.maliciousData['iocs']['filescan'] = filescanIOC
                    
                    print("[+] Getting all handles from malicious process. . .")

                    for malz in maliciousPidList:
                        handles = v.run("windows.handles.Handles", self.filepath, self.outputpath, [malz]).copy()

                        if not listHandles:
                            listHandles.update(handles)
                        else:
                            for key in listHandles.keys():
                                if key in handles:
                                    listHandles[key].extend(handles[key])

                    self.maliciousData["dict_handles"] = listHandles
                    
                    handleIOC = []
                    self.maliciousData['iocs']['mutex'] = []
                    self.maliciousData['iocs']['wanna_path'] = []
                    
                    # find the malicious handles from the result of handles
                    for name in listHandles['Name']:
                        if name.endswith('.eky') or name.endswith('.WNCRYT'):
                            handleIOC.append(name)
                        if name  == "MsWinZonesCacheCounterMutexA" or name == "MsWinZonesCacheCounterMutexA0":
                            self.maliciousData['iocs']['mutex'].append(name)
                            handleIOC.append(name)
                        if "tor\\lock" in name:
                            self.maliciousData['iocs']['wanna_path'].append(name)
                            handleIOC.append(name)  

                    if handleIOC:
                        self.maliciousData['iocs']['handles'] = handleIOC

                    print("[+] Checking registry. . .")
                    # find the malicious registry key
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

                # return dictionay of maliciousData
                return self.maliciousData
                    
            except Exception as e:
                print(f"[!] Error : {e}")