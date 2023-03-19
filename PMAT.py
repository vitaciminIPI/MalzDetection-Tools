import getopt
import sys
import hashlib
from getpass import getpass
import requests
import json

ARG1 = 0
ARG2 = False
isValidArgs = True
FILE_PATH = ""
CHECKSUM = False
ORIGINAL_HASH = "2C6D5BE488B96BB2D055D73B6CC8315531BAA927CEFDC4129935F08B60F2A71C"
MY_API = "3e7b7c1801535998c249f13d8bfe6b5739ffbc1eaeb4ffe26341f46812d4041e"

def getHelp():
    print("This is help message")
    sys.exit()
    
# check argument lenght
def checkArgs(args):
    global isValidArgs
    if len(args) < 1:
        print("Error")
        isValidArgs = False

def getFileHash(pathFile):
    try:
        with open(pathFile, 'rb') as f:
            data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            sha1 = hashlib.sha1(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()
            return md5, sha1, sha256
    except FileNotFoundError as e:
        print(e)
        return ""

def getArgument():
    global ARG1, ARG2, CHECKSUM, isValidArgs, FILE_PATH
    
    try:
        args,_ = getopt.getopt(sys.argv[1:], "hc:bC:", ["help", "count=", "bool", "checksum="])
        checkArgs(args)
        for key, val in args:
            if key in ["-h", "--help"]:
                getHelp()
            elif key in ["-c", "--count"]:
                ARG1 = val
            elif key == "-b" or key == "--bool":
                ARG2 = True
            elif key in ["-C", "--checksum"]:
                CHECKSUM = True
                FILE_PATH = val
    except Exception:
        isValidArgs = False
        print("Error")
        getHelp()

def checksumVT(fileHash, clientAPIKey):
    # Inject Ransomware hash
    inject_hash = "07c44729e2c570b37db695323249474831f5861d45318bf49ccf5d2f5c8ea1cd"
    # print(clientAPIKey)
    if clientAPIKey:
        try:
            print("\\-->[*] SHA256 SUM : " + fileHash)
            url = "https://www.virustotal.com/api/v3/files/" + inject_hash
            # print(url)
            headers = {
                'x-apikey' : clientAPIKey
            }
            response = requests.get(url, headers=headers)
            responseCode = response.status_code
            json_resp = json.loads(response.text)

            if responseCode == 200:
                print("//--> [*] Malicious : " + str(json_resp['data']['attributes']['last_analysis_stats']['malicious']) + " %")
                print("//--> [*] Harmless : " + str(json_resp['data']['attributes']['last_analysis_stats']['harmless']) + " %")
                print("//--> [*] Undetected : " + str(json_resp['data']['attributes']['last_analysis_stats']['undetected']) + " %")
                print("//--> [*] Suspicious : " + str(json_resp['data']['attributes']['last_analysis_stats']['suspicious']) + " %")
                print("//--> [*] Failure : " + str(json_resp['data']['attributes']['last_analysis_stats']['failure']) + " %")
                print("//--> [*] Timeout : " + str(json_resp['data']['attributes']['last_analysis_stats']['timeout']) + " %")
                print("//--> [*] Confirmed-Timeout : " + str(json_resp['data']['attributes']['last_analysis_stats']['confirmed-timeout']) + " %")
                print("//--> [*] Type-Unsupported : " + str(json_resp['data']['attributes']['last_analysis_stats']['type-unsupported']) + " %")
            else:
                print("\\--> [!] Error")
                print(json_resp['error']['message'])

        except ConnectionError as e:
            print("[!] Something's went wrong")
            print(e)
    else:
        print('[!] Please input your VirusTotal API key!')
        sys.exit()


def main():
    getArgument()
    if not isValidArgs:
        sys.exit()
    else:
        if CHECKSUM :
            print("[!] Getting File Hashes. . .")
            md5Hash, sha1Hash, sha256Hash = getFileHash(FILE_PATH)
            print("\\--> [*] MD5 : " + md5Hash)
            print("\\--> [*] SHA-1 : " + sha1Hash)
            print("\\--> [*] SHA-256 : " + sha256Hash)
            isContinueToVt = input('Do you want to check in VirusTotal? [N|Y] ')

            if isContinueToVt.upper() == 'Y':
                clientAPIKey = getpass("Enter Your API Key: ")
                print('[*] Forwarding to VirusTotal...')
                checksumVT(sha256Hash, clientAPIKey)
            else:
                sys.exit()

if __name__ == "__main__":
    main()