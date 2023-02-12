from colorama import Fore, Back, Cursor, init #install pip 
import argparse #install pip 
import requests
import datetime
import time
import json
import os

init(autoreset=True)

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="enable verbosity", action="store_true")
# parser.add_argument("--analysis", help="get scan results", action="store_true")
parser.add_argument("--scan", help="scan a file option", action ="store_true")
parser.add_argument("--apikey", help="Your Apikey by Virus Total Scaner")
parser.add_argument("-f", "--file", help="especific a filename")
argument = parser.parse_args()

# DEFINE FUNCTIONS 

def print_analysis_results(analysis):
    """
    Prints the data from the parsed file

    @params analysis: get json file from analysis (JSON FILE)
    """

    data = dict(analysis)
    timestamp = data["data"]["attributes"]["date"] #timestamp
    time = datetime.datetime.fromtimestamp(timestamp) #time formated
    attributes = data["data"]["attributes"] 
    stats = attributes["stats"]

    print(Cursor.FORWARD(30) + Fore.CYAN +'-'*10 + "File analysed" + '-'*10)
    print(Fore.CYAN + "Datetime: " + time.strftime('%Y-%m-%d %H:%M:%S'))

    if attributes["status"] == "completed":
        print("-"*20+"\n")
        print(Fore.CYAN + "Status: " + attributes["status"] + "\n")

    print(Fore.RED + f"Type: " + data["data"]["type"] +"\n")
    
    
    for stat in stats:
        if stat == "suspicious" and stats["suspicious"] > 0:
            print(Fore.YELLOW + "[!]" + " Indicators of suspicion of active malware\n")
            print(Fore.YELLOW + f"\t{stat} : {stats[stat]}\n")
            continue

        elif stat == "malicious" and stats["malicious"] > 0:
            print(Fore.RED + "[!]" + " Active Malware Indicators\n")
            print(Fore.RED + f"\t{stat} : {stats[stat]}\n")
            continue


        print(Fore.GREEN + f"\t{stat} : {stats[stat]}\n")

def request_analysis_results(filename, apikey):  
    """
    open a file and return analysis results.
    @param filename: the file if it exists
    @param apikey: get the api key to work
        
    @return: return an analysis in json format
    """
    
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "accept": "application/json",
        "X-Apikey": apikey
    }
    files = {"file": (filename, open(filename, "rb"))}
    response = requests.post(url, files=files, headers=headers)
    json_data = json.loads(response.text)
    return json_data


def analysis_file(identificator, apikey):
    """
    get the data in json format to process the data.
    
    @param identificator: unique analysis identificatorentifier of the processed file
    @param apikey: get the api key to work
    
    @return: return json analysis from identificator file
    """
    
    url = "https://www.virustotal.com/api/v3/analyses/"
    headers = {"accept": "application/json",
        "X-Apikey": apikey}
    response = requests.get(url + identificator, headers=headers)
    json_analysis = json.loads(response.text)
    if json_analysis["data"]["attributes"]["status"] == "completed":
        return json_analysis
    else:
        analysis_file(identificator, apikey)
        time.sleep(1)
    
# ARGS PARSING PRINCIPAL SCRIPT 

if not any(arg for arg in [argument.scan, argument.file]):
    print("not option selected")

if not argument.apikey:
    print("\nError: No such apikey, please insert you'r apikey or get a api in https://www.virustotal.com\n\n")

if argument.scan and argument.file and argument.apikey:
    if os.path.exists(argument.file) and os.path.isfile(argument.file):
        #return analysis JSON
        data = request_analysis_results(argument.file, argument.apikey)
        #return JSON analysis from identificator
        analysis = analysis_file(data["data"]["id"], argument.apikey)
        # results = get_analysis_by_complete_status(analysis)
        print_analysis_results(analysis)
    
    else:
        print("no such file exists or file no valid id")
