import netaddr
import subprocess
import sys
import re
from os import system
import time
from colorama import Fore
from abuseipdb import AbuseIPDB


#============ API KEY  ===============#
abuse = AbuseIPDB(apikey='')


#========== GLOBAL VARS ==============#

# list to store the ip connections in case of detailed output
id_list = []

# variable to store the IP to add to ip2check
ip2add = ''

# list to store all the IPs to check against AbusedIPDB
ip2check = []

# regex rule to filter IPv4 addresses
regex_IPv4 = '(?<![-\\.\\d])(?:0{0,2}?[0-9]\\.|1\\d?\\d?\\.|2[0-5]?[0-5]?\\.){3}(?:0{0,2}?[0-9]|1\\d?\\d?|2[0-5]?[0-5]?)(?![\\.\\d])'


#======== FUNCTION SECTION ===========#

# function to scan the netres.txt file
def scanFile():
    global id_list
    with open('netres.txt', encoding='utf-8') as netres:

        # getting the lines from the file
        lines = netres.readlines()
        print("\nACTIVE CONNECTIONS: {}\n".format(len(lines)-3))
        cnt = 0

        # starting from 4 to remove the headers
        for line in range(4,len(lines)):
            
            tmp_list = lines[line].split()

            # handling the case where there is an IPv6 address
            if tmp_list[2].startswith('['):
                continue
            ip = tmp_list[2].split(':', 1)[0]
            # checking if the ip is private, loopback or not IPv4
            if netaddr.IPAddress(ip).is_private() or netaddr.IPAddress(ip).is_loopback() or netaddr.IPAddress(ip).version != 4:
                continue
            else:
                cnt += 1
                id_list.append(lines[line].split())

# function to output the details of all the active external connections and  populate ip2check list
def printResVerb():
    global ip2add, ip2check
    print('\n' + '-' * 15 + 'LISTING DETAILS' + '-' * 14)
    for id in range(0,len(id_list)):
        print("ID {}".format(id+1))
    
        print('Protocol: {}'.format(id_list[id][0]))
        print('Local IP-PORT: {}'.format(id_list[id][1]))
        print('External IP-PORT: {}'.format(id_list[id][2]))
        
        ip2add = id_list[id][2].split(':', 1)[0]
        ip2check.append(ip2add)
        print('Status: {}'.format(id_list[id][3]))
        print("\n------------------\n")
    # print(ip2check)

# function that only populate ip2check list
def printRes():
    global ip2add, ip2check
    for id in range(0,len(id_list)):
        ip2add = id_list[id][2].split(':', 1)[0]
        ip2check.append(ip2add)

# function that does the checking job of IPs against AbusedIPDB
def checkConn():
    global ip2check
    ip2check = list(set(ip2check))
    for ip in range(0,len(ip2check)):
        q = abuse.check(ipAddress=ip2check[ip], maxAgeInDays=90)

        # calling a dedicated print function to print the results
        printIP(ip2check[ip], q)

# function that prints the results from AbusedIPDB
def printIP(ip, abuse_res):
    stat = ''
    print('\n Results for IP ' + ip)
    print('- IP: ' + abuse_res.ipAddress)
    print('- Public: ' + str(abuse_res.isPublic))
    print('- Whitelisted: ' + str(abuse_res.isWhitelisted))
    
    '''
        Using ANSI escape sequence to color the advice output:
        - Good: 0 - 30 > green '\033[92m <string> \033[00m'
        - Maybe check it: 30 - 50 > cyan '\036[92m <string> \033[00m'
        - Check it: 50 - 60 > yellow '\033[923m <string> \033[00m'
        - Absolutely check it!: 60 - 100 > red '\033[91m <string> \033[00m'
    '''
    
    if abuse_res.abuseConfidenceScore > 30 and abuse_res.abuseConfidenceScore < 50:
        # cyan
        stat = '\033[96m[Maybe check it]\033[00m'
    
    elif abuse_res.abuseConfidenceScore > 50 and abuse_res.abuseConfidenceScore < 60:
        # yellow
        stat = '\033[93m[Check it]\033[00m'
    
    elif abuse_res.abuseConfidenceScore > 60:
        # red
        stat = '\033[91m[Absolutely check it!]\033[00m'
    
    else:
        # green
        stat = '\033[92m[Good]\033[00m'

    print('- Abuse score: ' + str(abuse_res.abuseConfidenceScore) +' ' + stat)
    print('- Total reports: ' + str(abuse_res.totalReports))
    try:
        print('- Last report: ' + abuse_res.lastReportedAt)
    except:
        print('- Last report: never')
    print('- Usage type: ' + abuse_res.usageType)
    print('[!] Other info [!]')
    print('- Domain: ' + abuse_res.domain)
    print('- Country code: ' + abuse_res.countryCode)
    print('- Country name: ' + abuse_res.countryName)
    print('- ISP: ' + abuse_res.isp)

# function that simply output an introduction message
def greetings():
    _ = system('cls')
    print('\nWelcome to NetFier.\nNetFier is programmed to check your connections against AbusedIPDB to see if any of them is suspicious.\n\n- Author: Andrea Grigoletto - Wirzka\n- Github: https://github.com/wirzka\n- NetFier Repo: https://github.com/wirzka/netfier')

# main function
def main():
    p = subprocess.Popen('netstat -n > netres.txt', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    # out, err = p.communicate()
    p.communicate()
    # ouput the intro message
    greetings()
    # scan the txt file containing the IPs
    scanFile()

    # asking to the user if output verbousity is wanted or not
    ask = input('Do you want to see all the details of the active external connections? \033[92my\033[00m / \033[91mn\033[00m')
    if ask.lower() == 'y':
        printResVerb()
    else:
        printRes()
    
    # checking IPs against AbusedIPDB and printing the resultss
    print('\n' + '-' * 15 + 'LISTING RESULTS FROM AIPDB' + '-' * 14)
    checkConn()
    
    print('\033[94m\n\n[!] Be Aware:\n\
|   AbusedIPDB and other tools like it are useful to gain some infos on IPs\n\
|   e.g.: suspicious, behaviour, domain details, etc\n\
|   BUT you should be careful to block IP or take some actions just by reviewing a score.\n\
[!] Go deeper, get more intel and then take some actions, maybe.\033[00m\n')

#========= END FUNCTION SECTION =======#

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[91m[!] You have interrupted the stuff with your keyboard, bye. [!]\033[00m")
        time.sleep(3)
        sys.exit(0)
    
