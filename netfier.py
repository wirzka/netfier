'''
    netfier.py - Python 3.7.3
    Author: wirzka
    E-mail: wiirzka@gmail.com
    Git: https://github.com/wirzka
    Description:
        I wrote this tool just for educational purpose.
        Netfier is a simple tool to check if the machine's connections are
        malicious/suspicious, so if they require deeper investigation.
        For this job, at this moment the script uses AbusedIPDB.
    Requirements:
        - Python version: 3.7
        - AbusedIPDB profile for the API KEY
        - AbusedIpDB by @vsecades: https://github.com/vsecades/AbuseIpDb
'''
#starwars #speed #slant #sblood
import netaddr
import subprocess
import sys
import re
from os import system
import time
import pprint
from colorama import Fore
from abuseipdb import AbuseIPDB
from art import *

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

# dictionary for final statistics
stat_dict = {
    "Good" : 0,
    "Maybe check it" : 0,
    "Check it" : 0,
    "Absolutely check it!" : 0
}


#========= CLASS SECTION =============#
class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

#======== FUNCTION SECTION ===========#

# function to scan the netres.txt file
def scanFile():
    global id_list
    with open('netres.txt', encoding='utf-8') as netres:

        # getting the lines from the file
        lines = netres.readlines()
        print(color.BOLD + color.YELLOW + '\nTOTAL ACTIVE CONNECTIONS:' + color.END + ' {}\n'.format(len(lines)-3))
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
    print('\033[92m\n' + '-' * 15 + 'VERBOSE MODE ACTIVATED' + '-' * 14 + '\033[00m')
    for id in range(0,len(id_list)):
        print(color.PURPLE + color.BOLD + "{:<15s}".format('ID ' + str(id+1) + color.END))
        print(color.BOLD + '{:<18s}'.format('Protocol:') + color.END + '{:<24s}'.format(id_list[id][0]))
        print(color.BOLD + '{:<18s}'.format('Local IP-PORT:') + color.END + '{:<24s}'.format(id_list[id][1]))
        print(color.BOLD + '{:<18s}'.format('External IP-PORT:') + color.END + '{:<24s}'.format(id_list[id][2]))
        print(color.BOLD + '{:<18s}'.format('Status:') + color.END + '{:<24s}\n'.format(id_list[id][3]))

        ip2add = id_list[id][2].split(':', 1)[0]
        ip2check.append(ip2add)

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
         
    if abuse_res.abuseConfidenceScore > 30 and abuse_res.abuseConfidenceScore < 50:
        # cyan
        stat = color.CYAN + '[Maybe check it]' + color.END
        stat_dict["Maybe check it"] += 1
    
    elif abuse_res.abuseConfidenceScore > 50 and abuse_res.abuseConfidenceScore < 60:
        # yellow
        stat = color.YELLOW + '[Check it]' + color.END
        stat_dict["Check it"] += 1

    elif abuse_res.abuseConfidenceScore > 60:
        # red
        stat = color.RED + '[Absolutely check it!]' + color.END
        stat_dict["Absolutely check it!"] += 1

    else:
        # green
        stat = color.GREEN + '[Good]' + color.END
        stat_dict["Good"] += 1
        
    print(color.BOLD + color.PURPLE + '\n Results for IP ' + ip + color.END)
    print(color.BOLD + '{:<18s}'.format('- IP') + color.END + '{:<30}'.format(abuse_res.ipAddress))
    print(color.BOLD + '{:<18s}'.format('- Public:') + color.END + '{:<30}'.format(str(abuse_res.isPublic)))
    print(color.BOLD + '{:<18s}'.format('- Whitelisted:') + color.END + '{:<30}'.format(str(abuse_res.isWhitelisted)))
    try:
        print(color.BOLD + '{:<18s}'.format('- Abuse score:') + color.END + '{:<30}'.format(str(abuse_res.abuseConfidenceScore) + ' ' + stat))
    except:
        print(color.BOLD + '{:<18s}'.format('- Abuse score:') + color.END + '{:<30}'.format('N/D'))
    try:
        print(color.BOLD + '{:<18s}'.format('- Total reports:') + color.END + '{:<30}'.format(str(abuse_res.totalReports)))
    except:
        print(color.BOLD + '{:<18s}'.format('- Total reports:') + color.END + '{:<30}'.format(' N/D'))
    try:
        print(color.BOLD + '{:<18s}'.format('- Last report:') + color.END + '{:<30}'.format(abuse_res.lastReportedAt))
    except:
        print(color.BOLD + '{:<18s}'.format('- Last report:') + color.END + '{:<30}'.format('never'))
    try:
        print(color.BOLD + '{:<18s}'.format('- Usage type:') + color.END + '{:<30}'.format(abuse_res.usageType))
    except:
        print('{:<18s}'.format('- Usage type:') + '{:<30}'.format('N/D'))

    print(color.BOLD + '[!] Other info [!]' + color.END)
    try:
        print(color.BOLD + '{:<18s}'.format('- Domain:') + color.END + '{:<30}'.format(abuse_res.domain))
    except:
        print(color.BOLD + '{:<18s}'.format('- Domain:') + color.END + '{:<30}'.format(' N/D'))
    try:
        print(color.BOLD + '{:<18s}'.format('- Country code:') + color.END + '{:<30}'.format(abuse_res.countryCode))
    except:
        print(color.BOLD + '{:<18s}'.format('- Country code:') + color.END + '{:<30}'.format(' N/D'))
    try:
        print(color.BOLD + '{:<18s}'.format('- Country name:') + color.END + '{:<30}'.format(abuse_res.countryName))
    except:
        print(color.BOLD + '{:<18s}'.format('- Country name:') + color.END + '{:<30}'.format(' N/D'))
    try:
        print(color.BOLD + '{:<18s}'.format('- ISP:') + color.END + '{:<30}'.format(abuse_res.isp))
    except:
        print(color.BOLD + '{:<18s}'.format('- ISP:') + color.END + '{:<30}'.format(' N/D'))

# function that generate the connections' statistics
def stats():
    print('\n\n' + color.GREEN + color.BOLD + '-' * 10 + 'CONNECTIONS\' STATS' + '-' * 10 + '\n')
    for key, value in stat_dict.items():
        if key == 'Absolutely check it!':
            print(color.RED + color.BOLD + '{:<22s}:'.format(key) + color.END + '{:>3}'.format(value))
        elif key == 'Check it':
            print(color.YELLOW + color.BOLD + '{:<22s}:'.format(key) + color.END + '{:>3}'.format(value))
        elif key == 'Maybe check it':
            print(color.CYAN + color.BOLD + '{:<22s}:'.format(key) + color.END + '{:>3}'.format(value))
        elif key == 'Good':
            print(color.GREEN + color.BOLD + '{:<22s}:'.format(key) + color.END + '{:>3}'.format(value))
        else:
            print("Wtf")
            sys.exit(0)

# function that simply output an introduction message
def greetings():
    _ = system('cls')
    print(color.GREEN + color.BOLD)
    tprint("Netfier",font="starwars")
    print(color.END)
    print('\033[92mWelcome to NetFier.\n\
Netfier checks your connections against AbuseIPDB looking for any suspicious IP.\n\033[00m \
        \n\n- \033[92mAuthor\033[00m: Andrea Grigoletto - Wirzka\
        \n- \033[92mGithub\033[00m: https://github.com/wirzka\
        \n- \033[92mNetFier Repo\033[00m: https://github.com/wirzka/netfier')

# function that toggle the disclaimer
def disclaimer():
    print('\033[93m\n\n[!] Be Aware:\033[00m\n\
\033[93m|\033[00m\033[94m If you get all good scores and confidence, it doesn\'t mean that there are only good connections.\033[00m\n\
\033[93m|\033[00m\033[94m It means that the current connections are not identified as suspicious on AbuseIPDB!\033[00m\n\
\033[93m|\033[00m \n\
\033[93m|\033[00m\033[94m AbuseIPDB and other tools like it are useful to gain some infos on IPs\033[00m\n\
\033[93m|\033[00m\033[94m e.g.: suspicious, behaviour, domain details, etc\033[00m\n\
\033[93m|\033[00m\033[94m BUT you should be careful to block IP or take some actions just by reviewing a score.\033[00m\n\
\033[93m|\033[00m\033[94m Go deeper, get more intel and then take some actions, maybe.\033[00m\n\
\033[93m[!]\033[00m')

# main function
def main():
    # ouput the intro message
    greetings()

    p = subprocess.Popen('netstat -n > netres.txt', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    # out, err = p.communicate()
    p.communicate()
    
    # scan the txt file containing the IPs
    scanFile()

    # asking to the user if output verbosity is wanted or not
    ask = input('Do you want to see all the details of the active external connections? \033[92my\033[00m / \033[91mn\033[00m ')
    if ask.lower() == 'y':
        printResVerb()
    else:
        printRes()
    
    # checking IPs against AbusedIPDB and printing the resultss
    print('\033[92m\n' + '-' * 15 + 'LISTING RESULTS FROM AIPDB' + '-' * 14 +'\033[00m')
    checkConn()
    
    # printing statistics infos
    stats()
    
    # printing disclaimer
    disclaimer()

#========= END FUNCTION SECTION =======#

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[91m[!] You have interrupted the stuff with your keyboard, bye. [!]\033[00m")
        time.sleep(3)
        sys.exit(0)
    
