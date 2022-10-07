from print_color import print
from prettytable import PrettyTable
import nmapthon as nm
import string
import threading
import time,sys
import itertools
import re
import requests
import pyfiglet
import readline

#for tab autocomplete
readline.set_completer_delims('\t\n=')
readline.parse_and_bind("tab: complete")


done = False
ports=[]
#wordlist="default.txt"

#header for the script
def header():
    #go to https://fsymbols.com/generators/tarty/ and get the name of the tool in this font
    print("""
░█████╗░██╗░░░██╗████████╗░█████╗░██████╗░███████╗░█████╗░░█████╗░███╗░░██╗
██╔══██╗██║░░░██║╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗████╗░██║
███████║██║░░░██║░░░██║░░░██║░░██║██████╔╝█████╗░░██║░░╚═╝██║░░██║██╔██╗██║
██╔══██║██║░░░██║░░░██║░░░██║░░██║██╔══██╗██╔══╝░░██║░░██╗██║░░██║██║╚████║
██║░░██║╚██████╔╝░░░██║░░░╚█████╔╝██║░░██║███████╗╚█████╔╝╚█████╔╝██║░╚███║
╚═╝░░╚═╝░╚═════╝░░░░╚═╝░░░░╚════╝░╚═╝░░╚═╝╚══════╝░╚════╝░░╚════╝░╚═╝░░╚══╝""")
    print("""
█▄▄ █▄█   █▄░█ █ █▄░█ ░░█ ▄▀█   █░█ ▄▀█ ▀█▀ ▀█▀ █▀█ █▀█ █
█▄█ ░█░   █░▀█ █ █░▀█ █▄█ █▀█   █▀█ █▀█ ░█░ ░█░ █▄█ █▀▄ █""")

#here is the animation
def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\rScanning in progress ' + c)
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\rDone!     ')


#Basic Scan
def base_sc():
    global done
    scanner = nm.NmapScanner(host, arguments='-O -Pn')
    scanner.run()
    print("\r", end="")
    print(" "*22+"\r", end="")
    if(host in scanner.scanned_hosts()):
        print("Host IP: ", end="")
        print("{}".format(host), end="", color="green", format="bold")
        print("\tState: ", end="")
        print("{}".format(scanner.state(host)).capitalize(), color="red", format="bold")
        print("Hostname: {}".format(','.join(scanner.hostnames(host))))
        try:
            for os_match, acc in scanner.os_matches(host):
                print('OS Match: {}\tAccuracy:{}%'.format(os_match, acc))

            fingerprint = scanner.os_fingerprint(host)
            if fingerprint is not None:
                print('Fingerprint: {}'.format(fingerprint))

            for most_acc_os in scanner.most_accurate_os(host):
                print('Most accurate OS: {}'.format(most_acc_os))
        except IndexError:
            print("No OS could be detected")
    else:
        done=True
        sys.exit("Host seems to be down.")

#Quick Port Scan
def quick_sc():
    global done
    scanner = nm.NmapScanner(host, arguments='-sT -Pn')
    scanner.run()
    print("\r", end="")
    print(" "*22+"\r", end="")
    # Get scanned protocols
    for proto in scanner.all_protocols(host):
        # Get scanned ports
        if(len(scanner.scanned_ports(host, proto))==0):
            done=True
            sys.exit("All 1000 ports are closed")
        else:
            for port in scanner.scanned_ports(host, proto):
                ports.append(port)
                state, reason = scanner.port_state(host, proto, port)
                print("Port ", end="")
                print("{}".format(port), format="bold", end="")
                print(" is {}".format(state))

#Service and Version Scan
def norm_sc():
    scanner = nm.NmapScanner(host, arguments='-sV -sC -Pn')
    scanner.run()
    print("\r", end="")
    print(" "*22+"\r", end="")
    for proto in scanner.all_protocols(host):
        # for each scanned port
        for port in scanner.scanned_ports(host, proto):
            state, reason = scanner.port_state(host, proto, port)
            print("Port: ", end="")
            print("{0}".format(port), format="bold", background="red", end="")
            print("\tState:{0:<9}Reason:{1}".format(state, reason))
            # Get service object
            service = scanner.service(host, proto, port)
            if service is not None:
                print("Service name: ", end="")
                print("{}".format(service.name), format="bold", background="red")
                print("Service product: {}".format(service.product))
                for cpe in service.all_cpes():
                    print("CPE: {}".format(cpe))
                my_tab=PrettyTable(["Script","Output"])
                for name, output in service.all_scripts():
                    output1=output.strip('\n')
                    my_tab.add_row([name,output1])
                print(my_tab)
                # You could also do print(str(service))
                # You could also know if 'ssh-keys' script was launched and print the output
                if 'ssh-keys' in service:
                    print("{}".format(service['ssh-keys']))

#Directory Scanning function
def dir_sc(ip, wordlist):
    result = pyfiglet.figlet_format("\r"+"-"*10+"VALID URL"+"-"*10, font = "wideterm")
    print(result, format="bold")
    #looping through each word in wordlist
    for word in wordlist:
        #making the url
        url=f"http://{ip}/{word}"

        #making a try block to avoid failure of program
        try:
            #sending the request
            response=requests.head(url)

            #if url is valid, print
            if response.status_code==200:
                print(f'[+] {url}')
            elif response.status_code==301:
                print(f'[+] DIRECTORY-> {url}')
            else:
                pass
        #if url is invalid, pass
        except requests.ConnectionError:
            pass
    print("\n")
    result = pyfiglet.figlet_format("\r"+"-"*10+"DONE"+"-"*10, font = "wideterm")
    print(result, format="bold")    



#main function
if __name__ == "__main__":
    header()
    print("\n\n")
    regex="^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"
    try:
        host=str(input("Enter IP: "))
        print("\n")
        if re.match(regex, host):
            result = pyfiglet.figlet_format("\r"+"-"*10+"BASIC IP SCAN"+"-"*10, font = "wideterm")
            print(result, format="bold")
            t = threading.Thread(target=animate)
            t.start()
            base_sc()
            done = True
            t.join()
            print("\n")
            done=False
            result = pyfiglet.figlet_format("\r"+"-"*10+"QUICK PORT SCAN"+"-"*10, font = "wideterm")
            print(result, format="bold")
            t1 = threading.Thread(target=animate)
            t1.start()
            quick_sc()
            done = True
            t1.join()
            print("\n")
            done=False
            result = pyfiglet.figlet_format("\r"+"-"*10+"NORMAL SCAN"+"-"*10, font = "wideterm")
            print(result, format="bold")
            t2 = threading.Thread(target=animate)
            t2.start()
            norm_sc()
            done=True
            t2.join()
            print("\n")
            if(80 in ports):
                char=str(input("Seems like the host has port 80 open. Do you want run a directory scan?(Y/N): "))
                if (char=="y" or char=="Y"):
                    char1=str(input("Do you want to provide a wordlist?(Y/N): "))
                    if (char1=="y" or char1=="Y"):
                        wordlist=str(input("Enter full path of wordlist: "))
                    else:
                        wordlist="default.txt"
                    print("\n")
                    print(f"Testing URL: http://{host}/\n")
                    print(f"Wordlist used: {wordlist}\n")
                    #reading the wordlist
                    with open(wordlist,"r") as file:
                            name=file.read()
                            words=name.splitlines()
                            #print(type(words))
                            length=len(words)
                            print(f"Total words generated = {length}\n")
                    dir_sc(host,words)
                else:
                    print("\n")
                    result = pyfiglet.figlet_format("\r"+"-"*10+"DONE"+"-"*10, font = "wideterm")
                    print(result, format="bold")
                    sys.exit()
        else:
            print("PLEASE ENTER A VALID IP!!", color="red", format="blink")
    except KeyboardInterrupt:
        done=True
        print("\r!!KEYBOARD INTERRUPT!!")