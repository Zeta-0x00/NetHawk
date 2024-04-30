#!/opt/homebrew/bin/python3.11
#-*- coding: utf-8 -*-

VERSION: str = '0.0.1'
"""
NetHawk - Network Scanner
Copyright © 2024 Daniel Hoffman (Aka. Z)
GitHub: Zeta-0x00

@Author Daniel Hofman (Aka. Z)
@License: GPL v3
@version {}
""".format(VERSION)


#region imports
import ipaddress
import socket
from termcolor import colored
import argparse
import os, re, signal, sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import timeit
from random import choice
#endregion

#region signals
socket_pool: list[socket.socket] = [] # list of sockets to close
signal.signal(signalnum=signal.SIGINT, handler=lambda sig, frame: (print(colored(text="\nSe recibió la señal SIGINT (Ctrl+C). Cerrando sockets y saliendo del programa...\n",color='red')), [s.close() for s in socket_pool], sys.exit(0)))
#endregion


#region arguments
def valid_range_threats(threads: str) -> int:
    """
    Validate the number of threads to use
    Args:
        threads (int): The number of threads to use
    Returns:
        int: The number of threads to use
    """
    if not threads.isdigit():
        raise argparse.ArgumentTypeError(colored(text="The number of threads must be an integer", color="red"))
    if int(threads) < 1 or int(threads) > 256:
        raise argparse.ArgumentTypeError(colored(text="The number of threads must be between 1 and 256", color="red"))
    return int(threads)

def getArguments() -> tuple[str, str]:
    """
    Get the arguments from the command line and return them as a tuple
    Returns:
        tuple[str, str]: The target and ports to scan
    """
    parser:argparse.ArgumentParser = argparse.ArgumentParser(description=colored(text='NetHawk - Network Scanner', color="magenta"))
    parser.add_argument( "-t", "--target", dest="target", metavar=colored(text="Target(s)",color='cyan'), required=True, help=colored(text="Target to scan: 192.168.1.1 | 192.168.1.1-42 | shodan.io | targets.txt (contain IP's by line) | 192.168.1.0/24", color='light_yellow') )
    parser.add_argument( "-p", "--ports", dest="ports", metavar=colored(text="Port(s)", color="cyan"), required=True, help=colored(text="Ports range to scan: 80 | 80,139,443,445 | 80-445 | - (`-p-` all ports from 1 to 65535 like nmap)",color="light_yellow") )
    parser.add_argument("-v", "--version", action="version", version="%(prog)s "+VERSION)
    parser.add_argument("-T", "--threads", dest="threads", type=valid_range_threats, metavar=colored(text="Threads", color="cyan"), required=False, default=50, help=colored(text="Number of threads to use: [min: 1] | [max: 256]", color="light_yellow"))
    options: argparse.Namespace = parser.parse_args()
    return options.target, options.ports, options.threads

def ParseTarget(prospect: str) -> list[str]:
    """
    Parse the target and return a list of valid targets
    Args:
        prospect (str): The target to parse
    Posible values:
        - Single IP:
            - e.g. 10.10.20.1
        - IP range:
            - e.g. 10.10.20.2-10
        - File:
            - e.g. targets.txt
            (contain IP's by line)
            10.10.20.1
            10.10.20.3
            10.10.20.14
        - Domain:
            - e.g. shodan.io
        - List of IPs:
            - e.g. 10.10.20.1,10.10.20.34,10.10.20.56
        - Netmask:
            - e.g. 10.10.20.0/24
    Returns:
        list[str]: The list of valid targets
    """
    ip_regex: str = r"^(\d{1,3}\.){3}\d{1,3}$"
    #valid if prospect is an IP
    if re.match(pattern=ip_regex, string=prospect):
        return [prospect]
    #valid if prospect is a range of IPs e.g. 192.168.1.1-10
    if re.match(pattern=r"^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$", string=prospect):
        start, end = prospect.split('-')
        start = int(start.split('.')[-1])
        end = int(end)
        return [f"192.168.1.{i}" for i in range(start, end+1)]
    #valid if prospect is a file
    if os.path.isfile(path=prospect):
        # deepcode ignore PT: Is not a security issue, there is not a PT, is a loading targets from a file, only works with local files and in the local machine for the current user
        with open(file=prospect, mode='r') as file:
            tempt: list[str] = file.readlines()
        targets: list[str] = [line.strip() for line in tempt if re.match(pattern=ip_regex,string=line)]
        return targets
    #valid if prospect is a domain
    try:
        tmp:str =  socket.getaddrinfo(host=prospect, port=None)
        targets = list(set([addr[4][0] for addr in tmp if addr[0] == socket.AddressFamily.AF_INET]))
        return targets
    except socket.gaierror:
        pass
    #valid if prospect is a list of IPs
    if ',' in prospect:
        targets: list[str] = prospect.split(',')
        return [target.strip() for target in targets if re.match(pattern=ip_regex, string=target)]
    #valid if prospect is a netmask
    if re.match(pattern=r"^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$", string=prospect):
        raise NotImplementedError
        return [str(object=ip) for ip in ipaddress.IPv4Network(address=prospect)]
    return []

def ParsePorts(ports: str) -> list[int]:
    """
    Parse the ports and return a list of valid ports
    Args:
        ports (str): The ports to parse
    Posible values:
        - Single port:
            - e.g. 80
        - Range of ports:
            - e.g. 80-443
        - List of ports:
            - e.g. 80,443,8080
        - All ports:
            - e.g. -
    Returns:
        list[int]: The list of valid ports
    """
    if not ports.isdigit() and len(ports)==1 and ports=='-':
        return [x for x in range(1, 65536)] # all ports from 1 to 65535
    if ports.isdigit():
        return [int(ports)] if int(ports) <= 65535  and int(ports) > 0 else []
    if '-' in ports:
        start: int
        end: int
        start, end = ports.split('-') if ports.split('-')[0].isdigit() and ports.split('-')[1].isdigit() else (0, 0)
        return [i for i in range(int(start), int(end)+1) if i <= 65535 and i > 0]
    if ',' in ports:
        return [int(x) for x in ports.split(',') if x.isdigit() and int(x) <= 65535 and int(x) > 0] 
    return []

def ParseArguments() -> tuple[list[str],list[int]]:
    """
    Parse the arguments from the command line and return the valid targets and ports
    Returns:
        tuple[list[str], list[int]]: The valid targets and ports
    """
    targets: str
    ports: str
    threads: int
    targets, ports, threads = getArguments()
    return ParseTarget(prospect=targets), ParsePorts(ports=ports), threads

#endregion


def create_socket() -> socket.socket:
    """
    Create a socket object
    Returns:
        socket.socket: The socket object
    """
    s:socket.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    s.settimeout(1)
    socket_pool.append(s)
    return s


def port_scanner(host:str, port: int) -> None:
    """
    Scan the target by single port
    Args:
        host (str): The target to scan
        port (int): The port to scan
    """
    s: socket.socket = create_socket()
    try:
        #print(f"Scanning {host}:{port}", end='\r', flush=True)
        if port >= 65530:
            print(port)
        #exit(1)
        s.connect((host, port))
        print(colored(text=f"\n[+] Open Port -> {port}", color='green'))
        s.close()
    except (socket.timeout, ConnectionRefusedError):
        s.close()
    except Exception as e:
        print(colored(text=f"\n[!] Error: {e}", color='red'))
        s.close()

def scanner(targets:str, ports:int, threads:int) -> None:
    """
    Scan the targets by ports range
    Args:
        targets (str): The targets to scan
        ports (int): The ports to scan
        threads (int): The number of threads to use
    Description:
        - Create a thread pool
        - Map the ports to the thread pool
        - Scan the ports by target
    """
    print(colored(text=f"\nStarting Scan on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", color='light_grey'))
    print(colored(text=f"[!] Threads: {threads}", color='light_yellow'))
    start: float = timeit.default_timer()
    for target in targets:
        print(colored(text=f"\n[!] Scanning target: {target}", color='light_yellow'))
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(lambda port: port_scanner(host=target,port=port), ports)
        """ for port in ports:
            port_scanner(host=target, port=port) """
    end: float = timeit.default_timer()
    a:float
    b:float
    a,b = divmod(end-start, 60)
    print(colored(text=f"Scan Duration{int(a)}m {b:4f}s", color='light_cyan'))

def banner() -> None:
    """
    Print the banner
    """
    banners: list[str] = [
        """
 _   _        _    _   _                   __    
| \ | |      | |  | | | |                 | |   
|  \| |  ___ | |_ | |_| |  __ _ __      __| | __
| . ` | / _ \| __||  _  | / _` |\ \ /\ / /| |/ /
| |\  ||  __/| |_ | | | || (_| | \ V  V / |   < 
\_| \_/ \___| \__|\_| |_/ \__,_|  \_/\_/  |_|\_\\
""",
"""
_____  ___    _______  ___________  __    __       __       __   __  ___  __   ___  
(\"   \|"  \  /"     "|("     _   ")/" |  | "\     /""\     |"  |/  \|  "||/"| /  ") 
|.\\   \    |(: ______) )__/  \\__/(:  (__)  :)   /    \    |'  /    \:  |(: |/   /  
|: \.   \\  | \/    |      \\_ /    \/      \/   /' /\  \   |: /'        ||    __/   
|.  \    \. | // ___)_     |.  |    //  __  \\  //  __'  \   \//  /\'    |(// _  \   
|    \    \ |(:      "|    \:  |   (:  (  )  :)/   /  \\  \  /   /  \\   ||: | \  \  
 \___|\____\) \_______)     \__|    \__|  |__/(___/    \___)|___/    \___|(__|  \__) 
""",
"""
    _   __       __   __  __                  __  
   / | / /___   / /_ / / / /____ _ _      __ / /__
  /  |/ // _ \ / __// /_/ // __ `/| | /| / // //_/
 / /|  //  __// /_ / __  // /_/ / | |/ |/ // ,<   
/_/ |_/ \___/ \__//_/ /_/ \__,_/  |__/|__//_/|_|  
""",
"""
 __   __   ______  ______  __  __   ______   __     __   __  __    
/\ "-.\ \ /\  ___\/\__  _\/\ \_\ \ /\  __ \ /\ \  _ \ \ /\ \/ /    
\ \ \-.  \\ \  __\\/_/\ \/\ \  __ \\ \  __ \\ \ \/ ".\ \\ \  _"-.  
 \ \_\\"\_\\ \_____\ \ \_\ \ \_\ \_\\ \_\ \_\\ \__/".~\_\\ \_\ \_\ 
  \/_/ \/_/ \/_____/  \/_/  \/_/\/_/ \/_/\/_/ \/_/   \/_/ \/_/\/_/ 
""",
"""
 ███▄    █ ▓█████▄▄▄█████▓ ██░ ██  ▄▄▄       █     █░██ ▄█▀
 ██ ▀█   █ ▓█   ▀▓  ██▒ ▓▒▓██░ ██▒▒████▄    ▓█░ █ ░█░██▄█▒ 
▓██  ▀█ ██▒▒███  ▒ ▓██░ ▒░▒██▀▀██░▒██  ▀█▄  ▒█░ █ ░█▓███▄░ 
▓██▒  ▐▌██▒▒▓█  ▄░ ▓██▓ ░ ░▓█ ░██ ░██▄▄▄▄██ ░█░ █ ░█▓██ █▄ 
▒██░   ▓██░░▒████▒ ▒██▒ ░ ░▓█▒░██▓ ▓█   ▓██▒░░██▒██▓▒██▒ █▄
░ ▒░   ▒ ▒ ░░ ▒░ ░ ▒ ░░    ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▓░▒ ▒ ▒ ▒▒ ▓▒
░ ░░   ░ ▒░ ░ ░  ░   ░     ▒ ░▒░ ░  ▒   ▒▒ ░  ▒ ░ ░ ░ ░▒ ▒░
   ░   ░ ░    ░    ░       ░  ░░ ░  ░   ▒     ░   ░ ░ ░░ ░ 
         ░    ░  ░         ░  ░  ░      ░  ░    ░   ░  ░   
"""
    ] # Ascii Arts from http://patorjk.com/software/taag/ all credits to the authors
                                                
        
    print(colored(text=choice(banners), color=choice(['cyan','magenta','blue','red'])))
    print(colored(text=VERSION, color='light_yellow'))
    print(colored(text="NetHawk - Network Scanner", color='magenta'))
    print(colored(text="Author: Daniel Hoffman (Aka. Z)", color='cyan'))
    print(colored(text="GitHub: Zeta-0x00", color='cyan'))
    print(colored(text="License: GPL v3", color='cyan'))
def main() -> None:
    """
    Main function
    args:
        -t, --target: The target to scan
        -p, --ports: The ports to scan
        -T, --threads: The number of threads to use
    description:
        - Parse the arguments
        - Call to the scanner
    """
    banner()
    target: list[str]
    ports: list[int]
    threads: int
    target,ports, threads = ParseArguments()
    scanner(targets=target, ports=ports, threads=threads)

if __name__ == "__main__":
    """
    Call to main if the module is the main file
    """
    main()

