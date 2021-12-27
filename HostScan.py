import nmap
from threading import Thread
from time import sleep

class Loading_thread:      
    def __init__(self):
        self._running = True
      
    def terminate(self):
        self._running = False
      
    def run(self):
        MAX_TIME = 120
        bar_char = "*"
        i = 1
        while self._running and i <= MAX_TIME:
            print(bar_char, end="", flush=True)
            i += 1
            sleep(1)
        if i >= MAX_TIME:
            print(f"\n[-] This is taking a may while. Take a look to arguments you introduce. Use Ctrl+C to finish proccess (Timeout)")
        print(f"(Proccess took {i} sec)", end="", flush=True)

def scan_host(ip: str, moreInfo: bool):
    print('\n')
    print(f"[!] Analyzing subnet with mask {ip}")

    load = Loading_thread()
    t_load = Thread(target=load.run)
    t_load.start()

    try:
        nport = nmap.PortScanner()

        nport.scan(hosts= f'{ip}', arguments='-n -sn -PE -PA21,23,80,3389')

        load.terminate()

        print()
        print(f"[!] Discovered {len(nport.all_hosts())} host UP")

        if not moreInfo:
            for x in nport.all_hosts():
                host_info = nport[x]
                status = host_info["status"]

                if status["reason"] != "localhost-response":
                    print(f'[+] Host with IP {x} is {status["state"].upper()} \n')
        else:
            for x in nport.all_hosts():
                host_info = nport[x]
                status = host_info["status"]

                if status["reason"] != "localhost-response":
                    vendor = host_info["vendor"]
                    addresses = host_info["addresses"]

                    print(f'[+] Host with IP {x} is {status["state"].upper()}')
                    print(f'\t└\\ Vendor => {len(vendor) > 0 and vendor[addresses["mac"]] or "NO INFORMATION"}')
                    print(f'\t└\\ Addresses => Ip: {addresses["ipv4"]} | {addresses["mac"] and "MAC: " + addresses["mac"] or "NO MAC ADDRESS"}')
                    print(f'\t└\\ State Reason => {status["state"].upper()} because {status["reason"].upper()}')
                    print()

        sys.exit(0)
    except nmap.nmap.PortScannerError as e:
        load.terminate()     
        print("[-] You must have installed and added to path nmap from this url -> https://nmap.org/download.html")

    except KeyboardInterrupt as e:
        load.terminate()
        print("\n[-] Exit by user")

    except Exception as e:
        load.terminate()
        print(e)
    
    sys.exit(1)

    


if __name__ == "__main__":
    import sys, platform, os
    from tabulate import tabulate
    
    with open(os.path.join(os.path.dirname(__file__), "credits.txt")) as credits:
        print(f"\n{credits.read()}");

    os_table = [
        ["Platform", platform.system()],
        ["Version", platform.release()],
        ["Arch", platform.machine()]
    ]
    print("\nOS INFORMATION")
    print(tabulate(os_table))
    
    useHinfo = False

    if len(sys.argv) > 1:
        if "-net4" in sys.argv:

            if "-hinfo" in sys.argv: 
                useHinfo = True

            try:
                scan_host(sys.argv[sys.argv.index("-net4") + 1], useHinfo)
            except IndexError:
                print("[!] You forgot to include ipv4 mask here: -net4 <-Here")
            
    
    print("\n[?] HostScan.py -net4 <netmask-ipv4> [-hinfo | -h/--help]")
    sys.exit(0)