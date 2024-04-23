import nmap
import os


def version():
    x,y=nm.nmap_version()
    return str(x)+"."+str(y)

def setIp():
    while True:
        ip = input("Enter IP Adderss or Range: ")
        if len(ip.split("."))==4:
            if ip.split(".")[0].isnumeric():
                return ip
        print("Enter a Valid IP or Range. Use '/' or '-' to give a range \n")

def setPort():
    p =input("Enter Port Range (Default is 1-1024):")
    if p.isnumeric():
        return p
    elif p.split("-")[0].isnumeric() and p.split("-")[0].isnumeric():
        return p
    return '1-1024'

# Check ip status and print it
def networkCheck(ip, out=True):
    """ 
    it will check the ip status and print it
    it takes two arguments first for ip and 2nd for print the output or not
    """
    status =[]
    try:
        nm.scan(ip,arguments="-n -sn")
        hosts = nm.all_hosts()
        for i in hosts:
            state=nm[i].state()
            if out:
                print("Host: ",nm[i].hostname(),i,":",state)
            if state=="up":
                status.append(i)
    except:
        pass
    return status

def synAck(ip, port, sudo):
    #Checking hosts are up or down
    hosts= networkCheck(ip,False)
    for i in hosts:
        print("Host:",i)
        try:
            nm.scan(ip,port,"-sS", sudo=sudo, timeout=30)
            try:
                print("\nHostName:",nm[i].hostname())
                print("mac address: ",nm[i]['addresses']['mac'],"\n")
            except:
                pass
            for (x,y) in nm[i]['tcp'].items():
                print(x," tcp ",y['state'],"  ",y['name'])
            print()
        except Exception as e:
            print(e)
            print("Error! Try Again")
        print("-----------------------")

def tcpScan(ip,port, sudo):
    hosts= networkCheck(ip,False)
    for i in hosts:
        print("Host:",i)
        try:
            nm.scan(ip,port,"-sT", sudo, 30)
            try:
                print("\nHostName:",nm[i].hostname())
                print("mac address: ",nm[i]['addresses']['mac'],"\n")
            except:
                pass
            for (x,y) in nm[i]['tcp'].items():
                print(x," tcp ",y['state'],"  ",y['name'])
            print()
        except Exception as e:
            print(e)
            print("Error! Try Again")
        print("-----------------------")

def udpScan(ip,port, sudo):
    hosts= networkCheck(ip,False)
    for i in hosts:
        print("Host:",i)
        try:
            nm.scan(ip,port,"-sU", sudo, 50)
            try:
                print("\nHostName:",nm[i].hostname())
                print("mac address: ",nm[i]['addresses']['mac'],"\n")
            except:
                pass
            for (x,y) in nm[i]['udp'].items():
                print(x," udp ",y['state'],"  ",y['name'])
            print()
        except Exception as e:
            print(e)
            print("Error! Try Again")
        print("-----------------------")

def osDetection(ip, sudo):
    hosts= networkCheck(ip, False)
    for i in hosts:
        print("Host: ",i)
        try:
            nm.scan(ip,'1-1024',arguments="-O",sudo=sudo,timeout=30)
            try:
                print("\nHostName:",nm[i].hostname())
                print("mac address: ",nm[i]['addresses']['mac'],"\n")
            except:
                pass
            print("Predictions:")
            for i in nm[ip]['osmatch']:
                print("Operating System:",i['name']," ",i['accuracy'],"%")
            print()
        except Exception as e:
            print(e)
            print("Error! Try Again")
        print("-----------------------")

def dictTravel(d):
    if isinstance(d, dict):
        for x,y in d.items():
            if isinstance(y, dict):
                print(x, " :")
                dictTravel(y)
            elif isinstance(y, list) or isinstance(y,tuple):
                print(x, " :")
                for i in y:
                    dictTravel(i)
            else:
                print(x," : ",y)
    else:
        print(d)
                
def aggressiveScan(ip,port, sudo):
    hosts= networkCheck(ip,False)
    for i in hosts:
        print("Host: ",i)
        try:
            nm.scan(ip,port,arguments="-A",sudo=sudo)
            dictTravel(nm[ip])
            print()
        except Exception as e:
            print(e)
            print("Error Scaning! Try Again")
        print("-----------------------")


def customScan(ip,port, sudo):
    hosts= networkCheck(ip,False)
    for i in hosts:
        print("Host: ",i)
        try:
            nm.scan(ip,port,sudo=sudo)
            print("Enter Your Custom Command For this Ip: ")
            nm.command_line()
            dictTravel(nm[ip])
            print()
        except Exception as e:
            print(e)
            print("Error Scaning! Try Again")
        print("-----------------------")


if __name__ == "__main__":

    nm = nmap.PortScanner()
    #Check the OS
    sudo= True
    if os.name=='nt':
        sudo=False

    print('''

    █████╗ ██╗   ██╗████████╗ ██████╗       ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
    ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗      ████╗  ██║████╗ ████║██╔══██╗██╔══██╗
    ███████║██║   ██║   ██║   ██║   ██║█████╗██╔██╗ ██║██╔████╔██║███████║██████╔╝
    ██╔══██║██║   ██║   ██║   ██║   ██║╚════╝██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
    ██║  ██║╚██████╔╝   ██║   ╚██████╔╝      ██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
    ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝       ╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
                                                                                
          made for Educational perpose ;)
                                                                        By sanu
        ''')
    ip= setIp()
    ports= setPort()

    print('Nmap version:',version())

    while True:
        print('<-------------------------------------------->')
        print("Ip- ",ip," Port- ",ports,"\n")
        print('''Choose an option: 
            1. Check Network Status 
            2. SynAck Scan
            3. TCP Scan
            4. UDP Scan
            5. Aggressive Scan
            6. OS Detection
            7. Custom Command
            9. Reset Crediantials
            0. Exit
            ''')
        # Validae the Input
        try:
            n = int(input("Enter option Number: "))
        except ValueError:
            print("please enter a Number")
            input("Press Enter to Continue")
            continue
        print()
        if n==1:
            print("Checking Network Status \n")
            networkCheck(ip, True)
        elif n==2:
            print("Starting Scan \n")
            synAck(ip, ports, sudo)
        elif n==3:
            print("Starting TCP Scan \n")
            tcpScan(ip,ports, sudo)
        elif n==4:
            print("Starting UDP Scan \n")
            udpScan(ip,ports, sudo)
        elif n==5:
            print("Starting Aggressive Scan \n")
            aggressiveScan(ip,ports, sudo)
        elif n==6:
            print("Detecting Os \n")
            osDetection(ip, sudo)
        elif n==7:
            print("Custom command \n")
            osDetection(ip, sudo)
        elif n==9:
            ip= setIp()
            ports = setPort()
            continue
        elif n==0:
            print("\nThanks for using  :D\n")
            exit()
        else:
            print("\nERROR! Please Enter a Valid Number :)\n")
            continue

        input("Press Enter to Continue")

  
