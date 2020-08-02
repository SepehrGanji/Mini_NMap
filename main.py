import sys
from socket import *

ip = "127.0.0.1"
ports = [0, 1000]
model = "CS"
delay = 1

def ConnectScan(sock, ip, port):
    try:
        sock.connect((ip, port))
        return True
    except:
        return False

#Start of program
for i in range(0, len(sys.argv)):
    arg = sys.argv[i]
    if(arg[-3:] == ".py"):
        continue
    if(arg == "-t"):
        ip = gethostbyname(sys.argv[i+1])
    elif(arg == "-T"):
        ip = sys.argv[i+1]
    elif(arg == "-p"):
        ps = sys.argv[i+1].split("-")
        ports = [int(ps[0]), int(ps[1])]
    elif(arg == "-s"):
        model = sys.argv[i+1]
    elif(arg == "-d"):
        delay = int(sys.argv[i+1])

print("Starting my map ...")
print("Scanning " + str(ip) + " , ports " + str(ports[0]) + " to " + str(ports[1]) )

if(model == "CS"):
    is_Any = False
    for p in range(ports[0], ports[1] + 1):
        my_socket = socket(AF_INET, SOCK_STREAM)
        my_socket.settimeout(delay)
        if(ConnectScan(my_socket, ip, p)):
            print("\tPort " + str(p) + " is Open for TCP connection")
            is_Any = True
    if(is_Any == False):
        print("\tAll ports in the target are closed!")
    print("End of scan")
elif(model == "AS"):
    pass
elif(model == "SS"):
    pass
elif(model == "FS"):
    pass
elif(model == "WS"):
    pass
else:
    print("Unknown Scan Model!")

#End of program
