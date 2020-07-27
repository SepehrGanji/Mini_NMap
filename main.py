import sys
import socket

ip = "127.0.0.1"
ports = [0, 1000]
model = "CS"
delay = 1

#Start of program
for i in range(0, len(sys.argv)):
    arg = sys.argv[i]
    print(i)
    if(arg[-3:] == ".py"):
        continue
    if(arg == "-t"):
        ip = socket.gethostbyname(sys.argv[i+1])
    elif(arg == "-T"):
        ip = sys.argv[i+1]
    elif(arg == "-p"):
        ps = sys.argv[i+1].split("-")
        ports = [int(ps[0]), int(ps[1])]
    elif(arg == "-s"):
        model = sys.argv[i+1]
    elif(arg == "-d"):
        delay = int(sys.argv[i+1])

#/////////////////////////////////

#End of program
