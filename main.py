from socket import *
from struct import *

import sys
import binascii
import time
import json
import random

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

def get_hex_ip(ip):
    t = []
    b_array = ip.split(".")
    myhex = ""
    for i in range(0, 2):
        a = int(b_array[i]) // 16
        b = int(b_array[i]) % 16
        if(a < 10):
            myhex += str(a)
        else:
            myhex += chr(ord('a') + a-10)
        if(b < 10):
            myhex += str(b)
        else:
            myhex += chr(ord('a') + b-10)
    t.append(bytes.fromhex(myhex))
    myhex = ""
    for i in range(2, 4):
        a = int(b_array[i]) // 16
        b = int(b_array[i]) % 16
        if(a < 10):
            myhex += str(a)
        else:
            myhex += chr(ord('a') + a-10)
        if(b < 10):
            myhex += str(b)
        else:
            myhex += chr(ord('a') + b-10)
    t.append(bytes.fromhex(myhex))
    return t

def calc_checksum(vals):
    sum = 0
    for i in range(0, len(vals)):
        w = vals[i]
        sum += (int.from_bytes(w,'big'))
    btes = int.to_bytes(sum, 3, 'big')[0]
    sum = sum % 65536
    sum += btes
    sum = 65535 - sum
    return int.to_bytes(sum, 2, 'big')

def get_ip():
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def craft_packet(src_ip, src_port, dest_ip, dest_port, scantype):
    hex_src_ip = get_hex_ip(src_ip)
    hex_dest_ip = get_hex_ip(dest_ip)
    ii = (9733713 * src_port) % 65536
    idn = int.to_bytes(ii, 2, 'big')
    ip_header_vals = [
        b'\x45\x00', #Version = 4(IPv4), IHL, TOS
        b'\x00\x28', #TotalLength = 40bytes
        idn, #Identification
        b'\x00\x00', #Flags and Fragment Offset
        b'\x40\x06', #TTL = 64, Protocol = 6(tcp)
        b'\x00\x00', #CheckSum (0 for now)
        hex_src_ip[0], #Source IP Address
        hex_src_ip[1],
        hex_dest_ip[0], #Destination IP Address
        hex_dest_ip[1]
    ]
    ip_header_vals[5] = calc_checksum(ip_header_vals)

    n = 20480
    if(scantype == "AS" or scantype == "WS"):
        n += 16
    elif(scantype == "SS"):
        n += 2
    elif(scantype == "FS"):
        n += 1
    else:
        n += 41
    offlag = int.to_bytes(n, 2, 'big')
    tcp_pseudo_header =[
        b'\x00\x06', #Protocol
        hex_src_ip[0], #Source IP
        hex_src_ip[1],
        hex_dest_ip[0], #Destination IP
        hex_dest_ip[1],
        b'\x00\x14', #Tcp header length = 20
        int.to_bytes(src_port, 2, 'big'), #Source port
        int.to_bytes(dest_port, 2, 'big'), #Destination port
        b'\x00\x00', #Seq num
        b'\x00\x00',
        b'\x09\x73', #Ack num
        b'\x37\x13',
        offlag, #Data offset and flags
        b'\x05\x77', #Window size = 1399
        b'\x00\x00', #Checksum (0 for now)
        b'\x00\x00' #URG pointer
    ]
    tcp_pseudo_header[-2] = calc_checksum(tcp_pseudo_header)
    tcp_header = tcp_pseudo_header[6:]

    packet = b''
    for i in range(0, 10):
        packet += ip_header_vals[i]
    for i in range(0, 10):
        packet += tcp_header[i]
    return packet

def tcp_flags(data):
    arr = unpack('!HHLLBBHHH', data)
    return [arr[0], arr[1], arr[6] == 0, arr[5]]

json_file = open("ports.json", "r")
port_servieces = json.load(json_file)

#Start of program
for i in range(0, len(sys.argv)):
    arg = sys.argv[i]
    if(arg[-3:] == ".py"):
        continue
    if(arg == "-t"):
        try:
            ip = gethostbyname(sys.argv[i+1])
        except:
            print("Can't find target host ip")
            exit(-1)
    elif(arg == "-T"):
        ip = sys.argv[i+1]
    elif(arg == "-p"):
        ps = sys.argv[i+1].split("-")
        ports = [int(ps[0]), int(ps[1])]
    elif(arg == "-s"):
        model = sys.argv[i+1]
    elif(arg == "-d"):
        delay = int(sys.argv[i+1])

t1 = time.time()
localtime = time.asctime(time.localtime(t1))

print("Starting my map at", localtime)
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
else: #We Should Manualy Craft Packets
    print("PORT\tSTATE\tSERVIECE")
    myip = get_ip()
    random.seed(time.time())
    for p in range(ports[0], ports[1] + 1):
        po = random.randrange(1000, 65000)
        packet = craft_packet(myip, po, ip, p, model)
        s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
        s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        s.sendto(packet, (ip, p))
        i_said_so = True
        flgs = []
        s.settimeout(delay)
        NO_RESP = False
        while(i_said_so):
            try:
                data = s.recv(1024)
            except:
                s.sendto(packet, (ip, p))
                s.settimeout(delay + 1)
                try:
                    data = s.recv(1024)
                except:
                    NO_RESP = True
                    i_said_so = False
            finally:
                if(NO_RESP == False):
                    flgs = tcp_flags(data[20:40])
                    if(flgs[0] == p and flgs[1] == po):
                        i_said_so = False
                        s.close()
        ACK_flag = 0
        RST_flag = 0
        SYN_flag = 0
        ZERO_Window = False
        if(NO_RESP == False):
            flg_num = flgs[-1]
            ZERO_Window = flgs[2]
            ACK_flag = (flg_num & 16) >> 4
            RST_flag = (flg_num & 4) >> 2
            SYN_flag = (flg_num & 2) >> 1
        serv = ""
        try:
            serv = port_servieces[str(p)]
        except:
            serv = "unknown"
        string = str(p) + "/tcp\t"
        port_state = ""
        if(model == "AS"):
            if(RST_flag):
                port_state = "unfiltered"
            else:
                port_state = "filtered"
        elif(model == "SS"):
            if(SYN_flag and ACK_flag):
                port_state = "open"
            elif(RST_flag):
                port_state = "closed"
            else:
                port_state = "filtered"
        elif(model == "WS"):
            if(RST_flag):
                if(ZERO_Window):
                    port_state = "closed"
                else:
                    port_state = "open"
            else:
                port_state = "filtered"
        else: #FS or Xmas
            if(NO_RESP):
                port_state = "open|filtered"
            elif(RST_flag):
                port_state = "closed"
            else:
                port_state = "filtered"
        string = string + port_state + " " + serv
        print(string)

t2 = time.time()
print(str(ports[1] - ports[0] + 1) + " ports scanned in " + str(int(t2-t1)) +" seconds")
#End of program
