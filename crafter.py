from socket import *
import binascii

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
    # rem = sum // 65536
    # sum = sum - (rem*65536) + rem
    # return int.to_bytes(65535 - sum, 2, 'big')

def get_ip():
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

s = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)

src_ip = get_ip()
hex_src_ip = get_hex_ip(src_ip)
dest_ip = "127.0.0.1"
hex_dest_ip = get_hex_ip(dest_ip)
src_port = 3000
dest_port = 80
scantype = "SS"

ip_header_vals = [
    b'\x45\x00', #Version = 4(IPv4), IHL, TOS
    b'\x00\x28', #TotalLength = 40bytes
    b'\x83\xb1', #Identification : 33713(my student num is 97-33713)
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
offlag = int.to_bytes(n, 2, 'big')

tcp_pseudo_header =[
    b'\x00\x06', #Protocol
    hex_src_ip[0],
    hex_src_ip[1],
    hex_dest_ip[0],
    hex_dest_ip[1],
    b'\x00\x14', #Tcp header length = 20
    int.to_bytes(src_port, 2, 'big'), #Source port : 3000
    int.to_bytes(dest_port, 2, 'big'), #Destination port : 80
    b'\x00\x00', #Seq num
    b'\x00\x00',
    b'\x00\x00', #Ack num
    b'\x00\x00',
    offlag, #Data offset and flags
    b'\x71\x10', #Window size
    b'\x00\x00', #Checksum
    b'\x00\x00' #URG pointer
]

tcp_pseudo_header[-2] = calc_checksum(tcp_pseudo_header)

tcp_header = tcp_pseudo_header[6:]

packet = b''

for i in range(0, 10):
    packet += ip_header_vals[i]
for i in range(0, 10):
    packet += tcp_header[i]

s.sendto(packet, (dest_ip, dest_port))
s.settimeout(5)
try:
    data = s.recv(1024)
    #ACK Scan
    # filtered = True
    # d = binascii.hexlify(data)
    # protoc = d[18:20]
    # if(protoc == b'06'): #TCP
    #     flagss = d[66:68]
    #     if(flagss == b'14' or flagss == b'10'): #RST Flag
    #         filtered = False
    # print(filtered)
except:
    print("TimeOut")
finally:
    s.close()
