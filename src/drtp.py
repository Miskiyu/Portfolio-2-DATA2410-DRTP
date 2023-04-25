#I denne filen skal vi ha nødvendig kode for server og client + DRTP (men ikke header, den er i en egen fil)
#Flags:
#-s -> server
#-c -> client
#-I -> client ip
#-b -> server ip
#-p -> port
#-f -> filename?
#-m -> mode (hvilken metode i DRTP for server)
#-r -> hvilken metode client skal sende på i DRTP
#-t -> Forskjell mellom client og server: Skipack er servermetode, loss er clientmetode ?

'''''''''
udp server:
from socket import *
serverPort = 12000
serverSocket = socket(AF_INET, SOCK_DGRAM)
serverSocket.bind(('', serverPort))
print ('The server is ready to receive')
while True:
    message, clientAddress = serverSocket.recvfrom(2048)
    modifiedMessage = message.decode().upper()
    serverSocket.sendto(modifiedMessage.encode(),clientAddress)


s'''

import header
import argparse
from socket import *
import sys
import re #Importing regex to check ip-adress for errors

def check_IP(ip_address): #Code to check that the ip adress is valid. Taken from https://www.abstractapi.com/guides/python-regex-ip-address. Comments added by us.
  
   if not re.search(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", ip_address): #Check that the format is like this: "XXX.XXX.XXX.XXX", where X is a number between 0 and 9.
        raise Exception(f"The IP address {ip_address} is not valid. It needs to be in the format X.X.X.X, where each X is a number from 0 to 255.")
   
   ip_split = ip_address.split(".") #Splits the IP-adress string based on the periods, and in the for loop checks that each byte is from 0 to 255.
  
   for ip_part in ip_split:
       if int(ip_part) < 0 or int(ip_part) > 255:
            raise Exception(f"The IP address {ip_address} is not valid. It needs to be in the format X.X.X.X, where each X is a number from 0 to 255.")
   return ip_address

def check_port(port): #Code to check that the port is written is valid. Inspired from the starter code for portfolio 1. 
    try:
        value = int(port)
    except ValueError:
        raise argparse.ArgumentTypeError("Expected an integer but you entered a " + str(type(port))) #Need to convert type(val) to string to append to the string.
    if (value<1024 or value >65535):
        raise Exception("The port number is not valid, please choose a port number from 1024 to 65535")
    return value

def createServer(ip, port):
    print("Her opprettes server:")
    serverSocket = socket(AF_INET, SOCK_DGRAM)
    serverSocket.bind((ip, port))
    print('The server is ready to receive')
    while True:
        message = serverSocket.recvfrom(2048) 
        header.parse_header(message)
        serverSocket.sendto(modifiedMessage.encode(),clientAddress)

def createClient(serverip, port):
    print("Her opprettes client:")
   
    clientSocket = socket(AF_INET, SOCK_DGRAM)
    
    #Message to server from client:
    data = b'0' * 1460
    print (f'app data for size ={len(data)}')
    sequence_number = 1
    acknowledgment_number = 0
    window = 0 
    flags = 0
    msg = create_packet(sequence_number, acknowledgment_number, flags, window, data)

    #Encoding packet and sending it to server ip and port
    clientSocket.sendto(msg.encode(), (serverip, port))
    
    modifiedMessage, serverAddress = clientSocket.recvfrom(2048)
    print (modifiedMessage.decode())
    clientSocket.close()

#Defining the argumentParser
parser = argparse.ArgumentParser(description='The arguments used when calling the program')
#server argument code
parser.add_argument("-s", "--server", help="try to type '-s", action="store_true")
parser.add_argument("-b", "--bind", help="define an ip-address for the clients to connect to the host", type=check_IP, default=socket.gethostbyname(socket.gethostname()))
#shared argument code
parser.add_argument("-p", "--port", help="type -p and wanted portnumber, or default port 8080 will be set", type=check_port, default=8080)
#client argument code
parser.add_argument("-c", "--client", help="try to type '-c", action="store_true")
parser.add_argument("-I", "--serverip", help="Write the IP-address of the server to connect", type=check_IP, default=socket.gethostbyname(socket.gethostname()))

args = parser.parse_args()

serverip = args.serverip
bind = args.bind
port = args.port

if args.client == True or args.server == True:
    if(args.client == True and args.server == True):
        print("You have to use either the -s (server) og -c (client) flag, not both")
        sys.exit()
    else:
        if args.client == True:
            print("Her opprettes en UDP client") #TODO: Slett denne linja
            if(check_port(port) and check_IP(serverip)):
                createClient(serverip, port)
        if(args.server == True):
            print("Her opprettes en UDP Server")
            if(check_port(port) and check_IP(bind)):
                createServer(bind, port)
else:
    print("FEIL, DU MÅ SETTE SERVER ELLER CLIENT")
    sys.exit()

#Udp client