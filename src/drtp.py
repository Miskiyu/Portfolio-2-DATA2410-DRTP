#I denne filen skal vi ha nødvendig kode for server og client + DRTP (men ikke header, den er i en egen fil)
#Flags:
#-f -> filename?
#-m -> mode (hvilken metode i DRTP for server)
#-r -> hvilken metode client skal sende på i DRTP
#-t -> Forskjell mellom client og server: Skipack er servermetode, loss er clientmetode ?

import header
import argparse
import socket
import sys
import re #Importing regex to check ip-adress for errors

socket.timeout(500) #The default timeout for any socket operation is 500 ms.

def handshakeServer(serverSocket, IP, port):

    message, (serverip, port) = serverSocket.recvfrom(2048)
    
    sequence_number = 0
    acknowledgment_number = 0
    window = 64000
    data = b'0' * 2

    seq, ack, flags, win = header.parse_header(message)
    data_from_msg = message[:12]
    seq, acknum, flags, win = header.parse_header(data_from_msg) #it's an ack message with only the header
    syn, ack, fin = header.parse_flags(flags)

    print(f"This is seq: {seq}, this is acknum: {acknum}, this is flags: {flags}")
    if seq == 0 and acknum == 0 and flags == 8:
        print("First syn recieved successfully at server from client!")
        flags = 12
        msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
        serverSocket.sendto(msg, (serverip, port))
    else:
        sys.exit()
    #Send stuff here

    print("We managed to reach line 38 in the code!")
    print(f"This is seq: {seq}, this is acknum: {acknum}, this is flags: {flags}")    
    if seq == 0 and acknum == 0 and flags == 4:
        print("Second syn recieved successfully at server from client!")
        return
    else:
        sys.exit()   
    
def handshakeClient(clientSocket, serverip, port, method, fileForTransfer): #Sends an empty package with a header containing the syn flag. Waits for a ack from the server with a timeout of 500 ms.
    sequence_number = 0
    acknowledgment_number = 0
    window = 64000
    flags = 8
    data = b'0' * 0

    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
    clientSocket.sendto(msg, (serverip, port))
    
    modifiedMessage, serverConnection = clientSocket.recvfrom(2048)

    
    data_from_msg = modifiedMessage[:12]
    seq, acknum, flags, win = header.parse_header (data_from_msg) #it's an ack message with only the header
    syn, ack, fin = header.parse_flags(flags)

    if syn and ack != 0:
        print("The ack from Server was recieved at Client!!")
        flags= 4
        print(f"Dette er flags fra client: {flags}")
        msg = header.create_packet(sequence_number,acknowledgment_number,flags,window,data)
        clientSocket.sendto(msg, (serverip, port))
        transmittAndListen(clientSocket, serverConnection, serverip, port, fileForTransfer, method)
    else:
        print('Error: Did not receive SYN-ACK packet')
        sys.exit()
        
def transmittAndListen(clientSocket, serverConnection, serverip, port, fileForTransfer, method):
    print("Her skal vi sende og lytte alt etter metode som ble satt i terminalen")
    #Message to server from client: 
    data = b'0' * 1460
    #print (f'app data for size ={len(data)}') TODO delete this
    sequence_number = 1
    acknowledgment_number = 0
    window = 0 
    flags = 0
    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)

    #Encoding packet and sending it to server ip and port
    clientSocket.sendto(msg, serverConnection)
    
    print("We managed to reach this points. This is the clientsocket:")
    print(clientSocket)
    modifiedMessage, serverConnection = clientSocket.recvfrom(2048)
    print("This point, however, is out of our reach")
    
    data_from_msg = modifiedMessage[12:]
    seq, acknum, flags, win = header.parse_header (data_from_msg) #it's an ack message with only the header
    print(f'seq={seq}, ack={acknum}, flags={flags}, receiver-window={win}')
    syn, ack, fin = header.parse_flags(flags)

    clientSocket.close()

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
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSocket.bind((ip, port))
    print('The server is ready to receive')
    handshakeServer(serverSocket, ip, port)
    
    while True:
        message, clientAddress = serverSocket.recvfrom(2048)
        message = message.decode()
        data_from_msg = message[12:]
        Recieved_header = header.parse_header(data_from_msg)
        print(Recieved_header)
        data = b''

        sequence_number = 0
        acknowledgment_number = 0
        window = 0 
        flags = 4
        
        msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
        serverSocket.sendto(msg.encode(), clientAddress)

        seq, acknum, flags, win = header.parse_header (msg) #it's an ack message with only the header
        print(f'seq={seq}, ack={acknum}, flags={flags}, receiver-window={win}') #TODO delete this

def createClient(serverip, port, method, fileForTransfer):
    print("Her opprettes client:")
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    handshakeClient(clientSocket, serverip, port, method, fileForTransfer) #Sending a packet with the syn flag to the server, if an ack is recieved transmission of data starts.
    
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
method = "Metode som hentes ut av argparse"
fileForTransfer = "Fil som skal sendes"

if args.client == True or args.server == True:
    if(args.client == True and args.server == True):
        print("You have to use either the -s (server) og -c (client) flag, not both")
        sys.exit()
    else:
        if args.client == True:
            if(check_port(port) and check_IP(serverip)):
                createClient(serverip, port, method, fileForTransfer)
        if(args.server == True):
            if(check_port(port) and check_IP(bind)):
                createServer(bind, port)
else:
    print("You have to use either the -s (server) og -c (client) flag.")
    sys.exit()
#UDP client