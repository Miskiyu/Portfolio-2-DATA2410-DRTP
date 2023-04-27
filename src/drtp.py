#I denne filen skal vi ha nødvendig kode for server og client + DRTP (men ikke header, den er i en egen fil)
#Flags:
#-f -> filename?
#-r -> hvilken metode client skal sende på i DRTP
#-t -> Forskjell mellom client og server: Skipack er servermetode, loss er clientmetode ?

import header
import argparse
import socket
import sys
import re #Importing regex to check ip-adress for errors
import inspect # Brukt for å få informasjon om objekt i koden. https://docs.python.org/3/library/inspect.html

window = 64000 #Window is always 64000, declaring it as a global variable at the start.

socket.timeout(500) #The default timeout for any socket operation is 500 ms.
#Dette vil ikke fungere som en global variabel??

def handshakeServer(serverSocket, ip, port):
    seqNum = 0
    while True:
        message, (ip, port) = serverSocket.recvfrom(2048)
        
        sequence_number = 0
        acknowledgment_number = 0
        data = b'0' * 0

        data_from_msg = message[:12]
        seq, acknum, flags, win = header.parse_header(data_from_msg)

        print(f"This is seq: {seq}, this is acknum: {acknum}, this is flags: {flags}")
        if seq == 1 and acknum == 0 and flags == 8:
            print("First syn recieved successfully at server from client!")
            acknowledgment_number = 1
            seqNum = 2
            flags = 12
            msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
            serverSocket.sendto(msg, (ip, port))

        print(f"We managed to reach line {inspect.currentframe().f_lineno} in the code!")
        print(f"This is seq: {seq}, this is acknum: {acknum}, this is flags: {flags}")    
        if seq == 0 and acknum == 1 and flags == 4:
            print("Second syn recieved successfully at server from client!")
            break
    return seqNum
    
def handshakeClient(clientSocket, serverip, port, method, fileForTransfer): #Sends an empty package with a header containing the syn flag. Waits for a ack from the server with a timeout of 500 ms.
    sequence_number = 1
    acknowledgment_number = 0
    flags = 8
    data = b'0' * 0

    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
    clientSocket.sendto(msg, (serverip, port))
    
    modifiedMessage, serverConnection = clientSocket.recvfrom(2048)

    
    data_from_msg = modifiedMessage[:12]
    seq, acknum, flags, win = header.parse_header (data_from_msg) #it's an ack message with only the header
    syn, ack, fin = header.parse_flags(flags)

    print(f"Dette er syn og ack:  {syn}, {ack}")
    if syn and ack != 0 and acknum == 1:
        print("The ack from Server was recieved at Client!!")
        sequence_number = 0
        acknowledgment_number = 1
        flags= 4
        print(f"Dette er flags fra client: {flags}")
        msg = header.create_packet(sequence_number,acknowledgment_number,flags,window,data)
        clientSocket.sendto(msg, (serverip, port))
        #Setter sequencenumber lik 2, for nå er handshake over, og datasendingen skal begynne med pakke 2
        sequence_number = 2
        transmittAndListen(clientSocket, serverConnection, serverip, port, fileForTransfer, method, sequence_number)
    else:
        print('Error: Did not receive SYN-ACK packet')
        sys.exit()
        
def transmittAndListen(clientSocket, serverConnection, serverip, port, fileForTransfer, method, seqNum):
    print("Her skal vi sende og lytte alt etter metode som ble satt i terminalen")
    
    if(method == "SAW"):
        print("Går inn i stopAndWait metode")
        seqNum = (int) (stop_and_wait(clientSocket, fileForTransfer, serverConnection, seqNum))
    elif(method == "GBN"):
        seqNum = (int) (goBackN(clientSocket, fileForTransfer, serverConnection, seqNum))
    else:
        print("Here comes SR method")

    #Going into Finish-mode:
    print("Going into Finish-mode at client")
    while True:
        print("Kommer inn i while-Loop")
        data = b'0' * 0
        sequence_number = seqNum
        acknowledgment_number = 0
        flags = 2
        msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
        #Encoding packet and sending it to server ip and port
        clientSocket.sendto(msg, serverConnection)
        print("Har sendt meldingen til server")

        modifiedMessage, serverConnection = clientSocket.recvfrom(2048)
        print("Vi har motatt melding fra server")
        data_from_msg = modifiedMessage[:12]
        seq, acknum, flags, win = header.parse_header (data_from_msg) #it's an ack message with only the header
        print(f'seq={seq}, ack={acknum}, flags={flags}, receiver-window={win}')
        syn, ack, fin = header.parse_flags(flags)
        print("Kommer til if-setningen")
        if(fin == 2 and ack == 4):
            sequence_number = 0
            acknowledgment_number = seqNum
            flags = 4
            msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
            clientSocket.sendto(msg, serverConnection)
            #We are done -> finish
            print("We are done at client side, finishing")
            break
    print("Closing socket")
    clientSocket.close()

def stop_and_wait(clientSocket, fileForTransfer, serverConnection, seq_num):
    listeMedData = []
    #Den første parameteren er filen du vil åpne, den andre er "moden" du vil ha, vi har valgt read binary(rb)
    with open(fileForTransfer, "rb") as file:
       while True:
           data = file.read(1460)
           if not data:
               break
           listeMedData.append(data)
    i = 0
    while i < len(listeMedData):
        print("sender data i StopAndWait metoden")
        data = listeMedData[i]
        flags = 0
        packet= header.create_packet(seq_num, 0, flags, window, data)
        try:
                clientSocket.sendto(packet, serverConnection)
               # clientSocket.settimeout(0.5)
                ack, serverConnection =  clientSocket.recvfrom(2048)
                header_from_msg = ack[:12]
                seq, acknum, flags, win = header.parse_header (header_from_msg) #it's an ack message with only the header
                syn, ack, fin = header.parse_flags(flags)

                if acknum == seq_num:
                    seq_num +=1
                    i+=1
                    continue
                elif acknum == seq_num - 1:
                    print("Duplicate ACK received, resending packet...")
                    clientSocket.sendto(packet, serverConnection)
        except socket.timeout:
                print("Timeout, resending packet...")
    return seq_num

def goBackN(clientSocket, fileForTransfer, serverConnection, seq_num):
    print("Go-Back-N reliability method")
    listOfData = []
    i = 0
    while i < len(listOfData):
        if(len(listOfData) - i >= 5):
            k = 0
            dataTransfer = []
            ackList = []
            while k < 5:
                dataTransfer[k] = listOfData[i + k]
                k+=1

            w = 0
            sumSeq = 0
            while len(ackList) <= 5:
                flags = 0
                packet= header.create_packet(seq_num + w, 0, flags, window, dataTransfer[w])
                #Oppdaterer sumSeq som vi bruker for å sjekke om vi fikk alle acks som ble sendt i denne omgang til 
                sumSeq += seq_num + w

                if(w < 5): 
                    try:   
                        clientSocket.sendto(packet, serverConnection)
                        # clientSocket.settimeout(0.5)
                        ack, serverConnection =  clientSocket.recvfrom(2048)
                        header_from_msg = ack[:12]
                        seq, acknum, flags, win = header.parse_header (header_from_msg) #it's an ack message with only the header
                        syn, ack, fin = header.parse_flags(flags)
                        
                        ackList.append(acknum)
                        w += 1
                    except socket.timeout:
                        print("Timeout, resending packet...")
            #Vi sjekker om antall acks og nummeret deres stemmer overens med seqnummer av pakker sendt til server
            sjekk = False
            if sum(ackList) == sumSeq:
                sjekk = True

            if(sjekk):
                seq_num += 5
                i += 5
        else:
            print("Mindre enn 5 pakker igjen, må da regne hvor mange det er og sende de")
    return seq_num

def PackFile(fileForTransfer):
    listOfData = []
    with open(fileForTransfer, "rb") as file:
       while True:
           data = file.read(1460)
           if not data:
               break
           listOfData.append(data)

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

def createServer(ip, port, method):
    print("Her opprettes server:")
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSocket.bind((ip, port))
    print('The server is ready to receive')

    seqNum = (int) (handshakeServer(serverSocket, ip, port))
    listOfData = []
    ackNum = seqNum
    if(method == "SAW"):
        while True:
            message, clientAddress = serverSocket.recvfrom(2048)
            header_from_msg = message[:12]
            seq, acknum, flags, win = header.parse_header(header_from_msg)
            syn, ack, fin = header.parse_flags(flags)
            
            #Staten der vi legger inn data etterhvert som det kommer
            print(f"Dette er flags: {flags}")
            print(f"Dette er ack og fin: {ack}, {fin}")
            print(f"Dette er ackNum og seqNum: {acknum}, {seq}")
            if(flags == 0):
                if(seq == ackNum):
                    listOfData.append((seq ,message[12:]))
                
                    data = b''
                    sequence_number = 0
                    acknowledgment_number = ackNum
                    flags = 4
                    
                    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
                    serverSocket.sendto(msg, clientAddress)
                    ackNum+=1
                    
                else:
                    #seq og acknum er lik. Pakken ble lagt til, men acken herifra kom aldri frem til client. Vi sender ny ack
                    data = b''
                    sequence_number = 0
                    acknowledgment_number = ackNum
                    flags = 4
                    
                    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
                    serverSocket.sendto(msg, clientAddress)
            #Staten der vi er ferdige med å motta data, og vil avslutte
            elif(flags != 0 and listOfData):
                if fin == 2:
                    print("First FIN recieved successfully at server from client!")
                    data = b''
                    sequence_number = 0
                    acknowledgment_number = 0
                    window = 0 
                    flags = 6
                    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
                    serverSocket.sendto(msg, clientAddress)
                elif ack == 4:
                    print("Second FIN recieved successfully at server from client!")
                    #Her må vi liste ut alt dataen vi har fått inn ...!
                    break
    elif(method == "GBN"):
        print("Her kommer GBN koden")
    else:
        print("Her kommer SR koden")



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
#Nye argumenter som brukes i denne portifolioen:
parser.add_argument("-f", "--file", help="Write in the file you want to transmitt", type=str)
parser.add_argument("-r", "--reliability", help="Type inn the type of reliablity you want", type=str, default='SAW', choices=['SAW', 'GBN', 'SR'])
parser.add_argument("-t", "--testcase", help="Type in if you want to set a type of testcase", type=str, choices=['loss', 'skipack'])

args = parser.parse_args()

connection = (bind, port) #TODO: Gjennomgåande bruk denne

if args.client == True or args.server == True:
    if(args.client == True and args.server == True):
        print("You have to use either the -s (server) og -c (client) flag, not both")
        sys.exit()
    else:
        if args.client == True:
            PackFile(args.file)
            if(check_port(args.port) and check_IP(args.serverip)):
                createClient(args.serverip, args.port, args.reliability, args.fileForTransfer)
        if(args.server == True):
            if(check_port(args.port) and check_IP(args.bind)):
                createServer(args.bind, args.port, args.reliability)
else:
    print("You have to use either the -s (server) og -c (client) flag.")
    sys.exit()