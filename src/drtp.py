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

    print(f"We managed to reach line {inspect.currentframe().f_lineno} in the code!")
    print(f"This is seq: {seq}, this is acknum: {acknum}, this is flags: {flags}")    
    if seq == 0 and acknum == 0 and flags == 4:
        print("Second syn recieved successfully at server from client!")
        return
    
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

    print(f"Dette er syn og ack:  {syn}, {ack}")
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
    
    data_from_msg = modifiedMessage[:12]
    seq, acknum, flags, win = header.parse_header (data_from_msg) #it's an ack message with only the header
    print(f'seq={seq}, ack={acknum}, flags={flags}, receiver-window={win}')
    syn, ack, fin = header.parse_flags(flags)

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
        try:
                sendingPacket(seq_num,data, clientSocket,serverConnection)  #Calling a function to send a packet, which will simulate packet loss if the flag is used.
                ack, serverConnection =  clientSocket.recvfrom(1472)
                header_from_msg = ack[:12]
                seq, acknum, flags, win = header.parse_header (header_from_msg) #it's an ack message with only the header
                syn, ack, fin = header.parse_flags(flags)
                if acknum == seq_num:
                    seq_num +=1
                    i+=1
                    continue
                elif acknum == seq_num - 1:
                    print("Duplicate ACK received, resending packet...")
                    sendingPacket(seq_num,data, clientSocket,serverConnection) 
        except socket.timeout:
                print("Timeout, resending packet...")
    return seq_num


def goBackN(clientSocket, fileForTransfer, serverConnection, seq_num):
    print("Go-Back-N reliability method")
    listOfData = PackFile(fileForTransfer)
    
    i = 0
    print(f" lengde av listofData: {len(listOfData)}")
    ackList = []
    sumSeq = 0

    while i < len(listOfData):
        print("Nå er vi inne i whileløkken som skal gå til når vi er tom for data å sende")
        dataTransfer = []
        if(len(listOfData) - i >= 5):
            for k in range(5):
                dataTransfer.append(listOfData[i + k])
        else: #If there's less than 5 packets left to send, we send those packets, and a few extra packets so that the total amount of packets sent is 5. 
            print("Mindre enn 5 pakker igjen, må da regne hvor mange det er og sende de")
            antallTommePakker = len(listOfData) - i 

            for p in range(5-antallTommePakker): #Preparing the remaing packets to be sent.
                dataTransfer.append(listOfData[p])
                
            for j in range(antallTommePakker): #Ading empty packets so that we got 5 packets left to send.
                data = b'0' * 0
                dataTransfer.append(data)

        for j in range(5):
            flags = 0
            packet= header.create_packet(seq_num + j, 0, flags, window, dataTransfer[j])
            try:   
                    clientSocket.sendto(packet, serverConnection)
            except socket.timeout:
                    print("Timeout, resending packets...")
            sumSeq += seq_num + j
        
        clientSocket.settimeout(5)
        for j in range(5):
            try:
                ack, serverConnection =  clientSocket.recvfrom(12)
                print("test")
                header_from_msg = ack[:12]
                seq, acknum, flags, win = header.parse_header (header_from_msg) #it's an ack message with only the header
                syn, ack, fin = header.parse_flags(flags)
                print(f"Legger til acknum: {acknum}")
                ackList.append(acknum)
            except:
                print("Breaker ut av reciving packets")
                break
        
        sjekk = False

        print(sum(ackList))
        print(sumSeq)

        if sum(ackList) == sumSeq:
            sjekk = True
        
        print(f"verdi av sjekk: {sjekk}")
        print(f"sec_num: {seq_num}")
        print(f"i: {i}")
        if(sjekk):
            seq_num += 5
            i += 5
            
    return seq_num

def selectiveRepeat(clientSocket, fileForTransfer, serverConnection, seq_num):
    print("SNR reliability method")
    listOfData = PackFile(fileForTransfer)
    
    i = 0
    print(f" lengde av listofData: {len(listOfData)}")
    ackList = []
    allSentPacketNumbers = []

    while i < len(listOfData):
        print("Nå er vi inne i whileløkken ")
        dataTransfer = []
        if(len(allSentPacketNumbers) == 0):
            if(len(listOfData) - i >= 5):
                for k in range(5):
                    dataTransfer.append(listOfData[i + k])
            else: #If there's less than 5 packets left to send, we send those packets, and a few extra packets so that the total amount of packets sent is 5. 
                print("Mindre enn 5 pakker igjen, må da regne hvor mange det er og sende de")
                antallTommePakker = len(listOfData) - i 

                for p in range(5-antallTommePakker): #Preparing the remaing packets to be sent.
                    dataTransfer.append(listOfData[p])
                    
                for j in range(antallTommePakker): #Ading empty packets so that we got 5 packets left to send.
                    data = b'0' * 0
                    dataTransfer.append(data)

            for j in range(5):
                flags = 0
                packet= header.create_packet(seq_num + j, 0, flags, window, dataTransfer[j])
                try:   
                        clientSocket.sendto(packet, serverConnection)
                except socket.timeout:
                        print("Timeout, resending packets...")
                allSentPacketNumbers.append(seq_num + j) 

            clientSocket.settimeout(0.5)
            for j in range(5):
                try:
                    ack, serverConnection =  clientSocket.recvfrom(12)
                    print("test")
                    header_from_msg = ack[:12]
                    seq, acknum, flags, win = header.parse_header (header_from_msg) #it's an ack message with only the header
                    syn, ack, fin = header.parse_flags(flags)
                    print(f"Legger til acknum: {acknum}")
                    ackList.append(acknum)
                except:
                    print("Breaker ut av reciving packets")
                    break

            print(sum(ackList))
            
            for i in ackList:    #Metoden vi hadde før funket ikke, det ble index out of bounds.
                for j in allSentPacketNumbers:
                    if i == j:
                        allSentPacketNumbers.remove(i)  #Alt blir fjernert fordi alt blir sendt
           

          

            
            if(len(allSentPacketNumbers) == 0):
                seq_num += 5
                i += 5
        else:
            print("Dette er tilfellet der ack ikke kom tilbake for en pakke, og den skal sendes til den mottas hos server og acken kommmer")
            indexForTransfer = []
            allSentPacketNumbers.sort() #Sorterer etter stigende rekkefølge

            for a in allSentPacketNumbers:
                indexForTransfer.append(a - 2) #Finner variabel i sin verdi i listen for å hente ut riktig data til transfer
            for b in indexForTransfer:
                dataTransfer.append(listOfData[b]) #Finner dataen vi må sende på ny til server
            
            for j in  range(len(dataTransfer)):
                flags = 0
                packet= header.create_packet(allSentPacketNumbers[j], 0, flags, window, dataTransfer[j])
                try:   
                        clientSocket.sendto(packet, serverConnection)
                except socket.timeout:
                        print("Timeout, resending packets...") 
        
            clientSocket.settimeout(0.5)
            for j in range(len(dataTransfer)):
                try:
                    ack, serverConnection =  clientSocket.recvfrom(12)
                    header_from_msg = ack[:12]
                    seq, acknum, flags, win = header.parse_header (header_from_msg) #it's an ack message with only the header
                    syn, ack, fin = header.parse_flags(flags)
                    print(f"Legger til acknum: {acknum}")
                    ackList.append(acknum)
                except:
                    print("Breaker ut av reciving packets")
                    break
            
            for i in ackList:
                for j in allSentPacketNumbers:  #Den kan bli ut av range hvis vi popper
                    if ackList[i]==allSentPacketNumbers[j]:
                        allSentPacketNumbers.pop(j)
            
            if(len(allSentPacketNumbers) == 0):
                seq_num += 5
                i += 5
                
    return seq_num 
                     
def PackFile(fileForTransfer): #This function packs the file we want to transfer into packets of size 1460 bytes, and returns a list with the data packed.
    listOfData = []
    with open(fileForTransfer, "rb") as file:
       while True:
           data = file.read(1460)
           if not data:
               break
           listOfData.append(data)
    return listOfData

def UnpackFile(fileToBeUnpacked,outputFileName): #This should unpack the data recieved by the server. 
    print(fileToBeUnpacked) # liste med data mottatt av serveren
    with open(outputFileName,"wb")as outputFIle: # outputFileName er den nye filen,"wb" betyr at filen skal åpnes i binær modus
        for data in fileToBeUnpacked:
            outputFIle.write(data)


def createServer(method):
    print("Her opprettes server:")
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSocket.bind((ip, port))
    print('The server is ready to receive')
    handshakeServer(serverSocket, ip, port)
    
    while True:
            message, clientSocket = serverSocket.recvfrom(1472) #Recieving message
            header_from_msg = message[:12] #Getting the header
            seq, acknum, flags, win = header.parse_header(header_from_msg) #Getting information from header
            ack=seq
            if(flags == 0):
                listOfData.append((seq ,message[12:]))
                sendAck(ack, serverSocket, clientSocket)
            elif(flags != 0 and listOfData): # Remove this when the rest of the code works :) We need a fin function!!!
                syn, ack, fin = header.parse_flags(flags) #We need to extract the fin flag
                if fin == 2:
                    print("First FIN recieved successfully at server from client!")
                    acknowledgment_number = 0
                    flags = 6
                    data= b''
                    msg = header.create_packet(seq, acknowledgment_number, flags, window, data)
                    serverSocket.sendto(msg, clientSocket)
                elif ack == 4:
                    print("Second FIN recieved successfully at server from client!")
                    print(f"dette ligger i posisjon 0 i list of data: {listOfData.pop(0)}")
                    #Her må vi liste ut alt dataen vi har fått inn ...!
                    break

def sendAck(acknowledgment_number, serverSocket, clientSocket): #Creating a function to send acks to client. Will randomly not send ack when -t skipack flag is used
    data = b''
    sequence_number = 0
    flags = 4
    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
    if args.testcase == "skipack":
        if random.random() > 0.5: #Generating a random float between 0 and 1 to simulate a 50% chance to loose a packet.
            serverSocket.sendto(msg, clientSocket)
    else:
        serverSocket.sendto(msg, clientSocket)

def sendingPacket(seq_num,data, clientSocket,serverConnection): #Creating a function to send packets to server. Will randomly skip acks when -t skipack flag is used.
     flags = 0
     packet= header.create_packet(seq_num, 0, flags, window, data)
     if args.testcase == "loss":
        if random.random() > 0.5: #Generating a random float between 0 and 1 to simulate a chance to loose a packet.
          print("just a test")

        else:
            clientSocket.sendto(packet, serverConnection)
     else:
         clientSocket.sendto(packet, serverConnection)

        sequence_number = 0
        acknowledgment_number = 0
        window = 0 
        flags = 4
        
        msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
        serverSocket.sendto(msg, clientAddress)

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
#Nye argumenter som brukes i denne portifolioen:
parser.add_argument("-f", "--file", help="Write in the file you want to transmitt", type=str)
parser.add_argument("-r", "--reliability", help="Type inn the type of reliablity you want", type=str, default='SAW', choices=['SAW', 'GBN', 'SR'])
parser.add_argument("-t", "--testcase", help="Type in if you want to set a type of testcase", type=str, choices=['loss', 'skipack'])
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