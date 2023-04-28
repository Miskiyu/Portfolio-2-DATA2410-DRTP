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
import os #Used to see if the file name given is valid (exists and is accessible)
import random
import time

window = 64000 #Window is always 64000, declaring it as a global variable at the start.
def check_IP(ip_address): #Code to check that the ip adress is valid. Taken from https://www.abstractapi.com/guides/python-regex-ip-address. Comments added by us.
    if not re.search(r"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", ip_address): #Check that the format is like this: "XXX.XXX.XXX.XXX", where X is a number between 0 and 9.
        raise Exception(f"The IP address {ip_address} is not valid. It needs to be in the format X.X.X.X, where each X is a number from 0 to 255.")

    ip_split = ip_address.split(".") #Splits the IP-adress string based on the periods, and in the for loop checks that each byte is from 0 to 255.
  
    for ip_part in ip_split: #Checking that each number in the IP-adress is between 0 and 255. 
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

def check_file(file):
    if os.path.exists(file):
        return file
    else:
        print(f"The file {file} is not valid. Make sure you gave the correct path from the current dictionary")
        sys.exit()

def handshakeServer(serverSocket):
    while True:
        message, (args.ip, args.port) = serverSocket.recvfrom(12)

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
            serverSocket.sendto(msg, (args.ip, args.port))

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
    
    modifiedMessage, serverConnection = clientSocket.recvfrom(12)

    
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
        seqNum=(int) (selectiveRepeat(clientSocket, fileForTransfer, serverConnection, seqNum))

    #Going into Finish-mode:
    print("Going into Finish-mode at client for SR method")
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

        modifiedMessage, serverConnection = clientSocket.recvfrom(12)
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
    serverSocket.bind((args.bind, args.port))
    print('The server is ready to receive')

    seqNum = (int) (handshakeServer(serverSocket))
    listOfData = []
    
    if(method == "SAW"):
        serverSaw(serverSocket, seqNum, listOfData)
    elif(method == "GBN"):
        serverGBN(serverSocket, seqNum, listOfData)                     
    else:
        serverSR(serverSocket, seqNum, listOfData)

def serverSaw(serverSocket, seqNum, listOfData):
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

def serverGBN(serverSocket, seqNum, listOfData):
    bufferData = []
    checkSeqNum = seqNum
    ackNum = seqNum
    while True:
        message, clientAddress = serverSocket.recvfrom(1472)
        header_from_msg = message[:12]
        seq, acknum, flags, win = header.parse_header(header_from_msg)
        syn, ack, fin = header.parse_flags(flags)
        if(flags == 0):
            print("Henter ut melding der flagg er 0")
            print(f"chcechSeqNum: {checkSeqNum}")
            print(f"seq: {seq}")
            if checkSeqNum == seq:
                bufferData.append(message[12:])
                checkSeqNum += 1
                if(len(bufferData) == 5):
                    print("Bufferdata er lik 5")
                    for i in bufferData:
                        listOfData.append(i)
                    bufferData.clear()
                    seqNum += 5
                    checkSeqNum = seqNum
                    for i in range(5): #Sending the 5 acks to the client
                        print(f"We managed to reach line {inspect.currentframe().f_lineno} in the code!")
                        data = b''
                        sequence_number = 0
                        acknowledgment_number = ackNum
                        flags = 4
                        msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)   
                        serverSocket.sendto(msg, clientAddress)
                        ackNum+=1
            else:
                print("Kommer inn i else i GBN")
                checkSeqNum = seqNum
                bufferData.clear()
        else:
            print("Kommer inn i avslutningsfasen i server for GBN metode")
            if fin == 2:
                print("First FIN recieved successfully at server from client!")
                serverSocket.sendto(msg, clientAddress) #Function to send acks..
            elif ack == 4:
                print("Second FIN recieved successfully at server from client!")
                #Her må vi liste ut alt dataen vi har fått inn ...!
                break

def serverSR(serverSocket, seqNum, listOfData):
    bufferData = []
    checkSeqNum = seqNum
    ackNum=seqNum
    while True:
        message, clientAddress = serverSocket.recvfrom(1472)
        header_from_msg = message[:12]
        seq, acknum, flags, win = header.parse_header(header_from_msg)
        syn, ack, fin = header.parse_flags(flags)
        if(flags == 0):
            print("Henter ut melding der flagg er 0")
            print(f"chcechSeqNum: {checkSeqNum}")
            print(f"seq: {seq}")
            if checkSeqNum == seq:
                bufferData.append(message[12:])
                checkSeqNum += 1
                if(len(bufferData) == 5):
                    print("Bufferdata er lik 5")
                    for i in bufferData:
                        listOfData.append(i)
                    bufferData.clear()
                    seqNum += 5
                    checkSeqNum = seqNum
                    for i in range(5): #Sending the 5 acks to the client
                        print(f"We managed to reach line {inspect.currentframe().f_lineno} in the code!")
                        data = b''
                        sequence_number = 0
                        acknowledgment_number = ackNum
                        flags = 4
                        
                        msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
                        serverSocket.sendto(msg, clientAddress)
                        ackNum+=1
            else: #Går inn i else hvis det er feil rekkefølge og sender på nytt
                print("Kommer inn i else i SR,det vil si at de ikke ble send i riktig rekkefølge ")
                flags = 4
                ackNum= checkSeqNum
                sequence_number = seqNum
                acknowledgment_number = ackNum
                data = b''
                packet  = header.create_packet(sequence_number, acknowledgment_number,flags,window,data)
                serverSocket.sendto(packet,clientAddress)
                #må sjekke for ack også, noe jeg ikk
        else:
            print("Kommer inn i avslutningsfasen i server for SR metode")
            if fin == 2:
                print("First FIN recieved successfully at server from client!")
                data = b''
                sequence_number = 0
                acknowledgment_number = 0
                flags = 6
                msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
                serverSocket.sendto(msg, clientAddress)
            elif ack == 4:
                print("Second FIN recieved successfully at server from client!")
                #Her må vi liste ut alt dataen vi har fått inn ...!
                break

def CheckForFinish(flags, listOfData):#This is just a placeholder function for now. TODO fiks
    print("This is just a test!")
    print(flags)
    print(listOfData)

def createClient(serverip, port, method, fileForTransfer):
    print("Her opprettes client:")
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    handshakeClient(clientSocket, serverip, port, method, fileForTransfer) #Sending a packet with the syn flag to the server, if an ack is recieved transmission of data starts.
    

#Defining the argumentParser
parser = argparse.ArgumentParser(description='The arguments used when calling the program')
#server arguments
parser.add_argument("-s", "--server", help="try to type '-s", action="store_true")
parser.add_argument("-b", "--bind", help="define an ip-address for the clients to connect to the host", type=check_IP, default=socket.gethostbyname(socket.gethostname()))
#client arguments
parser.add_argument("-c", "--client", help="try to type '-c", action="store_true")
parser.add_argument("-I", "--serverip", help="Write the IP-address of the server to connect", type=check_IP, default=socket.gethostbyname(socket.gethostname()))
parser.add_argument("-f", "--file", help="Write in the file you want to transmitt", type=check_file)
#shared arguments
parser.add_argument("-p", "--port", help="type -p and wanted portnumber, or default port 8080 will be set", type=check_port, default=8080)
parser.add_argument("-r", "--reliability", help="Type inn the type of reliablity you want", type=str, default='SAW', choices=['SAW', 'GBN', 'SR'])
#Nye argumenter som brukes i denne portifolioen:
parser.add_argument("-t", "--testcase", help="Type in if you want to set a type of testcase", type=str, choices=['loss', 'skipack'])
args = parser.parse_args()

if args.client == True or args.server == True:
    if(args.client == True and args.server == True):
        print("You have to use either the -s (server) og -c (client) flag, not both")
        sys.exit()
    else:
        if args.client == True:
            socket.setdefaulttimeout(0.5) #Setting socket timeout for the client.
            PackFile(args.file)
            if(check_port(args.port) and check_IP(args.serverip)):
                createClient(args.serverip, args.port, args.reliability, args.file)
        if(args.server == True):
            if(check_port(args.port) and check_IP(args.bind)):
                createServer(args.reliability)
else:
    print("You have to use either the -s (server) og -c (client) flag.")
    sys.exit()