#I denne filen skal vi ha nødvendig kode for server og client + DRTP (men ikke header, den er i en egen fil)
#Flags:
#-f -> filename?
#-r -> hvilken metode client skal sende på i DRTP
#-t -> Forskjell mellom client og server: Skipack er servermetode, loss er clientmetode ?

#TODO: Pass på at funksjonar står i ei logisk rekkjefølge
#TODO: Fjern (og fiks, ikkje fjern utan å fikse :P) alle TODO-meldingar
#TODO: Remove exmpales from header.py (At the very end).
#TODO: Make sure Loss and skipack are implemented for all functions
#TODO: Make sure only socket errors are caught when using methods that need the socekts error things. We don't wan't other errors to pass. 
#TODO: The finishing message repeats 3 times at the server side, that's not cool.
#TODO: Remove prints (clean output)
#TODO: Bonus tasks
#TODO: Testing in mininet

from socket import timeout
import header
import argparse
import socket
import sys
import re #Importing regex to check ip-adress for errors
import inspect # Brukt for å få informasjon om objekt i koden. https://docs.python.org/3/library/inspect.html
import os #Used to see if the file name given is valid (exists and is accessible)
import random
import time
import select

window = 64000 #Window is always 64000, declaring it as a global variable at the start of the code.

#The following 3 functions are user argument checks
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

#Handshake functions:
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
        transmittAndListen(clientSocket, serverConnection, sequence_number)
    else:
        print('Error: Did not receive SYN-ACK packet')
        sys.exit()

def transmittAndListen(clientSocket, serverConnection, seqNum): #Client 
    
    if(args.reliability == "SAW"):
        seqNum = (int) (stop_and_wait(clientSocket, serverConnection, seqNum))
    elif(args.reliability == "GBN"):
        seqNum = (int) (goBackN(clientSocket, serverConnection, seqNum))
    else:
        seqNum=(int) (selectiveRepeat(clientSocket, serverConnection, seqNum))

    #Going into Finish-mode:
    print("Going into Finish-mode at client")
    while True:
        data = b'0' * 0
        acknowledgment_number = 0
        flags = 2
        msg = header.create_packet(seqNum, acknowledgment_number, flags, window, data)
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
            print("We are done at client side, finishing")
            break
    print("Closing socket")
    clientSocket.close()

def stop_and_wait(clientSocket, serverConnection, seq_num): #Stop and wait method client side
    i = 0
    while i < len(PackedFile):
        print("sender data i StopAndWait metoden")
        sendingPacket(seq_num,PackedFile[i], clientSocket,serverConnection)  #Calling a function to send a packet, which will simulate packet loss if the flag is used.
        try:
            ack, serverConnection =  clientSocket.recvfrom(1472) #Listening for message from server
        except:
            continue #If no message is recieved within the timelimit set, we go back to the start of the function.
        header_from_msg = ack[:12] #Extracting header from message
        seq, acknum, flags, win = header.parse_header (header_from_msg) #Getting information from the header
        syn, ack, fin = header.parse_flags(flags) #Getting the flags
        if acknum == seq_num: #If the recieved acknum equals the seqnum sent, the server recieved the package, and we can send the next one. If not, the same package is retransmitted.
            seq_num +=1
            i+=1
    return seq_num

def goBackN(clientSocket, serverConnection, seq_num):
    i = 0 #initialising the auxilia
    print(f" lengde av listofData: {len(PackedFile)}")
    ackList = []

    while i < len(PackedFile): #Sending the packets within this loop. If not divisable by n, we send the remaining n packets as empty packets. 
        ackList = []
        for j in range(args.windowSize): #sending the packets
            if j + i >= len(PackedFile): #If the packets are not divisable byn, we send empty packets so that the total adds up to n
                sendingPacket(seq_num + j, b'0' * 0, clientSocket,serverConnection)
            else:
                sendingPacket(seq_num + j, PackedFile[j + i], clientSocket,serverConnection)

        for j in range(args.windowSize): #(Hopefully) Recieving n acks
            try:
                ack, serverConnection =  clientSocket.recvfrom(12)
                print("test")
                header_from_msg = ack[:12]
                seq, acknum, flags, win = header.parse_header (header_from_msg) #it's an ack message with only the header
                syn, ack, fin = header.parse_flags(flags)
                ackList.append(acknum) #Appending the recieved acknum to the list. 
            except: #If something wrong happens (for example: not recieving an ack within the time limit), we break out of the for loop
                print("Breaker ut av reciving packets")
                break

        if ackList == list(range(seq_num, seq_num + args.windowSize)): #If the acks recieved are correct and in correct sequence, we can send the next 5 packets.
            seq_num += args.windowSize
            i += args.windowSize
    
    return seq_num

def selectiveRepeat(clientSocket, serverConnection, seq_num):

    i = 0
    print(f" lengde av listofData: {len(PackedFile)}")
    toBeRetransmitted = [] #A list which will be used to know which data needs to be retransmitted. Data is retransmitted if no ack is recieved.
    while i < len(PackedFile): #The final packages are not sent in a bunch of n (window size), but rather based on how many packets are left to send
        for j in range(args.windowSize): #sending the first n packets
            try:
                sendingPacket(seq_num + j, PackedFile[j + i], clientSocket,serverConnection) #Sending the packets
                toBeRetransmitted.append(seq_num + j) #adding the seq_num to toBeRetransmitted to signal which seq_numbers were sent.
            except:
                break #Break out of the loop if we can't send the packet, which will happen if we reach try to send a part of PackedFile which is out of range.
            #TODO: Change from generic exception to out of bonds exception
        while toBeRetransmitted != []: #Continuously waits for acks and resends packages until all acks are recieved. 
            try:
                ack, serverConnection =  clientSocket.recvfrom(12) #Getting adress and message from server
                header_from_msg = ack[:12] #Extracting header from message
                seq, acknum, flags, win = header.parse_header (header_from_msg) #Getting flags from the header
                syn, ack, fin = header.parse_flags(flags)
                toBeRetransmitted.remove(acknum) #If we recieve an ack, that means we don't need to retransmitt the message with the corresponding seq, so we remove it from the list of data we need to retransmitt. 
            except timeout: #If we do not get all acks within the socket timeout, we enter this loop, where we resent all packets that have not recieved an ack. 
                for k in toBeRetransmitted: #Looping though all packets needing to be retransmitted
                    sendingPacket(k, PackedFile[k-2], clientSocket,serverConnection) #Sending all packets which need to be retransmitted. Using k-2 as the package number is 2 bigger than the ack num.
        i += args.windowSize #increasing i by window size
        seq_num += args.windowSize #increasing seq num by window size
    return seq_num #Returning the seq num

def serverSR(serverSocket, seqNum, listOfData):
    nestedBufferList = [] #In this nested list, we store the data recieved from the server. 
    nextSeq = seqNum #The next seq.number we are waiting for
    i=0
    while True:
        message, clientSocket = serverSocket.recvfrom(1472) #Recieving the message
        header_from_msg = message[:12]
        seq, acknum, flags, win = header.parse_header(header_from_msg)
        syn, ack, fin = header.parse_flags(flags) #Getting information from the header
        sendAck(seq, serverSocket, clientSocket) #Sending an ack to the client for the recieved package. The ack is equal to the seq for the package recieved
        if flags == 0: #If flags = 0, this is a normal package containing data.
            if seq == nextSeq: #Is the seq number recieved the right one? If yes, append to listOfData. If not, append to bufferdata.
                listOfData.append(message)
                nextSeq += 1 #The next seq we need is one higher
                while i < len(nestedBufferList): #Looping through the bufferdata to see if any of the buffered data can be added. We always do this when we add data to listOfData
                    if nestedBufferList[i][0] == nextSeq: #Does the bufferlist contain the next value which should be stored?
                        listOfData.append(nestedBufferList.pop(i)[0]) #If yes, we store it and remove it from nestedBufferList
                        nextSeq += 1 #The next seq number we want is one higher
                        i = 0 #If data is added, we completely loop through once more to see if any new data can be added. Do this by setting i to 0.
                    else:
                        i += 1 #Incrementing i if no data is added to the listOfData
                i = 0
            elif seq not in nestedBufferList: #If the recieved message is not already in the list of recieved data, we append it. Since acks can be lost, we need to add a check before adding.
                nestedBufferList.append([seq, message])
        else: #We're done, finishing the code. 
            print(len(listOfData)) #TODO: remove. Checking that the length of listOfData is correct
            finish = CheckForFinish(fin, ack, serverSocket, clientSocket) #TODO: Me har brukt mykje clientAdress og ClientSOcket om kvarandre, burde konsekvent bruke ein av delene.
            if finish:
                #TODO: Her må vi liste ut alt dataen vi har fått inn ...! TODO
                break

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

def createServer():
    print("Her opprettes server:")
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSocket.bind((args.bind, args.port))
    print('The server is ready to receive')

    seqNum = (int) (handshakeServer(serverSocket))
    listOfData = [] #All 3 methods use an empty array
    
    if(args.reliability == "SAW"):
        serverSaw(serverSocket, seqNum, listOfData)
    elif(args.reliability == "GBN"):
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
            finish = CheckForFinish(fin, ack, serverSocket, clientSocket)
            if finish:
            #Her må vi liste ut alt dataen vi har fått inn ...!
                break

def sendAck(acknowledgment_number, serverSocket, clientSocket): #Creating a function to send acks to client. Function will randomly skip sending acks if the -t skipack flag is used 
    data = b''
    sequence_number = 0
    flags = 4
    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
    if args.testcase == "skipack":
        if random.random() > 0.5: #Generating a random float between 0 and 1 to simulate a 50% chance to loose a packet.
            serverSocket.sendto(msg, clientSocket)
    else:
        serverSocket.sendto(msg, clientSocket)

def sendingPacket(seq_num, data, clientSocket, serverConnection): #Creating a function to send packets to server. Will randomly skip sending packets when -t skipack flag is used.
     flags = 0
     packet= header.create_packet(seq_num, 0, flags, window, data)
     if args.testcase == "loss":
        if random.random() > 0.5: #Generating a random float between 0 and 1 to simulate a chance to loose a packet.
            clientSocket.sendto(packet, serverConnection)
     else:
         clientSocket.sendto(packet, serverConnection)

def serverGBN(serverSocket, seqNum, listOfData): #Server go back N method
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
                if(len(bufferData) == args.windowSize): #If all data from the current window has been added
                    print("Bufferdata er lik n")
                    for i in bufferData:  #Add all data to the storage
                        listOfData.append(i)
                    bufferData.clear() #Clear the buffer to make space for new data
                    seqNum += args.windowSize
                    checkSeqNum = seqNum
                    for i in range(args.windowSize): #Sending the amount of packet acks to the client
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
            print("Kommer inn i avslutningsfasen i server for SR metode")
            finish = CheckForFinish(fin, ack, serverSocket, clientAddress)
            if finish:
                #Her må vi liste ut alt dataen vi har fått inn ...! TODO
                break

def CheckForFinish(fin,ack,serverSocket,clientSocket):#TODO fiks
   
    if fin == 2:
        print("First FIN recieved successfully at server from client!")
        acknowledgment_number = 0
        flags = 6
        data= b''
        seq = 0
        msg = header.create_packet(seq, acknowledgment_number, flags, window, data)
        serverSocket.sendto(msg, clientSocket) #Sending first ack
    elif ack == 4: # Ack for the first FIN is received
        print("Second FIN recieved successfully at server from client!")
        #TODO Her må vi liste ut alt dataen vi har fått inn ...!
        return True # indicate finish
    return False    #  if neither the first nor second FIN siganl, return false, so the communication is not finished    

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
parser.add_argument("-t", "--testcase", help="Type in if you want to set a type of testcase", type=str, choices=['loss', 'skipack'])
parser.add_argument("-p", "--port", help="type -p and wanted portnumber, or default port 8080 will be set", type=check_port, default=8080)
parser.add_argument("-r", "--reliability", help="Type inn the type of reliablity you want", type=str, default='SAW', choices=['SAW', 'GBN', 'SR'])
parser.add_argument("-w", "--windowSize", help="Select the windowSize for the transmission of packets",type=int, default=5, choices=[5, 10, 15])
args = parser.parse_args()

if args.client == True or args.server == True:
    if(args.client == True and args.server == True):
        print("You have to use either the -s (server) og -c (client) flag, not both")
        sys.exit()
    else:
        if args.client == True:
            socket.setdefaulttimeout(0.005) #Setting socket timeout for the client.
            PackedFile = PackFile(args.file) #Packing the file we are going to send in sizes of 1460 bytes.
            createClient(args.serverip, args.port, args.reliability, args.file)
        if(args.server == True):
            createServer()
else:
    print("You have to use either the -s (server) og -c (client) flag.")
    sys.exit()