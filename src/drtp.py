#TODO: Pass på at funksjonar står i ei logisk rekkjefølge
#TODO: Fjern (og fiks, ikkje fjern utan å fikse :P) alle TODO-meldingar
#TODO: Remove examples from header.py (At the very end).
#TODO: Make sure Loss and skipack are implemented for all functions
#TODO: Make sure only socket errors are caught when using methods that need the socekts error things. We don't wan't other errors to pass. 
#TODO: The finishing message repeats 3 times at the server side, that's not cool.
#TODO: Remove prints (clean output)
#TODO: Bonus tasks
#TODO: Testing in mininet
#TODO: Comment code
#TODO: Make sure you save the output file.
#TODO: Make sure all comments are in english

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

#Function to validate the port number
def check_port(port): #Code to check that the port is written is valid. Inspired from the starter code for portfolio 1. 
    # Try to convert tin input ta an  integer
    try:
        value = int(port)
    except ValueError:
        raise argparse.ArgumentTypeError("Expected an integer but you entered a " + str(type(port))) #Need to convert type(val) to string to append to the string.
    #Check if the port number is within the valid range
    if (value<1024 or value >65535):
        raise Exception("The port number is not valid, please choose a port number from 1024 to 65535")
    return value
# Function to check if the file is valid (exists and is accessible)
# If the file exists, return the file name
def check_file(file):
    if os.path.exists(file):
        return file
    # If the file does not exist, print an error message and exit the program
    else:
        print(f"The file {file} is not valid. Make sure you gave the correct path from the current dictionary")
        sys.exit()

#Handshake functions:
def handshakeServer(serverSocket):
    # Loop until the handshake process is complete
    while True:
        # Receive a message from the client
        message, (args.ip, args.port) = serverSocket.recvfrom(12)
        #Initialize sequence and acknowlegement numbers and data
        sequence_number = 0
        acknowledgment_number = 0
        data = b'0' * 0
        # Extract the first 12 bytes of the recieved message
        data_from_msg = message[:12]

        #Parse the header of the received message
        seq, acknum, flags, win = header.parse_header(data_from_msg)

        # Print the extracted sequence number, acknowledgment number, and flags
        print(f"This is seq: {seq}, this is acknum: {acknum}, this is flags: {flags}")

        # Check if this is the first SYN message from the client
        if seq == 1 and acknum == 0 and flags == 8:
            print("First syn recieved successfully at server from client!")

             # Update acknowledgment number, sequence number, and flags for the SYN-ACK response
            acknowledgment_number = 1
            seqNum = 2
            flags = 12
            # Create the SYN-ACK response packet
            msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)

             # Send the SYN-ACK response to the client
            serverSocket.sendto(msg, (args.ip, args.port))

        # Check if this is the second SYN message from the client   
        if seq == 0 and acknum == 1 and flags == 4:
            print("Second syn recieved successfully at server from client!")
             # Break the loop as the handshake is complete
            break
     # Return the updated sequence number    
    return seqNum
    
def handshakeClient(clientSocket, serverip, port, method, fileForTransfer): #Sends an empty package with a header containing the syn flag. Waits for a ack from the server with a timeout of 500 ms.

    # Initialize sequence and acknowledgment numbers, flags, and data for the SYN message
    sequence_number = 1
    acknowledgment_number = 0
    flags = 8
    data = b'0' * 0

    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data) # Create the SYN message packet
    clientSocket.sendto(msg, (serverip, port)) # Send the SYN message to the server 
    modifiedMessage, serverConnection = clientSocket.recvfrom(12) # Receive a response from the server
    data_from_msg = modifiedMessage[:12]# Extract the first 12 bytes of the received message
    seq, acknum, flags, win = header.parse_header (data_from_msg) #it's an ack message with only the header
    syn, ack, fin = header.parse_flags(flags) # Parse the flags from the received message

    if syn and ack != 0 and acknum == 1: # Check if the received message is a SYN-ACK message
        print("The ack from Server was recieved at Client!!")        
         # Update sequence and acknowledgment numbers, and flags for the final ACK message
        sequence_number = 0
        acknowledgment_number = 1
        flags= 4

        # Create the final ACK message packet
        msg = header.create_packet(sequence_number,acknowledgment_number,flags,window,data)

         # Send the final ACK message to the server
        clientSocket.sendto(msg, (serverip, port))
        #Setter sequencenumber lik 2, for nå er handshake over, og datasendingen skal begynne med pakke 2
        sequence_number = 2

          # Call the transmittAndListen function to start the data transmission
        transmittAndListen(clientSocket, serverConnection, sequence_number)
    else:
          # If the received message is not a SYN-ACK packet, print an error and exit
        print('Error: Did not receive SYN-ACK packet')
        sys.exit()

# Define the function to transmit data and listen for responses from the server
def transmittAndListen(clientSocket, serverConnection, seqNum): #Client 
    

    t0 = time.time()
     # Choose the reliability method based on the user argument and call the respective function
    if(args.reliability == "SAW"):
        seqNum = (int) (stop_and_wait(clientSocket, serverConnection, seqNum))
    elif(args.reliability == "GBN"):
        seqNum = (int) (goBackN(clientSocket, serverConnection, seqNum))
    else:
        seqNum=(int) (selectiveRepeat(clientSocket, serverConnection, seqNum))
    t_end = time.time() - t0
    #Going into Finish-mode:
    while True:
         # Initialize data, acknowledgment_number, and flags for the FIN message
        data = b'0' * 0
        acknowledgment_number = 0
        flags = 2

         # Create the FIN message packet
        msg = header.create_packet(seqNum, acknowledgment_number, flags, window, data)
        #Encoding packet and sending it to server ip and port
        clientSocket.sendto(msg, serverConnection)


         # Receive a response from the server
        modifiedMessage, serverConnection = clientSocket.recvfrom(12)
        

        # Extract the first 12 bytes of the received message
        data_from_msg = modifiedMessage[:12]

         # Parse the header of the received message
        seq, acknum, flags, win = header.parse_header (data_from_msg) #it's an ack message with only the header
        

        # Parse the flags from the received message
        syn, ack, fin = header.parse_flags(flags)

         # Check if the received message is a FIN-ACK message
        if(fin == 2 and ack == 4):
             # Update the sequence and acknowledgment numbers, and flags for the final ACK message
            sequence_number = 0
            acknowledgment_number = seqNum
            flags = 4

            # Create the final ACK message packet
            msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)

            # Send the final ACK message to the server
            clientSocket.sendto(msg, serverConnection)
            print("We are done at client side, finishing")
            break
    #Close the client socket
    
    size = os.path.getsize(args.file)/1000000 #Getting the size of the file in MB.
    time_string = str(round(t_end,2)) #Rounding the time to have to decimal places, and converting from float to string.
    throughput = size*8/t_end #Calculating the thoruhgput (multiply by 8 to convert from bytes to bits).
    headline = ["{:<8}".format("ServerID"), "{:<11}".format("time"), "{:<15}".format("Transfer"), "{:<11}".format("Bandwidth")]
    output = ["{:<8}".format(str(serverConnection[0])), "{:<11}".format(time_string + " s"), "{:<15}".format(str(round(size,4)) + " MB"), "{:<11}".format(str(round(throughput,2)) + " Mbps")] #Formatting the output

    print("") #Adding a line before and after the table to make it easier to read. 
    print("\t".join(headline)) #Printing the header for the output
    print("\t".join(output)) #Printing the needed output for the 
    print("")
    print("Closing socket")
    clientSocket.close()

# Define the stop_and_wait function for the client-side
def stop_and_wait(clientSocket, serverConnection, seq_num): 
     # Initialize a counter variable
    i = 0

      # Continue sending packets while there are packets in the PackedFile list
    while i < len(PackedFile):
        # Call the function to send a packet, which will simulate packet loss if the flag is used
        sendingPacket(seq_num, PackedFile[i], clientSocket, serverConnection)  #Calling a function to send a packet, which will simulate packet loss if the flag is used.
        try:
             # Listen for an ACK message from the server
            ack, serverConnection =  clientSocket.recvfrom(1472) #Listening for message from server
        except:
            continue #If no message is recieved within the timelimit set, we go back to the start of the function.
        header_from_msg = ack[:12] #Extracting header from message
        seq, acknum, flags, win = header.parse_header (header_from_msg) #Getting information from the header
        syn, ack, fin = header.parse_flags(flags) #Getting the flags
        if acknum == seq_num: #If the recieved acknum equals the seqnum sent, the server recieved the package, and we can send the next one. If not, the same package is retransmitted.
             # Increment the sequence number and counter variable to send the next packet
            seq_num +=1
            i+=1
     # Return the final sequence number after all packets have been sent        
    return seq_num

# Define the goBackN function for the client-side
def goBackN(clientSocket, serverConnection, seq_num):
    i = 0 #initialise a counter variable
    ackList = [] # Initialize an empty list to store acknowledgment numbers

    while i < len(PackedFile): #Sending the packets within this loop. If not divisable by n, we send the remaining n packets as empty packets. 
        ackList = []
        for j in range(args.windowSize): #sending the packets
            if j + i >= len(PackedFile): #If the packets are not divisable by n, we send empty packets so that the total adds up to n
                sendingPacket(seq_num + j, b'0' * 0, clientSocket,serverConnection)
            else:
                 # Send packets from the PackedFile list
                sendingPacket(seq_num + j, PackedFile[j + i], clientSocket,serverConnection)

        # Receive ACKs for the packets sent
        for j in range(args.windowSize): #(Hopefully) Recieving n acks
            try:
                # Listen for an ACK message from the server
                ack, serverConnection =  clientSocket.recvfrom(12)
               
                 # Extract the header from the received ACK message
                header_from_msg = ack[:12]

                # Parse the header to get the sequence number, acknowledgment number, flags, and window size
                seq, acknum, flags, win = header.parse_header (header_from_msg) #it's an ack message with only the header

                # Parse the flags from the header
                syn, ack, fin = header.parse_flags(flags)
                ackList.append(acknum) #Appending the recieved acknum to the list. 
            except: #If something wrong happens (for example: not recieving an ack within the time limit), we break out of the for loop
                #TODO: Exception should not be generic, but a timeout exception
                break
        if ackList == list(range(seq_num, seq_num + args.windowSize)): #If the acks recieved are correct and in correct sequence, we can send the next 5 packets.
            seq_num += args.windowSize
            i += args.windowSize
    # Return the final sequence number after all packets have been sent
    return seq_num

def selectiveRepeat(clientSocket, serverConnection, seq_num):
    i = 0
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

def serverSR(serverSocket, seqNum, recivedData):
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
            if seq == nextSeq: #Is the seq number recieved the right one? If yes, append to recivedData. If not, append to bufferdata.
                recivedData.append(message[12:])
                nextSeq += 1 #The next seq we need is one higher
                while i < len(nestedBufferList): #Looping through the bufferdata to see if any of the buffered data can be added. We always do this when we add data to recivedData
                    if nestedBufferList[i][0] == nextSeq: #Does the bufferlist contain the next value which should be stored?
                        recivedData.append(nestedBufferList.pop(i)[1]) #If yes, we store it and remove it from nestedBufferList
                        nextSeq += 1 #The next seq number we want is one higher
                        i = 0 #If data is added, we completely loop through once more to see if any new data can be added. Do this by setting i to 0.
                    else:
                        i += 1 #Incrementing i if no data is added to the recivedData
                i = 0
            elif seq not in nestedBufferList: #If the recieved message is not already in the list of recieved data, we append it. Since acks can be lost, we need to add a check before adding.
                nestedBufferList.append([seq, message[12:]])
        else: #We're done, finishing the code. 
            finish = CheckForFinish(fin, ack, serverSocket, clientSocket) #TODO: Me har brukt mykje clientAdress og ClientSOcket om kvarandre, burde konsekvent bruke ein av delene.
            if finish:
                #TODO: Her må vi liste ut alt dataen vi har fått inn ...! TODO
                return recivedData

#This method takes in the filename specified by the user in the parameter. It chops the file into chunkcs/packets of 1460 bytes and add them into an array. The array is returned to the clients sending method
def PackFile(fileForTransfer): #This function packs the file we want to transfer into packets of size 1460 bytes, and returns a list with the data packed. 
    listOfData = [] 
    #Read as binary = "rb":
    with open(fileForTransfer, "rb") as file:
        while True:
            data = file.read(1460)
            if not data:
                break
            listOfData.append(data)   
    return listOfData
        
#This method takes in the array containing the recived data from the client and the filename specified by the user 
def UnpackFile(fileToBeUnpacked,outputFileName):
    # outputFileName is the new file,"wb" means that a new file is to be written, and the data should be treatet as binary.
    with open(outputFileName,"wb") as outputFile: 
        for data in fileToBeUnpacked:
            outputFile.write(data)
            
#This methon creates a server and watis for a connection form client
#Once the connections is established, it uses reliability function to recevie and extrac the file data sent by the client.  
#It then extracts the file data and stores it in a the server
def createServer():
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #Creates a socket 
    serverSocket.bind((args.bind, args.port)) #bind the socekt to a specific IP address and port number
    print('The server is ready to receive')   #print a messeage to indicate that the server is ready to receive data

    seqNum = (int) (handshakeServer(serverSocket)) #
    recievedData = [] #Creates and empty lis to store the received data. All 3 methods use an empty array

    if(args.reliability == "SAW"):  #iif SAW is passed in
        recievedData = serverSaw(serverSocket, seqNum, recievedData) #calles the method serverSaw and store the data in receviedData
    elif(args.reliability == "GBN"): #if GBN is passed in
        recievedData = serverGBN(serverSocket, seqNum, recievedData)  #calles the method serverGBN and store the data in receviedData               
    else:
        recievedData = serverSR(serverSocket, seqNum, recievedData)  #calles the method serverSR and store the data in receviedData
    
    UnpackFile(recievedData, args.newFile)  #Unpakc the file 
    
#This method implemenst the Stop and wait for server. The methos listens to socket for incomming message from the client
#It waits until a message is received and send acknowledgement message back back to client.
def serverSaw(serverSocket, seqNum, recievedData):
    while True:
        message, clientSocket = serverSocket.recvfrom(1472) #Recieving message
        header_from_msg = message[:12] #Getting the header e
        seq, acknum, flags, win = header.parse_header(header_from_msg) #Getting information from header
        ack=seq
        if(flags == 0):   #if the flags is zero, this is a new packet
            recievedData.append(message[12:])   #save the data
            sendAck(ack, serverSocket, clientSocket)  #Send the ack message
        elif(flags != 0 and recievedData): # Remove this when the rest of the code works :) We need a fin function!!!
            syn, ack, fin = header.parse_flags(flags) #We need to extract the fin flag
            finish = CheckForFinish(fin, ack, serverSocket, clientSocket)
            if finish:
            #Her må vi liste ut alt dataen vi har fått inn ...!
                return recievedData
    
#This methos sends an acknowledment (ack) packet to client with given ack number
#The method also implements skipakc flag that randomly skips sending acks. 
def sendAck(acknowledgment_number, serverSocket, clientSocket): #Creating a function to send acks to client. Function will randomly skip sending acks if the -t skipack flag is used 
    data = b''         #intializes an empty byte string called data
    sequence_number = 0    #sets sequence_number to 0
    flags = 4             #sets flags variable to 4
    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)  #calls the create_packet methon to create a packet
    if args.testcase == "skipack":#checks if the command-line argument "testcase" is set to skipack
        if random.random() > 0.5: #Generating a random float between 0 and 1 to simulate a 50% chance to loose a packet.
            serverSocket.sendto(msg, clientSocket)  # sending the ack to the client
    else:
        serverSocket.sendto(msg, clientSocket)#if the flag is not set the ACK is sent to the client.

#This method sends packet to server
# Will randomly skip sending packets when -t skipack flag is used.
def sendingPacket(seq_num, data, clientSocket, serverConnection): 
     flags = 0 #sets flags variable to 0
     packet= header.create_packet(seq_num, 0, flags, window, data)  #calls the create_packet methon to create a packet
     if args.testcase == "loss":  #: Checks if the args.testcase flag is set to "loss"
        if random.random() > 0.5: #Generating a random float between 0 and 1 to simulate a chance to loose a packet.
            clientSocket.sendto(packet, serverConnection)
     else:
         clientSocket.sendto(packet, serverConnection) #if the flag is not set, the packet is sent to the server


#This a method for a server that use Go-Back-N to recived data from client. 
#It takes in three parameters:serverSocket,Seqnum and recivedData. 
#


def serverGBN(serverSocket, seqNum, recivedData): #Server go back N method 
    bufferData = []  #create an empty list
    checkSeqNum = seqNum  
    ackNum = seqNum
    while True:  
        message, clientAddress = serverSocket.recvfrom(1472)  #Receive a message and client address
        header_from_msg = message[:12]   #get the header from th
        seq, acknum, flags, win = header.parse_header(header_from_msg)
        syn, ack, fin = header.parse_flags(flags) #Getting information for the header
        if(flags == 0):  #if flags = 0
            if checkSeqNum == seq:  #if the number recived is the right one? If yes, append to bufferData 
                bufferData.append(message[12:])
                checkSeqNum += 1     #oppdate the checkSeqNum
                if(len(bufferData) == args.windowSize): #If all data from the current window has been added
                    for i in bufferData:   
                        recivedData.append(i) #Add all data to the storage
                    bufferData.clear() #Clear the buffer to make space for new data
                    seqNum += args.windowSize
                    checkSeqNum = seqNum
                    for i in range(args.windowSize): #Sending the amount of packet acks to the client
                        sendAck(ackNum, serverSocket, clientAddress) 
                        ackNum+=1
            elif(seq < checkSeqNum):   #
                print(f"ackNum er: {ackNum}")
                #This check prevents ackNum from growing out of control and keeps the acknumbers correct if an ack was lost in last transmission
                if(ackNum >= checkSeqNum):
                    ackNum = checkSeqNum
                    ackNum -= args.windowSize
                for i in range(args.windowSize): #Sending the amount of packet acks to the client
                        sendAck(ackNum, serverSocket, clientAddress)
                        ackNum+=1       
            else: #Clearing the bufferdata.
                checkSeqNum = seqNum
                bufferData.clear()
        else:
            finish = CheckForFinish(fin, ack, serverSocket, clientAddress)
            if finish:
                return recivedData

def CheckForFinish(fin,ack,serverSocket,clientSocket):#TODO fiks
    if fin == 2:
        print("First FIN recieved successfully at server from client!") #TODO: Remove unneeded prints
        acknowledgment_number = 0
        flags = 6
        data= b''
        seq = 0
        msg = header.create_packet(seq, acknowledgment_number, flags, window, data)
        serverSocket.sendto(msg, clientSocket) #Sending first ack
    elif ack == 4: # Ack for the first FIN is received
        print("Second FIN recieved successfully at server from client!") #TODO: Remove unneeded prints
        return True # indicate finish
    return False    #  if neither the first nor second FIN siganl, return false, so the communication is not finished    

#This method takes in arguments passed in by the user. The defined IP to the serverm the serverport, which reliability method and what file the user wants to transfer.
def createClient(serverip, port, method, fileForTransfer):
    print("Her opprettes client:")
    #Creating a udp socket for the client
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #Calling the hanshake method to start transmission with server
    handshakeClient(clientSocket, serverip, port, method, fileForTransfer) 
    
#Defining the argumentParser
parser = argparse.ArgumentParser(description='The arguments used when calling the program')
#server arguments
parser.add_argument("-s", "--server", help="try to type '-s", action="store_true")
parser.add_argument("-b", "--bind", help="define an ip-address for the clients to connect to the host", type=check_IP, default=socket.gethostbyname(socket.gethostname()))
parser.add_argument("-F", "--newFile", help="Write the name of the new file and type to create from transmission", type=str)
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
        if(args.client == True):
            if(args.file):
                socket.setdefaulttimeout(0.5) #Setting socket timeout for the client.
                PackedFile = PackFile(args.file) #Packing the file we are going to send in sizes of 1460 bytes.
                createClient(args.serverip, args.port, args.reliability, args.file)
            else:
                print("When you create a client, you also need to define which file to transfer to the server")
        if(args.server == True):
            if(args.newFile):
                createServer()
            else:
                print("A new filename for the recieved file must be")
else:
    print("You have to use either the -s (server) og -c (client) flag.")
    sys.exit()