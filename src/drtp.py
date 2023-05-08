#TODO: Make sure all methods are typed correctly.

from socket import timeout
import header
import argparse
import socket
import sys
import re #Importing regex to check ip-adress for errors
import os #Used to see if the file name given is valid (exists and is accessible)
import time

packets_retransmitted = 0 #A global variable to see how many packets were retransmitted.
allTimeouts = [] #Tracking timeouts to print out statistics from dynamic RTT
perPacketRoundTripTime = [] #Tracking roundtriptime to calculate RTT
window = 64000 #Window is always 64000, declaring it as a global variable at the start of the code.

#The following 4 functions are user argument checks

#Checks if the timeout inputted by the user is correct. If it's a float, the default timeout is set to that number.
#If the default timeout is "dyn", the default timeout is set to 0.5, and later changed based on the time used to send packets.
def check_timeout(timeout):
    try: #Checking if timeout is a float
        time = float(timeout)
    except ValueError: #If it's not a float, checking if it's "dyn"
        if timeout == "dyn":
            return timeout
        else: #If it's neither a float nor "dyn", raising an error.
            raise argparse.ArgumentTypeError("Expected a float or dyn but you entered a " + str(type(timeout))) #Need to convert type(val) to string to append to the string.
    socket.setdefaulttimeout(time) #Setting socket timeout for the client. It is 0.
    return time

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
        message, (args.ip, args.port) = serverSocket.recvfrom(12)# Receive a message from the client
        sequence_number = 0 #Initialize sequence and acknowlegement numbers and data
        acknowledgment_number = 0
        data = b'0' * 0 # Extract the first 12 bytes of the recieved message
        data_from_msg = message[:12] #Parse the header of the received message
        seq, acknum, flags, win = header.parse_header(data_from_msg)

        if seq == 1 and acknum == 0 and flags == 8: # Check if this is the first SYN message from the client
             # Update acknowledgment number, sequence number, and flags for the SYN-ACK response
            acknowledgment_number = 1
            seqNum = 2
            flags = 12
            # Create the SYN-ACK response packet
            msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)
            serverSocket.sendto(msg, (args.ip, args.port))# Send the SYN-ACK response to the client

        if seq == 0 and acknum == 1 and flags == 4: # Check if this is the second SYN message from the client
            print("A client has successfully connected to the server!")
            break# Break the loop as the handshake is complete
     # Return the updated sequence number
    return seqNum

def handshakeClient(clientSocket): #Sends an empty package with a header containing the syn flag. Waits for a ack from the server with a timeout of 500 ms.

    # Initialize sequence and acknowledgment numbers, flags, and data for the SYN message
    sequence_number = 1
    acknowledgment_number = 0
    flags = 8
    data = b'0' * 0

    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data) # Create the SYN message packet
    clientSocket.sendto(msg, (args.serverip, args.port)) # Send the SYN message to the server
    modifiedMessage, serverConnection = clientSocket.recvfrom(12) # Receive a response from the server
    data_from_msg = modifiedMessage[:12]# Extract the first 12 bytes of the received message
    seq, acknum, flags, win = header.parse_header (data_from_msg) #it's an ack message with only the header
    syn, ack, fin = header.parse_flags(flags) # Parse the flags from the received message

    if syn and ack != 0 and acknum == 1: # Check if the received message is a SYN-ACK message
        print("The SYN-ACK from Server was recieved at Client")
         # Update sequence and acknowledgment numbers, and flags for the final ACK message
        sequence_number = 0
        acknowledgment_number = 1
        flags= 4

        # Create the final ACK message packet
        msg = header.create_packet(sequence_number,acknowledgment_number,flags,window,data)

         # Send the final ACK message to the server
        clientSocket.sendto(msg, (args.serverip, args.port))
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
            print("We are done at client side, finishing")
            break
            #Close the client socket

    global packets_retransmitted #Getting the amount of packets retransmitted
    if args.timeout == "dyn":
        global allTimeouts
        if allTimeouts == []:
            allTimeouts.append(0.5) #If the recieved file is very small, the timeout will not get dynamically changed.
        else:
            print("\nHere is some information about the dynamically calculated timeout:")
            print(f"Lowest: {min(allTimeouts):.3f}, Highest: {max(allTimeouts):.3f}, Average: {sum(allTimeouts) / len(allTimeouts):.3f}")
    else:
        allTimeouts.append(args.timeout) 
    
    #Adding and formatting all the values we want for our output on the client side.
    ServerID = "{:<8}".format(str(serverConnection[0]))
    reliability = "{:<8}".format(args.reliability)
    windowSize = "{:<8}".format(args.windowSize if args.reliability != "SAW" else "1")
    size = os.path.getsize(args.file)/1000000 #GetFng the size of the file in MB.
    time_string = str(round(t_end,4)) #Rounding the time to have to decimal places, and converting from float to string.
    averageTimeout = sum(allTimeouts) / len(allTimeouts)
    averageTimeoutWithUnits = "{:<12}".format(f"{averageTimeout:.3f} s")
    total_time = "{:<11}".format(time_string + " s")
    transfer = "{:<10}".format(str(round(size,4)) + " MB")
    
    if t_end != 0:
        throughput = "{:<8}".format(str(round(size*8/t_end,4)) + " Mbps") #Calculating the thoruhgput (multiply by 8 to convert from bytes to bits).
        print("") #Adding a line before and after the table to make it easier to read.
    else:
        throughput ="{:<8}".format("Error")
        print("") #Adding a line before and after the table to make it easier to read.
        print("TIME TOO LOW TO CALCULATE BANDWIDTH, SEND A BIGGER PACKAGE")
    headline = ["{:<8}".format("Method"), "{:<8}".format("Windowsize"), "{:<12}".format("Avg. Timeout"),"{:<11}".format("time"), "{:<10}".format("Transfer"), "{:<8}".format("Bandwidth"), "packets_retransmitted"]
    output = [reliability            ,              windowSize     , averageTimeoutWithUnits        , total_time            , transfer                   ,throughput, str(packets_retransmitted)] #Formatting the output

    print("\t".join(headline)) #Printing the header for the output
    print("\t".join(output)) #Printing the needed output for the
    print("")
    print("Closing socket")
    clientSocket.close()

#This method sends packet to server
# Will not send the 10.th packet
def sendPacket(seq, data, clientSocket, serverConnection):

    flags = 0 #sets flags variable to 0
    packet = header.create_packet(seq, 0, flags, window, data)  #calls the create_packet methon to create a packet
    if (args.testcase == "loss" and seq == 10):  #: Checks if the args.testcase flag is set to "loss" #TESTING WITH DUPLICATE INSTEAD OF LOSS
        print(f"Packet with sequenceNumber: {seq}, was lost")
        args.testcase = "loss_completed"
    else:
        clientSocket.sendto(packet, serverConnection) #if the flag is not set, the packet is sent to the server
    
    if args.timeout == "dyn": #If the timeout is dynamic
        global perPacketRoundTripTime #tells the function to use these global arrays
        perPacketRoundTripTime.append([seq,time.time()]) #Appending the seq number and time to a list.

#This method recive packet from client, then it calculate the RTT for the packet
def getAck(clientSocket, serverConnection):
   
    while True:
        message, serverConnection =  clientSocket.recvfrom(1472) #Listening for message from client
        header_from_msg = message[:12] #Extracting header from message
        seq, ack, flags, win = header.parse_header (header_from_msg) #Getting information from the header
        if args.timeout == "dyn": #If the timeout is dynamic
            global perPacketRoundTripTime #tell the functions to use the gloabal array
            i = len(perPacketRoundTripTime) -1
            while i >= 0:
                if ack == perPacketRoundTripTime[i][0]:
                    rtt = time.time()-perPacketRoundTripTime[i][1]
                    if rtt > 0.025:
                        perPacketRoundTripTime[i][1] = rtt
                    break
                i -= 1
            if args.reliability != "GBN": #if SR or SAW is used as method
                global allTimeouts #Using a variable to store the average timeout for the input
                if len(perPacketRoundTripTime) > 15: #if more than 15 packets have been sent
                    average = specialSum(10) #calculate the average the last 10 packets
                    clientSocket.settimeout(average*4 if average != 0 else 0.2) #Average might reach 0 on a local computer comunicating with itself. In that case, we set average to 0.1.
                    allTimeouts.append(average*4 if average != 0 else 0.2)
            else: #if GBN is used at method
                if len(perPacketRoundTripTime) > args.windowSize*3: #if more than windowsize*3 packet have been sent
                    average = specialSum(3*args.windowSize) #calculate the average of the last 3*windowsize packets
                    clientSocket.settimeout(average*4 if average != 0 else 0.2) #Average might reach (approximated to) 0 on a local computer comunicating with itself. In that case, we set average to 0.1.
                    allTimeouts.append(average*4 if average != 0 else 0.2)
        return ack  #return acknum

def specialSum(sumSize): #Sums the last n numbers of a function, but skips any numbers larger than 100.
    global perPacketRoundTripTime #tell the functions to use the gloabal array
    counter = len(perPacketRoundTripTime) -1
    i = 0
    sum = 0
    while i < sumSize and counter >= 0:
        if perPacketRoundTripTime[counter][1] > 10000: #This makes sure we skip any values that contain only the time when the seq was sent, but the ack_recieved time was not subtracted. This will for instance happen if the ack is lost.
            counter -= 1
        else:
            sum += perPacketRoundTripTime[counter][1]
            if perPacketRoundTripTime[counter][1] < 0.1: #TODO: these lines are just for bigfixes, remove
                print(perPacketRoundTripTime[counter][1])
            counter -= 1
            i += 1
    return sum/sumSize

# Define the stop_and_wait function for the client-side
def stop_and_wait(clientSocket, serverConnection, seq_num):
    global packets_retransmitted
     # Initialize a counter variable
    i = 0
      # Continue sending packets while there are packets in the PackedFile list
    while i < len(PackedFile):
        # Call the function to send a packet, which will simulate packet loss if the flag is used
        sendPacket(seq_num, PackedFile[i], clientSocket, serverConnection)  #Calling a function to send a packet, which will simulate packet loss if the flag is used.
        try:
             acknum = getAck(clientSocket, serverConnection) #Getting the packet from the server with the getAck function
        except timeout:
            packets_retransmitted += 1
            continue
        if acknum == seq_num: #If the recieved acknum equals the seqnum sent, the server recieved the package, and we can send the next one. If not, the same package is retransmitted.
             # Increment the sequence number and counter variable to send the next packet
            seq_num +=1
            i+=1
        else:
            packets_retransmitted += 1
     # Return the final sequence number after all packets have been sent
    return seq_num

#This method implemenst the Stop and wait for server and it takes three arguments. The method listens to socket for incomming message from the client
#It waits until a message is received and send acknowledgement message back back to client.
def serverSaw(serverSocket, seqNum, recievedData):
    while True:
        message, clientSocket = serverSocket.recvfrom(1472) #Recieving message
        header_from_msg = message[:12] #Getting the header e
        seq, acknum, flags, win = header.parse_header(header_from_msg) #Getting information from header

        if(flags == 0):   #if the flags is zero, this is a new packet
            sendAck(seq, serverSocket, clientSocket)  #Send the ack message, which has ack equal to the seq of the package recieved.
            if(seq == seqNum): #Did we recieve the correct package? If so, append it. This check is needed as duplicate packages may be sent.
                seqNum += 1
                recievedData.append(message[12:])   #save the data

        elif(flags != 0 and recievedData): #Does the packet we recieved have a finish flag
            syn, ack, fin = header.parse_flags(flags) #We need to extract the fin flag
            finish = CheckForFinish(fin, seq, serverSocket, clientSocket)
            if finish:
            #Her må vi liste ut alt dataen vi har fått inn ...!
                return recievedData

# Define the goBackN function for the client-side
def goBackN(clientSocket, serverConnection, seq_num):
    i = 0 #initialise a counter variable
    ackList = [] # Initialize an empty list to store acknowledgment numbers
    acknum = 0

    global packets_retransmitted
    while i < len(PackedFile): #Sending the packets within this loop. If not divisable by n, we send the remaining n packets as empty packets.
        ackList = []
        k=0 # the variable k is needed to deal with 
        for j in range(args.windowSize): #sending the packets
            if j + i >= len(PackedFile): #If the packets are not divisable by n, we send empty packets so that the total adds up to n
                sendPacket(seq_num + j, b'0' * 0, clientSocket,serverConnection)
            else:
                 # Send packets from the PackedFile list
                sendPacket(seq_num + j, PackedFile[j + i], clientSocket,serverConnection)
        variable_incremented = False #Used to store the number of packets that have been retransmitted.

        # Receiving ACKs for the packets sent
        while True:  #Retriving packets until all the needed acks are retrieved or a timeout occurs. 
            try:
                acknum = getAck(clientSocket, serverConnection) #Getting the packet from the server with the getAck function
                if acknum >= seq_num and acknum not in ackList: #Appending all uniqueue acks to the list
                    ackList.append(acknum)
                    k += 1
                    
                    # Break the loop when the difference between the highest received ACK and the lowest expected ACK is equal to the window size
                    if len(ackList) == args.windowSize:
                        break
            except timeout: #If there's a timeout we leave the loop.'

                packets_retransmitted += args.windowSize #If there's a timeout, we retransmit all packages for the window.
                variable_incremented = True
                break

        if set(ackList) == set(range(i+2, i+ args.windowSize+2)): #If all the acks are recieved, we can send the next 5 packets. (We only get acks for packets)
            #Reordering of the acks are no worries on the client side, that's why we use set instead of range. 
            seq_num += args.windowSize
            i += args.windowSize
        elif variable_incremented == False:
            packets_retransmitted += args.windowSize
    # Return the final sequence number after all packets have been sent
    return seq_num

#This a method for a server that use Go-Back-N to recived data from client.
#It takes in three parameters:serverSocket,Seqnum and recivedData.
#Then checks if the packes is received in the right order
def serverGBN(serverSocket, seqNum, recivedData): #Server go back N method
    bufferData = []  #create an empty list
    checkSeqNum = seqNum

    while True:
        message, clientAddress = serverSocket.recvfrom(1472)  #Receive a message and client address
        header_from_msg = message[:12]   #get the header from the recieved packet
        seq, acknum, flags, win = header.parse_header(header_from_msg)
        syn, ack, fin = header.parse_flags(flags) #Getting information for the header
        if flags == 0: #Is the message recieved a normal message containing data?
            if checkSeqNum == seq:  #if the number recived is the right one? If yes, append to bufferData
                bufferData.append(message[12:])
                checkSeqNum += 1     #increase the checkSeqNum
                if len(bufferData) == args.windowSize: #Has all the data from the current window ben added?
                    if seq -2 > len(recivedData): #Is the last seq recieved bigger than the length of recieved data? If yes, that means that the current dataset has not been appended.
                        recivedData.extend(bufferData) #Add all data to the storage
                    for i in range(args.windowSize):
                        sendAck(seq+i-args.windowSize +1, serverSocket, clientAddress)
                    bufferData.clear()
            else:   #if the sequence number is not equal to the correct value, we need to restart from the start of the window. This snippet makes us reset whenever we recieve a packet out of order.
                bufferData.clear()
                checkSeqNum = ((seq-2) // args.windowSize) * args.windowSize + 2 
                if seq == checkSeqNum: #This line checks for skipped acks. If acks were skipped, the server still thinks they were sent, so it needs a double check.
                    bufferData.append(message[12:])
                    checkSeqNum += 1     #increase the checkSeqNum
        else: #If the message is a FIN message
            finish = CheckForFinish(fin, seq, serverSocket, clientAddress)
            if finish:
                return recivedData #Return the receive data

# Define the selective repeat function for the client-side:
def selectiveRepeat(clientSocket, serverConnection, seq_num):
    global packets_retransmitted
    i = 0
    toBeRetransmitted = [] #A list which will be used to know which data needs to be retransmitted. Data is retransmitted if no ack is recieved.
    while i < len(PackedFile): #The final packages are not sent in a bunch of n (window size), but rather based on how many packets are left to send
        for j in range(args.windowSize): #sending the first n packets
            try:
                sendPacket(seq_num + j, PackedFile[j + i], clientSocket,serverConnection) #Sending the packets
                toBeRetransmitted.append(seq_num + j) #adding the seq_num to toBeRetransmitted to signal which seq_numbers were sent.
            except IndexError:
                break #Break out of the loop if we can't send the packet, which will happen if we reach try to send a part of PackedFile which is out of range.
        while toBeRetransmitted != []: #Continuously waits for acks and resends packages until all acks are recieved.
            try:
                acknum = getAck(clientSocket, serverConnection) #Getting the packet from the server with the getAck function
                if acknum in toBeRetransmitted:  #Need this check for the code to work when using dynamic RTTs for packets
                    toBeRetransmitted.remove(acknum)
            except timeout: #If we do not get all acks within the socket timeout, we enter this loop, where we resend all packets that have not recieved an ack.
                for k in toBeRetransmitted: #Looping though all packets needing to be retransmitted
                    sendPacket(k, PackedFile[k-2], clientSocket,serverConnection) #Sending all packets which need to be retransmitted. Using k-2 as the package number is 2 bigger than the ack num.
                    packets_retransmitted += 1
        i += args.windowSize #increasing i by window size
        seq_num += args.windowSize #increasing seq num by window size
    return seq_num #Returning the seq num

#Servers method for Selective repeat:
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
            finish = CheckForFinish(fin, seq, serverSocket, clientSocket)
            if finish:
                return recivedData
            
#This method creates a server and watis for a connection form client
#Once the connections is established, it uses reliability function to recevie and extrac the file data sent by the client.
#It then extracts the file data and stores it in a the server
def createServer():
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #Creates a socket
    serverSocket.bind((args.bind, args.port)) #bind the socekt to a specific IP address and port number
    print('The server is ready to receive')   #print a messeage to indicate that the server is ready to receive data

    seqNum = (int) (handshakeServer(serverSocket)) #Getting the seqNum from the handshake
    recievedData = [] #Creates and empty lis to store the received data. All 3 methods use this array

    if(args.reliability == "SAW"):  #if SAW is passed in
        recievedData = serverSaw(serverSocket, seqNum, recievedData) #calles the method serverSaw and store the data in receviedData
    elif(args.reliability == "GBN"): #if GBN is passed in
        recievedData = serverGBN(serverSocket, seqNum, recievedData)  #calles the method serverGBN and store the data in receviedData
    else: #Else = SR method
        recievedData = serverSR(serverSocket, seqNum, recievedData)  #calles the method serverSR and store the data in receviedData
    UnpackFile(recievedData, args.newFile)  #Unpakc the file

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

#This methos sends an acknowledment (ack) packet to client with given ack number
#The method also implements skipakc flag that randomly skips sending acks.
def sendAck(acknowledgment_number, serverSocket, clientSocket): #Creating a function to send acks to client. Function will randomly skip sending acks if the -t skipack flag is used
    data = b''         #intializes an empty byte string called data
    sequence_number = 0    #sets sequence_number to 0
    flags = 4             #sets flags variable to 4
    msg = header.create_packet(sequence_number, acknowledgment_number, flags, window, data)  #calls the create_packet methon to create a packet
    if (args.testcase == "skipack" and acknowledgment_number == 33):#checks if the command-line argument "testcase" is set to skipack
        print(f"Packet with acknowledgment_Number: {acknowledgment_number}, was lost")
        args.testcase = "ack_has_been_skipped"
    else:
        serverSocket.sendto(msg, clientSocket)#if the flag is not set the ACK is sent to the client.


#This method checks for the fin flag in the header of the message.
#If the fin=2 flag is received then it sends an ack and closes finishes.
#If the fin is not recived, FALSE is returned.
def CheckForFinish(fin, ackNum ,serverSocket,clientSocket):
    if(fin == 2):
        print("Finished message recieved successfully at server from client!")
        acknowledgment_number = ackNum
        flags = 6
        data= b''
        seq = 0
        msg = header.create_packet(seq, acknowledgment_number, flags, window, data)
        serverSocket.sendto(msg, clientSocket) #Sending ack on the finish
        return True # indicate finish
    return False    #  if the FIN siganl is not recieved, return false, so the communication is not finished

#This method takes in arguments passed in by the user. The defined IP to the serverm the serverport, which reliability method and what file the user wants to transfer.
def createClient():
    #Creating a udp socket for the client
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if args.timeout == "dyn":
        clientSocket.settimeout(0.5) #Default timeout for dyn is 0.5, which is changed dynamically as the code runs.
    else:
        clientSocket.settimeout(args.timeout)
    print("Client is created")
    #Calling the hanshake method to start transmission with server
    handshakeClient(clientSocket)

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
parser.add_argument("-T", "--timeout", help="Select the default timeout",type=check_timeout, default="dyn") #This also set's the default socket timeout
#shared arguments
parser.add_argument("-t", "--testcase", help="Type in if you want to set a type of testcase", type=str, choices=['loss', 'skipack'])
parser.add_argument("-p", "--port", help="type -p and wanted portnumber, or default port 8080 will be set", type=check_port, default=8080)
parser.add_argument("-r", "--reliability", help="Type inn the type of reliablity you want", type=str, default='SAW', choices=['SAW', 'GBN', 'SR'])
parser.add_argument("-w", "--windowSize", help="Select the windowSize for the transmission of packets",type=int, default=5, choices=[5, 10, 15])
args = parser.parse_args()

#checks if client or server is invoked. If both server and client is invoked at the same time, it prints out error message.
#If only one of the client or server is passed is proceeds to check if additional arguments have been passed
if args.client == True or args.server == True:
    if(args.client == True and args.server == True):
        print("You have to use either the -s (server) og -c (client) flag, not both")
        sys.exit()
    else:
        if(args.client == True):
            if args.testcase == "skipack":
                print("Skipack is defined at the serverside, please retry with the loss option to skip sending a packet")
                sys.exit()
            if(args.file):
                PackedFile = PackFile(args.file) #Packing the file we are going to send in sizes of 1460 bytes.
                createClient()
            else:
                print("When you create a client, you also need to define which file to transfer to the server")
                sys.exit()
        if(args.server == True):
            if args.testcase == "loss":
                print("Packetloss is defined at the serverside, please retry with another opinion")
                sys.exit()
            if(args.newFile):
                createServer()
            else:
                print("A new filename for the recieved file must be")
                sys.exit()
else:
    print("You have to use either the -s (server) og -c (client) flag.")
    sys.exit()