Reliable Transport Protocol (DRTP) 
----------------------------------
DRTP is a simple transport protocol that provides reliable data delivery on top of UDP. DRTP wil ensure that data is reliably delivered, and that the file store on the server side is identical to the sent file.


How to use the application
--------------------------
The transfer application can be run in either server mode or client mode. We have implement various flags for client and server. To run the applicatino you have to invoke the server and then the client, you can not invoke the server and client at the same time. You must run with the flags spesificed below, unless they have a default value which works for your testcase.

## Server mode ##
The server can be invoked with 
    
    python3 drtp.py  -s -b <ip_address> -F <file_path>

    -s, --server          tells the program to run in server mode.
    -b, --bind            tels the IP of the server. The default is the ip of the computer.
    -F, --file            select where you want to save the transmitted file.

Other command-line options:

    -r, --reliable        reliability functions (SAW,GBN or SP). Default: SAW.
    -t, --testcase        to skip sending ack number 33, once. Default: off. Trigger with the skipack flag.
    -w, --windowSize      Select the windowsize for the transmission of packets. Default = 5, 1 is always used for SAW.


## Client mode ##
The client can be invoked with:

    python3 drtp.py -c -I <server_ip_address> -f <file>

    -c, --client          tells the program to run in client mode.
    -I, --serverIP        tells the IP of the server. The default is the ip of the computer.
    -f, --file            select which file you want to send.

Other command-line options:

    -p, --port            tells which port to use  Default = 8080
    -r, --reliable        reliability functions (SAW,GBN or SP). Default = SAW
    -t, --testcase        if you want to skip sending packet number 10, once. Default = off. Trigger with the loss flag.
    -w, --windowSize      Select the windowsize for the transmission of packets. Default = 5, 1 is always used for SAW.
    -T, --timeout         Select the timeout. Default = dynamic timeout.


Reliablity functions
--------------------
Three reliability function was implemented and user will be able to choose them from the command line argument using -r. The three functions are:
* stop and wait protocol(STP): STP send one packet at time and the next packet is sent only when the sender receives an ackowledment(ACK). If the sender doesn't receive an ACK within a set period then it resends the packet. 

* go-back-n (GBN): Sends 5, 10 or 15 packets. If acks are not recieved for all packets, all packets will be retransmitted. Server will only save the recieved packets if all packets are recieved. If all packets are not recieved in the correct order, no acks will be delivered to the client.

* selective repeat (SR): Selective repeat sends 5, 10 or 15 packets, as spesificed by the user. If acks are not recieved, the client will resend all packets which acks were not recieved for. When all acks for the sent packets are recieved, the client will send the next packets.  














