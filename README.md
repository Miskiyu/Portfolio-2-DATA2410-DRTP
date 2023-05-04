Reliable Transport Protocol (DRTP) 
----------------------------------


DRTP is a simple transport protocol that provides reliable data delivery on top of UDP. DRTP wil ensure thata is reliably delivered in order whitout missing data.

How to use the application
--------------------------
The transfer application can be run in either server mode or client mode. We have implement various flags for client and server. To run the applicatino you have to invoke the server and then the client, you can not invoke the server and client at the same time. You must run with the flags spesificed below. 

## Server mode ##
The server can be invoked with 
    
    python3 application.py  -s -b <ip_address> -p <port_number>

Other command-line options:

    -r, --reliable        reliability functions (STP,GBN or SP)
    -t, --testcase        to skip ack to trigger retransmission 
    -F, --newFile         Write the name of the new file 
    -w, --windowSize      Select the windowsize for the transmission of packets. Default = 64 000


## Client mode ##
The client can be invoked with:

    python3 application.py -c -I <server_ip_address> -p <server_portt> 

Other command-line options:

    -r, --reliable        reliability functions (STP,GBN or SP)
    -t, --testcase        if you want to skip ack to trigger retransmission 
    -f, --file            select which file you want to send
    -w, --windowSize      Select the windowsize for the transmission of packets
    -T, --timeout         Select the timeout


Reliablity functions
--------------------
Three reliability function was implemented and user will be able to choose them from the command line argument using -r. The three functions are:
* stop and wait protocol(STP): STP send one packet at time and the next packet is sent only when the sender receives an ackowledment(ACK). If the sender doesnt receive an ACK within a set period then it resends the packet. 

* go-back-n (GBN): Sends 5, 10 or 15 packets. If acks are not recieved for all packets, all packets will be retransmitted. Server will only save the recieved packets if all packets are recieve and 

* selective repeat (SR): Selective repeat sends 5, 10 or 15 packets, as spesificed by the user. If acks are not recieved, the client will resend all packets which acks were not recieved for. When all acks for the sent packets are recieved, the client will send the next packets.  














