Reliable Transport Protocol (DRTP) 
----------------------------------

DRTP is a simple transport protocol that provides reliable data delivery on top of UDP. DRTP wil ensure thata is reliably delivered in order whitout missing data. We have implemetet two programs DRTP and simple file transfer client and server  

How to use the application
--------------------------
The transfer application can be run in either server mode or client mode. Each mode has flasgs that can be used. If you dont specify any flags, the applicaiton will use default values.


## Server mode ##
The server can be invoked with 
    
    python3 application.py  -s -b <ip_address> -p <port_number>

Other command-line options:

    -r, --reliable         reliability functions (STP,GBN or SP)
    -t, --tes_case         to skip ack to trigger retransmission 


## Client mode ##
The client can be invoked with:

    python3 application.py -c -I <server_ip_address> -p <server_portt> 

Other command-line options:

    -r, --reliable         reliability functions (STP,GBN or SP)
    -t, --test_case        if you want to skip ack to trigger retransmission 

Reliablity functions
--------------------














