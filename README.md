RawSockets
==========
Project Approach:

Through this project we learnt about low level functioning of IP protocol stack.We used raw sockets to do the same.The basic functioning of our function is as follows:
1.We use inet_aton scoket. We create IP header using pack function. Then we create pseudo TCP header packet consisting of IP so 
urse and destination.
2.Then we calculate checksum of this pseudo header and data. Then we attach the checksum to the original TCP packet and send this packet.
3.Then we receive the packet and unpack it.
4.Ths procedure is intially used to achieve a TCP handshake.
5.After that we download the entire file by acknowledging each and every packet.
6.For every packet we calculate and verify TCP checksum.
7.If the TCP checksum do not match, then we retransmit ACK for previous packets.
9.If an packet is obtained out of order,we drop te packet
8.We wait for receiver to send FIN+ACK packet.
9.In reply to this packet,we reply with FIN+ACK packet.

Challenges Faced:

1. The main challenges were creating proper TCP packet. The calculation of checksome using psedo header took lot of time to understand and implement.
2The other challenges were the approach to deal with out of order packets. There are different ways to deal with them.We followed approach as verified by Wireshark.
3.The verification of checksum was also a challenging task.
4.Calculating proper Sequence and ACK number was also also bit difficult.


Tests:

1.We tested our code by downloading all three files mentioned in Question Set.
2.We verified md5sum for all three files.

