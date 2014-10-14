import sys, socket, urlparse
from struct import *
from random import randint
from collections import OrderedDict
import time
global port
global flag
global first_flag
global new_dict
global sequnence_n
global sequence_pred
global flag_seq_pred
global flag_seq_in_order
global flag_first_packet
global counter
global contentlength
global contentlength_total
global order_count
global content_len_check
global flag_Case1
global flag_first
global first_sequence_number
global first_time
global last_time
global ack_recieved
ack_recieved=0
first_sequence_number=0
flag_Case1=0
last_time=0
content_len_check=0
contentlength=0
contentlength_total=0
dict_packet=OrderedDict()
dict_len=OrderedDict()
flag_seq_in_order=0	
flag_seq_pred=1		
flag=0
counter=0
flag_first_packet=0
sequence_pred=0
first_flag=0
port=randint(1025,65535)	
order_count=0

def create_packet(tcp_finh,tcp_synh,tcp_rsth,tcp_pshh,tcp_ackh,tcp_urgh,tcp_seqno,tcp_ack_seq_h,tcp_user_d,http_h):
	# now start constructing the packet	
	packet = '';
	# ip header fields
	ip_ihl = 5
	ip_ver = 4
	ip_tos = 0
	ip_tot_len = 0  # kernel will fill the correct total length
	ip_id = 54321  #Id of this packet
	ip_frag_off = 0
	ip_ttl = 255
	ip_proto = socket.IPPROTO_TCP
	ip_check = 0    # kernel will fill the correct checksum
	ip_saddr = socket.inet_aton ( src )   #Spoof the source ip address if you want to
	ip_daddr = socket.inet_aton ( tgt )
	ip_ihl_ver = (ip_ver << 4) + ip_ihl
 
	# the ! in the pack format string means network order
	ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
	# tcp header fields
	tcp_source = port   # source port
	tcp_dest = 80   # destination port
	tcp_seq = tcp_seqno
	tcp_ack_seq = tcp_ack_seq_h
		
	tcp_doff =5     #4 bit field, size of tcp header, 5 * 4 = 20 bytes
	#tcp flags
	tcp_fin = tcp_finh
	tcp_syn = tcp_synh
	tcp_rst = tcp_rsth
	tcp_psh = tcp_pshh
	tcp_ack = tcp_ackh
	tcp_urg = tcp_urgh
	tcp_window = socket.htons (30)    #   maximum allowed window size
	tcp_check = 0
	tcp_urg_ptr = 0
	 
	tcp_offset_res = (tcp_doff << 4) + 0
	tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)
 
	# the ! in the pack format string means network order
	tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)
       
 	user_data=http_h	
	# pseudo header fields
	source_address = socket.inet_aton( src )
	dest_address = socket.inet_aton(tgt)
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	tcp_length = len(tcp_header) + len(user_data)
	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
	psh = psh + tcp_header + user_data;
	tcp_check = checksum(psh)
	#print tcp_checksum
 
	# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
	tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)
 
	# final full packet - syn packets dont have any data
	packet = ip_header + tcp_header + user_data
	return packet

def checksum_check(tcph_check_h,data_h):
	tcp_source_h=tcph[0]
	tcp_dest_h=tcph[1]
	tcp_seq_h=tcph[2]
	tcp_ack_seq_h=tcph[3]
	tcp_offset_res_h=tcph[4]
	tcp_flags_h=tcph[5]
	tcp_window_h=tcph[6]
	tcp_urg_ptr_h=tcph[8]
	tcp_header_h = pack('!HHLLBBH' , tcp_source_h, tcp_dest_h, tcp_seq_h, tcp_ack_seq_h, tcp_offset_res_h, tcp_flags_h,  tcp_window_h) + pack('H' , 0) + pack('!H' , tcp_urg_ptr_h)	
	# pseudo header fields
	source_address_h = socket.inet_aton( src )
	dest_address_h = socket.inet_aton(tgt)
	placeholder_h = 0
	protocol_h = socket.IPPROTO_TCP
	tcp_length_h = len(tcp_header_h) + len(data_h)
	psh_h = pack('!4s4sBBH' , source_address_h , dest_address_h , placeholder_h , protocol_h , tcp_length_h);
	psh_h = psh_h + tcp_header_h + data_h;
	tcp_check_h = checksum(psh_h)
	print tcp_check_h
	print tcph[7]
	if not str(tcp_check_h)==str(tcph[7]):
		print 'f'
		return False
		
	else:
		print 't'
		return True


def reciver_packet(packet):
	global flag
	global sequnence_n
	global contentlength	
	global sequence_pred
	global flag_seq_pred
	global flag_seq_in_order			
	global order_count
	global flag_first_packet
	global first_flag
	global counter	
	global contentlength_total
	global content_len_check
	global flag_Case1
	global first_time
	global last_time	
	#packet string from tuple
	# Layer 2 14 bytes	
	#ethHeader = packet[0][0:14]
   	# Layer 3 20 bytes	
	ipHeader = packet[0][14:34]
	# Layer 3 20 bytes	
	tcpHeader = packet[0][34:54]
	# Data
	data = packet[0][54:]
	lenh=len(data)
	iph = unpack('!BBHHHBBH4s4s' , ipHeader) 
    	s_addr = socket.inet_ntoa(iph[8]);
	len_data=len(data)	
	last_time=time.time()
	if s_addr == tgt:
		
		

		tcph = unpack('!HHLLBBHHH' , tcpHeader) 
		dest_port = tcph[1]
    		protocol = iph[6]
		# TCP header
       		source_port = tcph[0]
		#Actual Sequence Number
		sequence = tcph[2]
		acknowledgement = tcph[3]
		#doff_reserved = tcph[4]
	   	flags = int(tcph[5])
		#For checksum	
		#if checksum_check(tcph,data)==False:
		#	packet=create_packet(0,0,0,0,1,0,acknowledgement,sequence,'','')
		#	s.sendto(packet, (tgt , 0))
		#	return 0
		dest_port = tcph[1]
    		protocol = iph[6]
		# TCP header
       		source_port = tcph[0]
		#Actual Sequence Number
		sequence = tcph[2]
		acknowledgement = tcph[3]
	   	flags = int(tcph[5])
				
		if dest_port == port:
			if first_flag==0:
				first_flag=first_flag+1
				return 0

			http_resp = 'HTTP/' 
			resp_1 = 'HTTP/1.1 200 OK'
    			resp_2 = 'HTTP/1.0 200 OK'
			if http_resp in data and flag == 0:
				if resp_1 in data or resp_2 in data: 
					           				
					header,body = data.split('\r\n\r\n')
					header = header.replace('\r\n',' ')
					header1 = header.split(' ')
					if 'Content-Length:' in header1:
	             				pos = header1.index('Content-Length:')
	             				contentlength = int(header1[pos+1])
						contentlength += len(data)
						contentlength_total=int(header1[pos+1])
	       	   				content_len_check=1
					else:
						print ''
					data = body		
	   				flag = flag+1	
				else:
					packet=create_packet(1,0,0,0,1,0,acknowledgement,sequence+1,'','')
					s.sendto(packet, (tgt , 0))
					print 'Invalid http response was recived'
					fo.close()
					sys.exit()	 
			
			if str(flags) =='17':
				packet=create_packet(1,0,0,0,1,0,acknowledgement,sequence+1,'','')
				s.sendto(packet, (tgt , 0))
				flag_Case1=1
				return 0



			if str(flags) =='25':
				packet=create_packet(1,0,0,0,1,0,acknowledgement,sequence+1,'','')
				s.sendto(packet, (tgt , 0))
				if not len_data == 0 and not len_data == 2:
					dict_packet[sequence]=data
					dict_len[sequence]=len_data
					if content_len_check==1:
						contentlength=contentlength-len_data				
						print str(contentlength)
					
					fo.write(data)	

				
				flag_Case1=1				
				return 0
			
			
			if sequence==first_sequence_number and str(flags)=='2' and ack_recieved==0:
				 ack_recieved=1
			if lenh==0:
				return 0
	
		    	tcph_length = doff_reserved >> 4
			#print 'Sequence'+ str(sequence)
			if flag_first_packet==0:
				flag_first_packet=1
				sequence_pred=sequence+len_data
				packet=create_packet(0,0,0,0,1,0,acknowledgement,sequence_pred,'','')
				dict_packet[sequence]=data
				dict_len[sequence]=len_data	
				counter=counter+1					
				fo.write(data)
				#deducting expected content length
				if content_len_check==1:
					contentlength=contentlength-len_data				
				#Checking if content length is 0 or not
				s.sendto(packet, (tgt , 0))
				return 0
			else:
				if sequence_pred==sequence:

					dict_packet[sequence]=data
					dict_len[sequence]=len_data 
					counter=counter+1
					temp_ptr=0
					while sequence in dict_packet and temp_ptr==0:
						fo.write(dict_packet[sequence])
						#deducting expected content length		
						if content_len_check==1:
							contentlength=contentlength-len(dict_packet[sequence])				
						sequence=sequence+dict_len[sequence]	

					sequence_pred=sequence
					
					#Checking if content length is 0 or not					
					packet=create_packet(0,0,0,0,1,0,acknowledgement,sequence,'','')					
					s.sendto(packet, (tgt , 0))
					return 0
				else:
					if not sequence in dict_packet:
						dict_packet[sequence]=data
						counter=counter+1
						dict_len[sequence]=len_data
						packet=create_packet(0,0,0,0,1,0,acknowledgement,sequence_pred,'','')
						s.sendto(packet, (tgt , 0))
						return 0
					else:
						dict_pred=sequence
						while dict_pred in dict_packet:
							dict_pred=dict_pred+dict_len[dict_pred]
						packet=create_packet(0,0,0,0,1,0,acknowledgement,dict_pred,'','')
						s.sendto(packet, (tgt , 0))




		

def checksum(data):
	pos = len(data)
	if (pos & 1):  # checking for odd data length
		pos -= 1
		sum = ord(data[pos])
			  # this is used to create a proper sum.
	else:
		sum = 0
 	
  # This calculates the actual checksum.
	while pos > 0:
    		pos -= 2
    		sum += (ord(data[pos + 1]) << 8) + ord(data[pos])
 
  	sum = (sum >> 16) + (sum & 0xffff)
  	sum += (sum >> 16)
 
	result = (~ sum) & 0xffff #Keeping the lower 16 bits
  	return result


#Getting Source IP address
f=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
f.connect(('www.google.com',80))
src = f.getsockname()[0]
filename = src

targeturl = sys.argv[1]

httpoccur = targeturl.find("http://")

if httpoccur == -1:
	targeturl = "http://" + targeturl

u = urlparse.urlparse(str(targeturl))
host = str(u.netloc)
path = str(u.path)

if not path:
	path = '/'
	targeturl = targeturl + path

filename = targeturl[(targeturl.rfind("/")+1): ]
if filename == '':
	filename = 'index.html'
    
tgt = socket.gethostbyname(host)


try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    fo.close()	
    sys.exit()

#Initial sequence number 
init_sequence_number=20

#File handler for writting file
fo = open(filename, "ab")

 
#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
	# create a raw socket and bind it to the public interface
	r = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))

except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    fo.close()	
    sys.exit()


#Send the packet SYN - the port specified has no effect
packet = create_packet(0,1,0,0,0,0,init_sequence_number,0,'','');
s.sendto(packet, (tgt , 0 ))   


# receive a packet
while True:
	packet = r.recvfrom(65565)
	#packet string from tuple
	# Layer 2 14 bytes	
	ethHeader = packet[0][0:14]
	# Layer 3 20 bytes	
	ipHeader = packet[0][14:34]
	# Layer 3 20 bytes	
	tcpHeader = packet[0][34:54]

	# Details of IP header	
	iph = unpack('!BBHHHBBH4s4s' , ipHeader) 
	version_ihl = iph[0]
	version = version_ihl >> 4
	ihl = version_ihl & 0xF
	iph_length = ihl * 4
	ttl = iph[5]
	protocol = iph[6]
	s_addr = socket.inet_ntoa(iph[8]);
	d_addr = socket.inet_ntoa(iph[9]);
	 	

	if tgt == str(s_addr) and str(protocol) == '6':
	   # Checking for TCP header 
	   tcph = unpack('!HHLLBBHHH' , tcpHeader)
	          
	   source_port = tcph[0]
	   dest_port = tcph[1]
	   sequence = tcph[2]
	   acknowledgement = tcph[3]
	   doff_reserved = tcph[4]
	   flags = tcph[5]	
	   tcph_length = doff_reserved >> 4
	   if str(dest_port) == str(port):  
		   #Checking for Syn + ACK	
		if str(flags) == '18' :		
			#Sending ACK packet
			packet=create_packet(0,0,0,0,1,0,acknowledgement,sequence+1,'','');
			#Send the packet finally - the port specified has no effect
			s.sendto(packet, (tgt , 0 )) 
			#TCP handshake complete  

			http_header='GET ' + path + ' HTTP/1.0\r\n' + 'Host: ' + host + '\r\n' + 'User-Agent: 	Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0\r\n'+'Connection: keep-alive\r\n\r\n' 
			packet=create_packet(0,0,0,1,1,0,acknowledgement,sequence+1,'',http_header);
			first_sequence_number=acknowledgement+len(http_header)
			s.sendto(packet, (tgt , 0 ))	
			first_time=time.time()		
			f = 0
			flag_temp=-1
			retransmission=1
			while True:
				last_time=time.time()
				if last_time-first_time>1 and retransmission<3 and ack_recieved==0:
					http_header='GET ' + path + ' HTTP/1.0\r\n' + 'Host: ' + host + '\r\n' + 'User-Agent: 	Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:26.0) Gecko/20100101 Firefox/26.0\r\n'+'Connection: keep-alive\r\n\r\n' 
					retransmission=retransmission+1
					ack_recieved=0
					packet=create_packet(0,0,0,1,1,0,acknowledgement,sequence+1,'',http_header);
					first_sequence_number=acknowledgement+len(http_header)
					s.sendto(packet, (tgt , 0 ))
					continue				
				packet = r.recvfrom(65565)		
				reciver_packet(packet)						
				if flag_Case1==1:
					fo.close()
					sys.exit()

