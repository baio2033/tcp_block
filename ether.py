import socket, sys
from struct import *

DEBUG = True

def checksum(msg):
    s = 0     
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    s = s + (s >> 16);
     
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s

def eth_addr(addr):
    mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" %(ord(addr[0]), ord(addr[1]), ord(addr[2]), ord(addr[3]), ord(addr[4]), ord(addr[5]))
    return mac

def parse_packet(packet):
    rst_packet = None
    eth_len = 14
    eth_header = packet[:eth_len]
    eth = unpack('!6s6sH', eth_header)
    eth_protocol = socket.ntohs(eth[2])

    eth_dst = packet[:6]
    eth_src = packet[6:12]

    rst_eth = pack('!6s6sH', eth[1], eth[0], eth[2])

    if DEBUG:
        print "###################################################"
        print "\n[+] ethernet header info"
        print "\tdst mac : ", eth_addr(eth_dst)
        print "\tsrc mac : ", eth_addr(eth_src)

    if eth_protocol == 8:
        ip_header = packet[eth_len:20+eth_len]
        iph = unpack('!BBHHHBBH4s4s', ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_len = ihl * 4

        chk_sum = packet[23:25]
        rst_chk_sum = checksum(chk_sum)

        protocol = iph[6]        
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        if DEBUG:
            print "[+] ip header info"
            print "\tprotocol : ", protocol
            print "\tsrc ip : ", s_addr
            print "\tdst ip : ", d_addr

        rst_ip = pack('!BBHHHBBH4s4s', iph[0], iph[1], iph[2], iph[3], iph[4], iph[5], iph[6], rst_chk_sum, iph[9], iph[8])
        if protocol == 6:
            ## TCP protocol
            t_ptr = iph_len + eth_len
            tcp_header = packet[t_ptr:t_ptr+20]

            tcph = unpack('!HHLLBBHHH', tcp_header)

            src_port = tcph[0]
            dst_port = tcph[1]
            seq = tcph[2]
            ack = tcph[3]
            doff_reserved = tcph[4]
            tcph_len = (doff_reserved >> 4) * 4
            tcp_chksum = packet[50:52]
            rst_tcp_chksum = checksum(tcp_chksum)

            if DEBUG:
                print "[+] tcp header info"
                print "\tsrc port : ", src_port
                print "\tdst port : ", dst_port
                print "\tseq : ", seq, "\tack : ", ack, "\n"                      

            header_len = eth_len + iph_len + tcph_len
            data_len = len(packet) - header_len   

            rst_seq = ack
            if data_len > 0:   
                data = packet[header_len:]                
                rst_ack = seq + data_len
            else:
                data = ''
                rst_ack = seq + 1

            rst_tcp = pack('!HHLLBBHHH', tcph[1], tcph[0], rst_seq, rst_ack, tcph[4], tcph[5], tcph[6], rst_tcp_chksum, tcph[8])

            if DEBUG:
                if data_len > 0:
                    print "[+] data (length : ", data_len, ")"
                    print data                                                             
    
            rst_packet = rst_eth + rst_ip + rst_tcp + data
    
            rs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            rs.connect((s_addr, src_port))
            rs.sendall(rst_packet)
            rs.close()

        return rst_packet

def main(argv):
	if len(sys.argv) < 2:
		print "[+] Usage : python ", sys.argv[0], " <interface>"
		sys.exit()

	dev = sys.argv[1]
	print "[+] device : " + dev

	try:
		s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
	except socket.error, msg:
		print msg
		sys.exit()

	while True:
		try:
			packet = s.recv(65565)	
			if len(packet) > 0:
				parse_packet(packet)

		except socket.error, msg:
			print msg
			if s:
				s.close()
			sys.exit()

		except KeyboardInterrupt:
			print "\n[+] terminate the program!\n"
			if s:
				s.close()
			sys.exit()

if __name__ == "__main__":
	main(sys.argv)