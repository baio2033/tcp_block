from scapy.all import *
import sys, time
import logging

SYN = 0x02
ACK = 0x10
RST = 0x04
FIN = 0x01
DF = 0x02

http_method = ['GET', 'POST', 'PUT', 'HEAD', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']

def PacketHandler(packet):	
	data_flag = False
	http_flag = False

	if packet.getlayer(Raw):
		data_flag = True	

	# Ethernet Header	
	ether_dst = packet[Ether].dst
	ether_src = packet[Ether].src

	# IP Header
	ip_src = packet[IP].src
	ip_dst = packet[IP].dst	

	# TCP Header
	tcp_dst = packet[TCP].dport
	tcp_src = packet[TCP].sport

	seq = packet[TCP].ack
	if data_flag:
		ack = packet[TCP].seq + len(packet[Raw])
	else:
		ack = packet[TCP].seq + 1

	if packet[TCP].flags & RST != RST:		
		if data_flag:
			data = str(packet[Raw])
			method = data.split()[0]			
			for m in http_method:									
				if m == method:					
					http_flag = True

		forward_reset = Ether(dst=ether_dst, src=ether_src) / IP(src=ip_src, dst=ip_dst, flags=DF) / TCP(flags=ACK|RST,dport=tcp_dst, sport=tcp_src, seq=packet[TCP].seq, ack=packet[TCP].ack)				
		sendp(forward_reset, iface=dev)

		if http_flag == False:									
			rst_packet = Ether(dst=ether_src, src=ether_dst) / IP(src=ip_dst, dst=ip_src, flags=DF) / TCP(flags=ACK|RST,dport=tcp_src, sport=tcp_dst, seq=seq, ack=ack)		
			sendp(rst_packet, iface=dev)				
		else:
			print "[+] HTTP block"				
			fin_packet = Ether(dst=ether_src, src=ether_dst) / IP(src=ip_dst, dst=ip_src, flags=DF) / TCP(flags=ACK|FIN,dport=tcp_src, sport=tcp_dst, seq=seq, ack=ack) / "FIN Message\r\n"					
			sendp(fin_packet, iface=dev)					

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print "\n[+] Usage : python", sys.argv[0], "<interface>"
		sys.exit()

	dev = sys.argv[1]

	logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
	sniff(iface=dev, prn=PacketHandler, filter="tcp")