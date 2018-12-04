import os
import sys
from scapy.all import *

class ScanDetector(object):
	def __init__(self, traffic_dump_filename):
		super(ScanDetector, self).__init__()
		self.filename = traffic_dump_filename
		self.dump = self.readDumpfile(self.filename)
		self.detects_amount = 0
		self.scanner_ips = set()
		self.scanned_ports = set()
		self.pinged_ips = set()
		self.scan_types = set()
		self.scan_detected = False

	def cleanup(self):
		try:
			os.remove(".temp_{}".format(self.filename))
		except OSError as e:
			pass

	def readDumpfile(self, filename):
		dump = None
		try:
			dump = rdpcap(filename)
		except scapy.error.Scapy_Exception as e:
			# Scapy works badly with pcapng files. So we need to convert it
			# cmd = "tshark -r {} -w {} -F libpcap".format(filename, ".temp_{}"+filename)
			# install tshark sudo apt install -y tshark
			cmd = ["tshark", "-r", filename, "-w", ".temp_{}".format(filename), "-F", "libpcap"]
			convert = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			out, errs = convert.communicate()
			if len(errs):
				raise e
			else:
				dump = rdpcap(".temp_{}".format(filename))
		return dump

	def extractScannerIp(self, packet):
		try:
			self.scanner_ips.add(packet[IP].src)
		except KeyError as e:
			pass

	def extractPingedIp(self, packet):
		try:
			self.pinged_ips.add(packet[IP].dst)
		except KeyError as e:
			pass

	def extractScannedPort(self, packet):
		if packet.haslayer(TCP):
			dport = packet[TCP].dport
			self.scanned_ports.add(dport)
		if packet.haslayer(UDP):
			dport = packet[UDP].dport
			self.scanned_ports.add(dport)

	def findResponsePacket(self, request_packet, packet_index):
		next_packet = self.dump[packet_index+1]
		afternext_packet = self.dump[packet_index+2]
		if next_packet[IP].dst == request_packet[IP].src and next_packet[IP].src == request_packet[IP].dst:
			if next_packet[TCP].flags == 0x014:
				# port is closed
				return True
			elif next_packet[TCP].flags == 0x012:
				if afternext_packet[TCP].flags == 0x004:
					# port is openned
					return True
		return False

	def tcpChecks(self, packet, packet_index):
		flags = packet[TCP].flags                
		if flags == 0x000:
			# null scan
			self.detects_amount += 1
			self.scan_detected = True
			self.scan_types.add('NULL')
			self.extractScannerIp(packet)
			self.extractScannedPort(packet)
		if flags == 0x029:
			# xmas scan
			self.detects_amount += 1
			self.scan_detected = True
			self.scan_types.add('XMAS')
			self.extractScannerIp(packet)
			self.extractScannedPort(packet)
		if flags == 0x002:
			# half-open scan
			if self.findResponsePacket(packet, packet_index):
				self.detects_amount += 1
				self.scan_detected = True
				self.scan_types.add('Half-Open')
				self.extractScannerIp(packet)
				self.extractScannedPort(packet)				

	def udpChecks(self, packet):
		try:
			if packet[UDP].len == 8:
				self.detects_amount += 1
				self.scan_detected = True
				self.scan_types.add('UDP')
				self.extractScannerIp(packet)
				self.extractScannedPort(packet)
		except KeyError as e:
			pass

	def icmpChecks(self, packet):
		try:
			if packet["ICMP"].type == 8:
				self.detects_amount += 1
				self.scan_detected = True
				self.scan_types.add('ICMP')
				self.extractScannerIp(packet)
				self.extractPingedIp(packet)
		except KeyError as e:
			pass
		
	def start(self):
		print("Starting...")
		for index, packet in enumerate(self.dump):
			if packet.haslayer(UDP):
				self.udpChecks(packet)
			if packet.haslayer(TCP):
				self.tcpChecks(packet, index)
			if packet.haslayer(ICMP):
				self.icmpChecks(packet)
		self.cleanup()

	def report(self):
		report = "Scan detection report\n"
		if self.scan_detected:
			report += "Scanners: {}\n".format(",".join(self.scanner_ips))
			report += "Scan types: {}\n".format(",".join(self.scan_types))
			report += "Detects: {}\n".format(str(self.detects_amount))
			report += "Ports: {}\n".format(",".join([str(x) for x in self.scanned_ports])) if len(self.scanned_ports) else ""
			report += "Pinged IPs: {}\n".format(",".join(self.pinged_ips)) if len(self.pinged_ips) else ""
		else:
			report += "No scans detected"
		return report


if __name__ == '__main__':
	if len(sys.argv) < 2:
		print("Usage: python {} <dump.pcap>".format(sys.argv[0]))
		sys.exit(1)

	traffic_dump = sys.argv[1]
	detector = ScanDetector(traffic_dump)
	detector.start()
	print(detector.report())
