/*
	Wake on LAN Packet forwarder written By Carloschi7 on 21/12/2022.


	This software makes a third terminal as a packet listener to wake up
	another device in the same local network
	This software is only needed if your router does not forward packets
	to turned off devices, meaning it has no way to set static ARP tables
	
	MAKE SURE TO USE THE FOLLOWING SOFTWARE WITH CAUTION, AS IN CAN CAUSE
	DAMAGE TO ONE OR MULTIPLE DEVICES IF NOT USED PROPERLY, AND IT CAN GENERATE
	FALLACIES IN THE SYSTEM.

	This software is not currently terminal-friendly, you will need to run
	this with Visual Studio and Npcap dependencies.

	Feel free to plug in your personal network values in the "Application data"
	section, such as IPs MACs and the recieving network's name.

	If you do everything correctly, this application will allow you to boot your
	PC from anywhere, with this piece of software running on a smaller device. 
	(E.G. raspberry, arduinos, laptops, maybe also phones).

	(Works only on windows for now as the linking procedures with Npcap is done 
	via the dll library file).
*/

#include <iostream>
#include <sstream>
#include <pcap/pcap.h>

class Enclosure {
public:
	Enclosure(pcap_t*& handler, pcap_if_t*& devs):
		m_Handler(handler), m_Alldevs(devs)
	{}

	~Enclosure() {
		if(m_Handler)
			pcap_close(m_Handler);
		
		if(m_Alldevs)
			pcap_freealldevs(m_Alldevs);
	}
private:
	pcap_t*& m_Handler;
	pcap_if_t*& m_Alldevs;
};

class MacAddress {
public:
	MacAddress() {}
	MacAddress(const std::string& data) {
		for (uint32_t i = 0, j = 0; i < 6; i++, j += 3){
			std::string edit = "0x" + data.substr(j, 2);
			m_Data[i] = static_cast<uint8_t>(std::stoul(edit, nullptr, 16));
		}
	}
	const uint8_t* Payload() const {
		return m_Data;
	}
private:
	uint8_t m_Data[6]{};
};

class IpAddress {
public:
	IpAddress(){}
	IpAddress(uint8_t n0, uint8_t n1, uint8_t n2, uint8_t n3) :
		m_Data{ n0,n1,n2,n3 }
	{
	}

	const uint8_t* Payload() const {
		return m_Data;
	}
private:
	uint8_t m_Data[4]{};
};

std::ostream& operator<<(std::ostream& out, const IpAddress& ip) {
	auto pl = ip.Payload();
	out << (int)pl[0] << "." << (int)pl[1] << "." << (int)pl[2] << "." << (int)pl[3] << ".";
	return out;
}

struct NetworkInterface {
	MacAddress mac;
	IpAddress ip;
};

std::string ResolvePacketFor(const NetworkInterface& src, const NetworkInterface& dest, const u_char* pkt_src, uint32_t size) {
	std::stringstream ss;
	std::string pkt_str(reinterpret_cast<const char*>(pkt_src), size);
	//inserting macs
	const uint8_t* pl = dest.mac.Payload();
	ss << std::dec << pl[0] << pl[1] << pl[2] << pl[3] << pl[4] << pl[5];
	pl = src.mac.Payload();
	ss << std::dec << pl[0] << pl[1] << pl[2] << pl[3] << pl[4] << pl[5];
	ss << pkt_str.substr(0x0C, 0x1A - 0x0C); 
	//Inserting ips
	const uint8_t* sl = src.ip.Payload();
	ss << std::dec << sl[0] << sl[1] << sl[2] << sl[3];
	sl = dest.ip.Payload();
	ss << std::dec << sl[0] << sl[1] << sl[2] << sl[3];
	ss << pkt_str.substr(0x22, 0x30 - 0x22);

	pl = dest.mac.Payload();
	for (uint32_t i = 0; i < 16; i++) {
		ss << std::dec << pl[0] << pl[1] << pl[2] << pl[3] << pl[4] << pl[5];
	}

	return ss.str();
}

int main() {

	SetDllDirectory("C:/Windows/System32/Npcap");

	//Application data
	pcap_if_t* dev = nullptr, *my_dev = nullptr;
	pcap_t* handler = nullptr;
	bpf_program program;
	bpf_u_int32 net, mask;
	pcap_pkthdr* header;
	const u_char* packet = nullptr;

	//This is the default Wake on Lan traveling port
	std::string wake_on_lan_recv = "udp port 9";

	NetworkInterface src{ {"30:9c:23:8c:64:15"}, {192,168,1,222} };
	NetworkInterface dest{ {"74:46:a0:bd:10:e2"}, {192,168,1,170} };

	Enclosure enc(handler, dev);

	char errbuf[PCAP_ERRBUF_SIZE]{};

	//Init pcap
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &dev, errbuf) == -1) {
		std::cout << "Error in pcap_findalldevs_ex" << errbuf << std::endl;

		return -1;
	}

	int index = 0, input_choice = 0;
	for (pcap_if_t* d = dev; d != nullptr; d = d->next, index++) {
		std::cout << index << ":" << d->name << ":\n" << d->description << "\n\n";
	}

	std::cout << "Choose sniffing device:\n";
	std::cin >> input_choice;

	my_dev = dev;
	for (uint32_t i = 0; i < input_choice; i++) {
		if(my_dev != nullptr)
			my_dev = my_dev->next;
	}

	if (my_dev == nullptr) {
		std::cout << "Index out of bounds\n";
		//Just so the console does not close instantly
		std::cin >> input_choice;
		return -1;
	}

	//Find the device net (not actually used now)
	if (pcap_lookupnet(my_dev->name, &net, &mask, errbuf) == -1) {
		std::cout << "Error in pcap_lookupnet:" << errbuf << std::endl;
		return -1;
	}

	handler = pcap_open_live(my_dev->name, BUFSIZ, 1, 1000, errbuf);
	if (handler == nullptr) {
		std::cout << "Error in pcap_open_live:" << errbuf << std::endl;
		return -1;
	}

	if (pcap_compile(handler, &program, wake_on_lan_recv.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
		std::cout << "Error in pcap_compile:" << pcap_geterr(handler) << std::endl;
		return -1;
	}
	
	if (pcap_setfilter(handler, &program) == -1) {
		std::cout << "Error in pcap_setfilter:" << errbuf << std::endl;
		return -1;
	}

	uint32_t packet_counter = 0;
	std::string final_pkt;
	while (pcap_next_ex(handler, &header, &packet) != -1) {

		//Avoid repetitions and scans of packets we have just sent
		if (header->len == 0)
			continue;

		//Ignore WakeOnLan packets with broadcast MAC (less redundant)
		if (packet[0] == 0xFF)
			continue;

		//Avoid packet repetitions
		if (!final_pkt.empty() && strcmp((const char*)packet, final_pkt.c_str()) == 0)
			continue;

		std::cout << "New packet sniffed(" << packet_counter++ << ")" << "\n";
		std::cout << "Packet lenght:" << header->len << "\n";
		std::cout << "Timestamps:" << header->ts.tv_sec << "\n";
		std::cout << "Packet payload:" << packet << "\n";
		std::cout << "Sending packet to:" << dest.ip << "\n\n\n";
		
		//Sending back the packet
		final_pkt = ResolvePacketFor(src, dest, packet, header->len);
		pcap_sendpacket(handler, (const u_char*)final_pkt.c_str(), final_pkt.size());
		
		header->len = 0;
	}

	return 0;
}