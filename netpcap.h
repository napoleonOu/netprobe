#include<pcap.h>
#include<string>
#include<mutex>

//typedef std::function<void(unsigned char*,const struct*,const unsigned char*)> cbFunc;
//struct pcap_pkthdr
//{
//      struct timeval ts;
//      bpf_u_int32 caplen;//  表示抓到的数据长度
//      bpf_u_int32 len;   // 表示数据包的实际长度
//}
typedef struct ether_header{
	unsigned char ether_dhost[6];   //目的mac  
	unsigned char ether_shost[6];   //源mac  
	unsigned short ether_type;      //以太网类型
}* ethernet_protocol_p,ethheader;
class netprobe;
typedef void (*np)(unsigned char*,const struct pcap_pkthdr*,const unsigned char*);
class netprobe{
public:
	np np_t;
	netprobe();
	~netprobe();
	void probeStart(netprobe* np);
	static void eth_protocol_callback(unsigned char* charP,
				 const struct pcap_pkthdr* packet_header,
				 const unsigned char* p);
	
private:
	pcap_t* pcap_handle;
	std::string BPF_Str;
	char error_content[100];
	//std::string error_content;
	char* net_interface;
	static ethernet_protocol_p ethernet_p;
	//cbFunc cfunc;
};
