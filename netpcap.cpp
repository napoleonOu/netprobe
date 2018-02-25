#include"netpcap.h"
#include<pcap.h>
#include<iostream>
#include<assert.h>
#include<functional>
#define BUFSIZE 1514
ethernet_protocol_p netprobe::ethernet_p=NULL;
netprobe::netprobe(){
	//cfunc=std::bind(&netprobe::eth_protocol_callback,this,_1,_2,_3,_4);
	np_t=eth_protocol_callback;
	net_interface=pcap_lookupdev(error_content);
	assert(net_interface);
	pcap_handle=pcap_open_live(net_interface,BUFSIZE,1,0,error_content);
	assert(pcap_handle);
	
	//if(NULL==net_interface){
	//	std::cout<<"error when lookupdev"<<std::endl;
	//}
	//std::bind
			
}
netprobe::~netprobe(){
	
	pcap_close(pcap_handle);
	delete net_interface;
}
void netprobe::probeStart(netprobe* np){
	unsigned char* mac_string;
	unsigned short ethernet_type;
	if(pcap_loop(pcap_handle,-1,np_t,NULL)<0)
		std::cout<<"pcap_loop error";
}
void netprobe::eth_protocol_callback(unsigned char* charP,
				 const struct pcap_pkthdr* packet_header,
				 const unsigned char* p){
	unsigned char *mac_string;
	std::cout<<"time:"<<ctime((time_t*)&(packet_header->ts.tv_sec))<<std::endl;
	ethernet_p=(ethernet_protocol_p)p;
	mac_string=(unsigned char *)ethernet_p->ether_shost;
	std::cout<<"short:"<<mac_string<<std::endl;
	mac_string=(unsigned char *)ethernet_p->ether_dhost;
	std::cout<<"long:"<<mac_string<<std::endl;
}
