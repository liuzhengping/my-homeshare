#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>

#define MAX_CLIENT 10
pcap_t *fp;
struct {
	u_int mac[6];
	u_int ip[4];
} mac_ip_table[MAX_CLIENT];
pcap_if_t *alldevs, *d;

int equal_mac(u_int left[6],u_int right[6]){
	int i;
	for(i=0;(i<6) && (left[i]==right[i]); ++i);
	if (i==6)
		return 1;
	return 0;
}

int equal_ip(u_int left[4],u_int right[6]){
	int i;
	for(i=0;(i<4) && (left[i]==right[i]); ++i);
	if (i==4)
		return 1;
	return 0;
}

int get_mac(u_int ip[4],int max){
	int i;
	for(i=0;i<max;++i){
		if ( equal_ip(mac_ip_table[i].ip,ip))
			return i;
	}
	return -1;
}

int get_ip(u_int mac[6],int max){
	int i;
	for(i=0; i<max; ++i){
		if (equal_mac(mac_ip_table[i].mac,mac))
			return i;
	}
	return -1;
}
		

int send_data(char *p,int len){
	if (pcap_sendpacket(fp,p,len) != 0){
		fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(fp));
		return 0;
	}
	return 1;
}

int show_devices()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
            fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
            return -1;
    }    
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s\n    ", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    
    if (i==0)
    {
        fprintf(stderr,"No interfaces found! Exiting.\n");
        return -1;
    }
    return i;
}    

    
void print_packet(u_char * ss,int len)
{ 
    int i; 
    for(i=0;i<len;i++) 
        printf("%2x",ss[i]); 
    printf("\n"); 
} 
    
int main(int argc, char **argv)
{
    u_int inum,i,j,k = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res,max_client = 0;
	struct pcap_pkthdr *header;
	u_char *pkt_data;
	u_int server_mac[6],gateway_mac[6],temp_mac[6];
	u_int server_ip[4],temp_ip[4];
	u_int server_mask[4];
	FILE * fpf;
	if ( !(fpf = fopen("./data.txt","r")) ){
		printf("请生成data.txt文件\n");
		return -1;
	}
	for(i=0;i<5;i++)
		fscanf(fpf,"%2x-",&server_mac[i]);
	fscanf(fpf,"%2x",&server_mac[i]);
	for(i=0;i<3;i++)
		fscanf(fpf,"%d.",&server_ip[i]);
	fscanf(fpf,"%d",&server_ip[i]);
	for(i=0;i<3;i++)
		fscanf(fpf,"%d.",&server_mask[i]);
	fscanf(fpf,"%d",&server_mask[i]);
	for(i=0;i<5;i++)
		fscanf(fpf,"%2x-",&gateway_mac[i]);
	fscanf(fpf,"%2x",&gateway_mac[i]);
	fscanf(fpf,"%d",&inum);
	fclose(fpf);
	for(i=0;i<6;i++)
		printf("%2x-",server_mac[i]);
	for(i=0;i<4;i++)
		printf("%d.",server_ip[i]);
	for(i=0;i<4;i++)
		printf("%d.",server_mask[i]);
	printf("\n");
    i = show_devices();
	if(i == -1){
        return -1;
    }
    if (inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }
    /* Jump to the selected adapter */
    for (d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

    /* Open the device */
    if ( (fp= pcap_open(d->name,
                        100 /*snaplen*/,
                        PCAP_OPENFLAG_PROMISCUOUS /*flags*/,
                        20 /*read timeout*/,
                        NULL /* remote authentication */,
                        errbuf)
                        ) == NULL)
    {
        fprintf(stderr,"\nError opening adapter\n");
        return -1;
    }

	while((res = pcap_next_ex( fp, &header, &pkt_data)) >= 0)
	{
		if ( (res == 0) || (header->len < 34) )
			continue;
		if ( pkt_data[12] == 0x08 && pkt_data[13] == 0x06 ) {  //  处理 ARP 请求
 			if ( pkt_data[21] == 0x01 ){ 
				for(i=0;i<4;i++)
					temp_ip[i] = pkt_data[38+i];    // 目标IP
				if(get_mac(temp_ip,max_client) != -1){
					for(i=0;i<6;i++)
						pkt_data[i] = pkt_data[i+6];
					for(i=0;i<6;i++)
						pkt_data[i+6] = server_mac[i];
					pkt_data[21] == 0x02;
					for(i=0;i<6;i++)
						pkt_data[i+22] = server_mac[i];
					for(i=0;i<4;i++)
						pkt_data[i+38] = pkt_data[i+28];

					for(i=0;i<4;i++)
						pkt_data[i+28] = temp_ip[i];
					for(i=0;i<6;i++)
						pkt_data[i+32] = pkt_data[i];

					send_data(pkt_data,header->len);
				}
			}
			continue;
		}
        if ( pkt_data[12] == 0x08 && pkt_data[13] == 0x00 ) {  //处理 tcp udp 请求
			if (pkt_data[23] == 0x11 || pkt_data[23] == 0x06) {  //tcp/udp
				for(i=0;i<6;i++){   // 目标MAC不为本机的跳过
				   if(pkt_data[i] != server_mac[i])
					   break;
				}
				if (i!=6)
				   continue;
				for(i=0;i<4;i++) {       // source ip != server ip
				   if(pkt_data[i+26] != server_ip[i])
					   break;
				}
				if(i==4)                // 源ip为本机IP的跳过
					continue;
				for(j=0;j<4;j++){  //是否同一网段
					if ( (pkt_data[j+26] & server_mask[j]) != ( server_ip[j] & server_mask[j] ) )
						break;
				}
				if (j == 4){  // 客户机发来的数据包
					for(j=0;j<6;j++){
						temp_mac[j] = pkt_data[j+6];
						pkt_data[j] = gateway_mac[j];  //改修目标MAC地址
						pkt_data[j+6] = server_mac[j];
					}
					if (get_ip(temp_mac,max_client) == -1){  //添加一个记录
						for(j=0;j<4;++j)
							mac_ip_table[max_client].ip[j] = pkt_data[j+26];
						for(j=0;j<6;++j)
							mac_ip_table[max_client].mac[j] = temp_mac[j];
						max_client++;
						printf("add a client !\n");
					}
					send_data(pkt_data,header->len);
				}
				else{
					if (max_client == 0)
						continue;
					else{
						for(j=0;j<4;j++)
							temp_ip[j] = pkt_data[30+j];
						j = get_mac(temp_ip,max_client);
						if (j != -1){
							for(k=0;k<6;++k)
								pkt_data[k+6] = pkt_data[k];
							for(k=0;k<6;++k)
								pkt_data[k] = mac_ip_table[j].mac[k];
							send_data(pkt_data,header->len);
							/*
							for(k=0;k<6;k++)
								printf("%2x-",mac_ip_table[j].mac[k]);
							for(k=0;k<4;k++)
								printf("%d.",mac_ip_table[j].ip[k]);
							printf("\n");
							*/
						}
					}
				}
			}
		}
	}
    if(res == -1)
    {
        fprintf(stderr, "Error reading the packets: %s\n", pcap_geterr(fp));
        return -1;
    }
    pcap_close(fp);
    return 0;
}
