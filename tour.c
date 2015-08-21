#include <unp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "abhmishra_api.h"

#define IP_PACKET_SIZE 1024
#define TOUR_SIZE 248
#define RT_PRO_NUM 227
#define MULTICAST_ADDR "227.227.227.227"
#define MULTICAST_PORT 2727
#define MAX_SIZE_OF_TOUR 100
#define RT_IDENTIFIER	272
#define PING_TTL		60
#define BUFSIZE 1500

//macros for sending pinging
#define ICMP_SIZE 64
#define IP_SIZE 84
#define EFRAME_SIZE 98


struct proto
{
	void	(*fproc)(char *, ssize_t, struct msghdr *, struct timeval *);
	void	(*fsend)(void);
	void	(*finit)(void);
	struct sockaddr  *sasend;
	struct sockaddr  *sarecv;	
	socklen_t	salen;	
	int			icmpproto;	
} *pr;


struct IPPayload{
	struct in_addr mcastIP; 	//4 bytes
	short mcastPort;			//2 bytes
	short index;				//2 bytes, index always indicates the dest addr
	int numofnodes;				//4 bytes
//	char tourlist[IP_PACKET_SIZE - 28]; // 4+4+2+2+20 = 32
	uint32_t tourlist[TOUR_SIZE]; //=(IP_PACKET_SIZE - 32)/4
};

struct IPPacket {                              
       struct iphdr header;		//20 bytes
       struct IPPayload payload;
};




int process_input(char**, char*, int, uint32_t*);
struct IPPayload* createIPPayload(struct in_addr,short,short,int,uint32_t*);
void joinMcastgroup(int,struct in_addr, struct in_addr);
void printIP(uint32_t);
void printIPPayload(struct IPPayload *input);
int maxofthree(int,int,int);
void sendIPPacket(int sockfd,struct IPPayload *payload);
char* getThisVM();
char* getVMwithaddr(uint32_t);
char* getIP(uint32_t);
void proc_v4(char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv);
void send_v4();
void sig_alrm(int);
void sendmcastmsg(char*);
void buildmcastmsg();


//--------------------------Global variables-----------------------
short isJoined = 0;
short pinglist[10] = {0};
int pf_sockfd,send_sockfd; // make PF_packet sock global, cause can pass value through signal
struct proto proto_v4 = {proc_v4,send_v4,NULL,NULL,NULL,0, IPPROTO_ICMP};
pid_t pid;
int icmp_data_len = 56;
struct sockaddr_in ping_destaddr;
struct in_addr hostip;
struct hwa_info *local_host_hwa;
int nsent;
int islastnode;
int echo_reply_counter;
int stoppinging;
struct in_addr temp_mcastIP;
char msgone[BUFSIZE];
char msgtwo[BUFSIZE];


void main(int argc,char *argv[]){
	int i,p;
	const int on = 1;
	short input_check, isSource;
	char *IPlist;
	uint32_t iplist[TOUR_SIZE];
	int rt_sockfd, pg_sockfd, recv_sockfd;
	struct sockaddr_in sa_send,sa_host;
	struct IPPayload *ippayload;
	char timebuffer[100];
    time_t ticks;
    struct timeval timeout;
    int use_another_select = 0;

	
	struct IPPacket *recvIPPacket;
	
	
	//these two variables check if ping for preceding node has started
	char *source_vm;
	int source_vm_num;
	uint32_t source_vm_addr;
	
	//these part of vars are a copy from book, for echo reply.
	int size;
	char recvbuf[BUFSIZE];
	char controlbuf[BUFSIZE];
	struct msghdr	msg;
	struct iovec	iov;
	struct timeval	tval;
	
	fd_set rset;
	int maxfdp1;
	
	recvIPPacket = malloc(sizeof(struct IPPacket));
		
	buildmcastmsg();
	if(argc > 1 && argc <= (MAX_SIZE_OF_TOUR+1)){
		printf("This is source node(%s)!\n",getThisVM());
		isSource = 1;
	}	
	else if(argc > (MAX_SIZE_OF_TOUR+1)){
		printf("Too many nodes on the tour, make it less than 100\n");
		exit(1);
	}
	else{
		printf("This is an intermediate node(%s)!\n",getThisVM());
		isSource = 0;
	} 
	
	IPlist = (char *)malloc(1024);
	
	if ((input_check = process_input(argv,IPlist,argc,iplist)) < 0){
		printf("Please check the name of VM nodes\n");
		exit(1);
	}	
	if(input_check > 0){
		printf("No consequentive nodes!\n");
		exit(1);
	}
	
	hostip.s_addr = iplist[0]; // give the local IP to hostip
	
	/*setup for pinging*/
	pid = getpid() & 0xffff;
	Signal(SIGALRM,sig_alrm);
	
	bzero(&sa_host, sizeof(sa_host));
	sa_host.sin_family = AF_INET;
	sa_host.sin_addr = hostip;
	
	pr = &proto_v4;
	pr->sasend = (SA*)&sa_host;
	pr->sarecv = Calloc(1,sizeof(struct sockaddr));
	pr->salen = sizeof(struct sockaddr);
	
	//setup global var ping_destaddr and islastnode
	ping_destaddr.sin_family = AF_INET;
	islastnode = 0;
	echo_reply_counter = 0;
	
	/**debugging method to check IPlist**/
//	printf("IPlist is %s\n",IPlist);
//	for(i=0;i<argc;i++)
//		printIP(iplist[i]);
//	printf("This is %s\n",getThisVM());

	
	/*Now, let's create these five sockets*/
	//First is the IP Raw socket for traversal
	rt_sockfd = Socket(AF_INET, SOCK_RAW, RT_PRO_NUM);
	Setsockopt(rt_sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	
	//IP raw socket from receiving echo reply
	pg_sockfd = Socket(AF_INET, SOCK_RAW, (IPPROTO_ICMP));
	size = 60*1024;
	Setsockopt(pg_sockfd,SOL_SOCKET,SO_RCVBUF,&size,sizeof(size));
	
	//pf packet socket to ping
	pf_sockfd = Socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	
	//UDP socket for receiving, setsockopt, and bind to multicast group 
	recv_sockfd = Socket(AF_INET, SOCK_DGRAM, 0);
	Setsockopt(recv_sockfd, SOL_SOCKET, SO_REUSEADDR,&on,sizeof(on));
	//set the socket non-blocking, with 5 seconds timeout
	setsockopt(recv_sockfd,SOL_SOCKET,SO_RCVTIMEO,(char *)&timeout,sizeof(struct timeval));
	memset(&temp_mcastIP,0,sizeof(struct in_addr));
	if(inet_aton((const char*)MULTICAST_ADDR, &temp_mcastIP) < 0){
		printf("inet_aton error: %s\n",strerror(errno));
		exit(1);
	}
	
//	printf("temp_mcastIp is %s\n", inet_ntoa(temp_mcastIP));
	sa_send.sin_addr.s_addr = temp_mcastIP.s_addr;
	sa_send.sin_port = (unsigned short) MULTICAST_PORT;
	sa_send.sin_family = AF_INET;
	Bind(recv_sockfd, (SA*)&sa_send, sizeof(struct sockaddr_in));
	
	//UDP socket for sending
	send_sockfd = Socket(AF_INET, SOCK_DGRAM, 0);
	Setsockopt(send_sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &on, sizeof(on));
	
	if(isSource){
		ippayload = createIPPayload(temp_mcastIP,(short)MULTICAST_PORT,1,argc,iplist);
		
		sendIPPacket(rt_sockfd,ippayload);
		
		joinMcastgroup(recv_sockfd,temp_mcastIP,hostip);
	}
	
	while(1){
		FD_ZERO(&rset);
		FD_SET(rt_sockfd, &rset);
		FD_SET(pg_sockfd, &rset);
		FD_SET(recv_sockfd,&rset);
		maxfdp1 = maxofthree(rt_sockfd, pg_sockfd,recv_sockfd)+1;
		
		if(use_another_select){
			p = select(maxfdp1, &rset, NULL, NULL, &timeout);
		}else{
			p = select(maxfdp1, &rset, NULL, NULL,NULL);	
		}
		if(p == 0){
			printf("Tour Ended, exit.\n");
			exit(0);
		}			
		if(p < 0){
			if(errno == EINTR){
//				printf("select EINTR\n");
				continue;
			} 
			else{
				printf("Select Error: %s\n", strerror(errno));
				exit(1);
			}
		} 
		
		
		if(FD_ISSET(pg_sockfd, &rset)){
//			printf("\n****pg_sock received pinging!!!****\n");
			memset(recvbuf, 0, BUFSIZE);
			iov.iov_base = recvbuf;
			iov.iov_len = sizeof(recvbuf);
			msg.msg_name = pr->sarecv;
			msg.msg_iov = &iov;
			msg.msg_iovlen = 1;
			msg.msg_control = controlbuf;

	
			msg.msg_namelen = pr->salen;
			msg.msg_controllen = sizeof(controlbuf);
			p = recvmsg(pg_sockfd, &msg, 0);
			if (p < 0) {
				if (errno == EINTR) continue;
				else{
					printf("recvmsg error in pg_socket");
					exit(1);
				}
			}

			Gettimeofday(&tval, NULL) ;
			
			(*pr->fproc)(recvbuf, p, &msg, &tval);
				
		}// end  of pg_sockfd
		
		

		if(FD_ISSET(rt_sockfd, &rset)){
//			printf("\n****rt_sock received data!!!****\n");
			Recvfrom(rt_sockfd,recvIPPacket, sizeof(struct IPPacket),0,NULL,NULL);
			
			// check protocol number and identification num, make sure it's the right packet
			if((ntohs(recvIPPacket->header.id) == RT_IDENTIFIER) 
				&& (recvIPPacket->header.protocol == RT_PRO_NUM)){
			//if check it's valid packet, then first print out message
				ticks = time(NULL);
				snprintf(timebuffer,sizeof(timebuffer),"%.24s\r\n", ctime(&ticks));
				timebuffer[strlen(timebuffer)-2]=0;
				
				//debugging method to print out the content of this payload
//				printIPPayload(&(recvIPPacket->payload));
				source_vm_addr = recvIPPacket->payload.tourlist[recvIPPacket->payload.index-1];
				source_vm = getVMwithaddr(source_vm_addr);
				printf("<%s> received source routing packet from <%s>\n",
					timebuffer,source_vm);
			
				//first check whether this node joined a group or not
				if(isJoined == 0){
					joinMcastgroup(recv_sockfd,recvIPPacket->payload.mcastIP,hostip);
					printf("%s joined a Multicast group.\n",getThisVM());
				}else{
					printf("%s has joined a group already.\n",getThisVM());
				}
				
				//2nd, check if this is the last node on the tourlist
				if(recvIPPacket->payload.numofnodes==(recvIPPacket->payload.index+1)){
				//this means this is the last node
					islastnode = 1;
					printf("\n\n******rt_socket received: last node on the tourlist***\n\n");
					
				}else{
				//otherwise increase the index and pass to next node along the tourlist
					recvIPPacket->payload.index += 1; // increase the index
					sendIPPacket(rt_sockfd,&recvIPPacket->payload);
				}
				
				
				if(sscanf(getVMwithaddr(source_vm_addr),"%*[^0-9]%d",&source_vm_num) <=0){
					printf("source_vm_num is %d\n",source_vm_num);
					printf("sscanf error: %s\n",strerror(errno));
					exit(1);
				}
				if(pinglist[source_vm_num]){
				//this means ping for this vm has started, don't do anything
					printf("Pinged already...\n");
					if(islastnode){
						stoppinging = 1;
//						signal(SIGALRM, SIG_DFL);
						sendmcastmsg(msgone);
					}
				}else{
				//not ping yet, start pinging, and set this bit to high
					pinglist[source_vm_num] = 1;
					printf("\nPING %s (%s): %d data bytes...........\n", getVMwithaddr(source_vm_addr), getIP(source_vm_addr),icmp_data_len);
					
					//set dest IP addr
					ping_destaddr.sin_addr.s_addr = (in_addr_t)source_vm_addr;
					//setup from here, and this will be done only once
					sig_alrm(SIGALRM);
				}

				
			}else{
				printf("Protocol or identification number doesn't match, drop packet.\n");
			}
			
		}// end of rt_sockfd
		
		
		if(FD_ISSET(recv_sockfd, &rset)){
			
			memset(recvbuf, 0, BUFSIZE);
			Recvfrom(recv_sockfd, recvbuf, BUFSIZE, 0, NULL, NULL);	
			
			printf("Node %s. Received:<%s>\n", getThisVM(),recvbuf);
			if(strstr(recvbuf,"please") != NULL){
			// this means 1st mcast msg received
				stoppinging = 1;
				timeout.tv_sec = 5;
				timeout.tv_usec = 0;
				use_another_select = 1;
//				signal(SIGALRM, SIG_DFL);
				sendmcastmsg(msgtwo);
			}

		}
	}
}//end of main()








//------------------ definition of all sub-routines---------------------

//check the commandline arguments, and update IPlist for traverse
//return 0 on success, -1 means some IP can't found with given host name
//return 1 means there are same nodes shows consequentively
int process_input(char **input, char *output, int argc, uint32_t *num_output){
	int return_val = 0;
	struct hostent *ho;
	char *temp_addr,*host_addr;
	uint32_t *temp_num;
	struct in_addr **in_addr_list;
	int i, list_index;
	 
	local_host_hwa = get_hw_addrs(); // get the info of local VM
	
	ho = malloc(sizeof(struct hostent));
	host_addr = malloc(20);
	
	//find the address of eth0
	while(local_host_hwa->hwa_next != NULL){
		if(strcmp(local_host_hwa->if_name,"eth0") == 0){			
			temp_addr = inet_ntoa(((struct sockaddr_in*)local_host_hwa->ip_addr) -> sin_addr);
//			printf("host_addr 1st is %s\n", host_addr);
//			printf("And this IP string length is %d\n",strlen(temp_addr));
			temp_num = (uint32_t*)&(((struct sockaddr_in*)local_host_hwa->ip_addr)->sin_addr.s_addr);
//			printf("temp_num is %d\n",*temp_num);
			memcpy(num_output,temp_num,sizeof(uint32_t));
			list_index = strlen(temp_addr);
			memcpy(output,temp_addr,list_index);
			memcpy(host_addr,temp_addr,list_index);
			break;
		}
		local_host_hwa = local_host_hwa -> hwa_next;
	}
//	printf("local ip is: %s\n", output);

	
	for(i=1;i<argc;i++){
		if(i == (argc-1)){//if this is the second to the last, 
			memset(ho,0,sizeof(*ho));
			if((ho = gethostbyname(*(input+i))) == NULL){
				printf("gethostbyname error: %s\n", strerror(errno));
				return_val = -1;
				break;
			}
			
			in_addr_list = (struct in_addr**)ho->h_addr_list;
			temp_addr = inet_ntoa(*in_addr_list[0]);
			temp_num = (uint32_t*)&(in_addr_list[0]->s_addr);
//			printf("temp_num is %d\n",*temp_num);
			memcpy(num_output+i,temp_num,sizeof(uint32_t));
			memcpy(output+list_index, temp_addr, strlen(temp_addr));
			break;
		}
		
		if(strcmp(*(input+i),*(input+i+1)) == 0){
			//means there nodes shows consequentively
			return_val = 1;
			break;
		}else{
			memset(ho,0,sizeof(*ho));
			if((ho = gethostbyname(*(input+i))) == NULL){
				printf("gethostbyname error: %s\n", strerror(errno));
				return_val = -1;
				break;
			}
			
			in_addr_list = (struct in_addr**)ho->h_addr_list;
			
			temp_addr = inet_ntoa(*in_addr_list[0]);
//			printf("host_addr 3st is %s\n", host_addr);
			if((strcmp(host_addr,temp_addr) == 0) && i==1){
//				printf("host_addr is %s\n", host_addr);
//				printf("temp_addr is %s\n", temp_addr);
				return_val = 1;
				break;
			}
			temp_num = (uint32_t*)&(in_addr_list[0]->s_addr);
//			printf("temp_num is %d\n",*temp_num);
			memcpy(num_output+i,temp_num,sizeof(uint32_t));
			memcpy(output+list_index, temp_addr, strlen(temp_addr));
			list_index +=  strlen(temp_addr);
		}
		
	}
	
	free(host_addr);	
	
// can't free local_host_hwa, need this info for pinging
//	free_hwa_info(local_host_hwa);
	return return_val;
}

struct IPPayload* createIPPayload(struct in_addr addr,short mcastNum,short index,int size,uint32_t* tourlist){
	struct IPPayload *ippl = malloc(sizeof(struct IPPayload));
	ippl->mcastIP = addr;
	ippl->mcastPort = mcastNum;
	ippl->index = index;
	ippl->numofnodes = size;
	if(tourlist != NULL)
		memcpy(ippl->tourlist,tourlist,TOUR_SIZE);
		
	return ippl;
}

void sendIPPacket(int sockfd,struct IPPayload *payload){
	struct IPPacket *ippacket;
	struct iphdr *ipheader;
	struct sockaddr_in destaddr;
	
	memset(&destaddr, 0, sizeof(struct sockaddr_in));
	
	destaddr.sin_addr.s_addr = (in_addr_t) payload->tourlist[payload->index];
	destaddr.sin_family = AF_INET;
//	printIP(destaddr.sin_addr.s_addr);

	ippacket = malloc(sizeof(struct IPPacket));
	ipheader = malloc(sizeof(struct iphdr));
	
	ipheader->version = 4;
	ipheader->ihl = 5;
	ipheader->tos = 0;
	ipheader->tot_len = htons(sizeof(struct IPPacket));
	ipheader->id = htons(RT_IDENTIFIER);
	ipheader->frag_off = 0;	
	ipheader->ttl = (PING_TTL);
	ipheader->protocol = (RT_PRO_NUM);
		
	ipheader->saddr = (in_addr_t) payload->tourlist[payload->index -1];
	ipheader->daddr = destaddr.sin_addr.s_addr;
	
	ipheader->check = 0;
//	ipheader->check = in_cksum((u_short *)ipheader, sizeof(struct iphdr));
	
	memcpy(&(ippacket->header),ipheader, sizeof(struct iphdr));
	memcpy(&(ippacket->payload), payload, sizeof(struct IPPayload));
	
//	printIP(ippacket->header.saddr);
//	printIP(ippacket->header.daddr);
	
	Sendto(sockfd, ippacket, sizeof(struct IPPacket), 0, (SA*)&destaddr, sizeof(destaddr));
	
}



void joinMcastgroup(int recv_sockfd,struct in_addr mcastIP,struct in_addr hostip){
	struct ip_mreq ipmreq;
	char *temp;
	
	//set isJoined to 1
	isJoined = 1;
	
	memset(&ipmreq, 0, sizeof(struct ip_mreq));
	
	ipmreq.imr_multiaddr.s_addr = mcastIP.s_addr;
	ipmreq.imr_interface.s_addr = hostip.s_addr;
//	printIP(hostip.s_addr);

	setsockopt(recv_sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &ipmreq, sizeof(struct ip_mreq));

}

char* getThisVM(){
	struct hwa_info *local_host;
	struct in_addr *temp_addr;
	struct hostent ho;
	 
	local_host = get_hw_addrs(); // get the info of local VM
	
//	ho = malloc(sizeof(struct hostent));
	
	//find the address of eth0
	while(local_host->hwa_next != NULL){
		if(strcmp(local_host->if_name,"eth0") == 0){
			temp_addr = &((struct sockaddr_in*)local_host->ip_addr)->sin_addr;
			break;
		}
		local_host = local_host -> hwa_next;
	}
	
	ho = *gethostbyaddr(temp_addr,sizeof(struct in_addr), AF_INET);
	
	return ho.h_name;
}

char* getVMwithaddr(uint32_t input){
	struct hostent ho;
	struct in_addr temp_addr;
	temp_addr.s_addr = (in_addr_t)input;
	ho = *gethostbyaddr(&temp_addr,sizeof(struct in_addr), AF_INET);
	return ho.h_name;
}

char* getIP(uint32_t input){
	struct in_addr temp_addr;
	temp_addr.s_addr = input;
	return inet_ntoa(temp_addr);
}

//------------------methods for pinging-----------
void sig_alrm(int signo){
	if(stoppinging){
//		alarm(100);
	}else{
		(*pr->fsend)();
		alarm(1);	
	}
	return;
}


// a copy of proc_v4 from book
void proc_v4(char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv){
	int				hlen1, icmplen;
	double			rtt;
	struct ip		*ip;
	struct icmp		*icmp;
	struct timeval	*tvsend;

	ip = (struct ip *) ptr;		/* start of IP header */
	hlen1 = ip->ip_hl << 2;		/* length of IP header */
	if (ip->ip_p != IPPROTO_ICMP)
		return;				/* not ICMP */

	icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
	if ( (icmplen = len - hlen1) < 8)
		return;				/* malformed packet */

	if (icmp->icmp_type == ICMP_ECHOREPLY) {
		if(islastnode && echo_reply_counter <= 5){
			//sendmcastmsg();
			if(echo_reply_counter == 5){
				stoppinging = 1;
//				signal(SIGALRM, SIG_DFL);
				sendmcastmsg(msgone);
				return;
			}
			echo_reply_counter++;
		}
		if (icmp->icmp_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			return;			/* not enough data to use */

		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		printf("%d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
				icmplen, Sock_ntop_host(pr->sarecv, pr->salen),
				icmp->icmp_seq, ip->ip_ttl, rtt);

	}
}


void send_v4(){
//	printf("send_v4() is working\n");
	int i;
	//it seems can't initialize icmp from frame, so define this icmp pointer and then memcpy
	struct hwaddr desthwaddr;
	struct sockaddr_ll sockll;
	char eframe_buffer[EFRAME_SIZE]; 
	struct ethhdr *eframeHeader;
	struct ip     *ipHeader;
	struct icmp   *icmpHeader;

	memset(eframe_buffer, 0, EFRAME_SIZE);
	memset(&sockll, 0, sizeof(struct sockaddr_ll));

	memset(&desthwaddr, 0, sizeof(struct hwaddr));
	
	printf("\n");
	if(areq((SA*)&ping_destaddr, sizeof(struct sockaddr_in),&desthwaddr) < 0){
		printf("areq error, exit!\n");
		exit(1);
	}
	printf("\n");
	
	//once got the hwaddr of dest, 1st, set up sockaddr_ll
	sockll.sll_family = PF_PACKET;        
	sockll.sll_hatype = ARPHRD_ETHER;
	sockll.sll_pkttype = PACKET_OTHERHOST;
	sockll.sll_halen = ETH_ALEN;
	sockll.sll_protocol = htons(ETH_P_IP);
	sockll.sll_ifindex = local_host_hwa->if_index;

	for (i = 0; i < ETH_ALEN; i++) {
		sockll.sll_addr[i] = desthwaddr.sll_addr[i];
	}

//now start filling up all different headers

//1st: filling up ethernet frame 
	eframeHeader = (struct ethhdr *)eframe_buffer;
	memcpy(eframe_buffer, (void *)desthwaddr.sll_addr, ETH_ALEN);
	memcpy(eframe_buffer + ETH_ALEN, (void* )local_host_hwa->if_haddr, ETH_ALEN);
	eframeHeader->h_proto = htons(ETH_P_IP);

//2nd: fill up ip header
	ipHeader = (struct ip *)(eframe_buffer + sizeof(struct ethhdr));
	ipHeader->ip_v = 4;
	ipHeader->ip_hl = 5;
	ipHeader->ip_p = IPPROTO_ICMP;
	ipHeader->ip_len = htons(IP_SIZE);
	ipHeader->ip_sum = 0;
	ipHeader->ip_id = 0;
	ipHeader->ip_off = 0;
	ipHeader->ip_tos = 0;
	ipHeader->ip_ttl = htons(PING_TTL);
	ipHeader->ip_src.s_addr = hostip.s_addr;
	ipHeader->ip_dst.s_addr = ping_destaddr.sin_addr.s_addr;

//3rd, icmp header
	icmpHeader = (struct icmp *)(eframe_buffer + sizeof(struct ethhdr) + sizeof(struct ip));
	icmpHeader->icmp_type = ICMP_ECHO;
	icmpHeader->icmp_code = 0;
	icmpHeader->icmp_id = pid;
	icmpHeader->icmp_seq = nsent++;
	memset(icmpHeader->icmp_data, 0xa5, 56);
	gettimeofday((struct timeval *)icmpHeader->icmp_data, NULL);

//important, the checksum will be calculated based upon from that header all
// the way to the end of the frame.
	icmpHeader->icmp_cksum = in_cksum((ushort *)icmpHeader, ICMP_SIZE);
	ipHeader->ip_sum = in_cksum ((ushort *)ipHeader, IP_SIZE);

	Sendto(pf_sockfd, eframe_buffer, EFRAME_SIZE, 0, (SA*)&sockll, sizeof(struct sockaddr_ll));
}

void sendmcastmsg(char* msg){
	struct sockaddr_in tempaddr;
	memset(&tempaddr, 0, sizeof(struct sockaddr_in));

	tempaddr.sin_family = AF_INET;
	tempaddr.sin_addr.s_addr = 	temp_mcastIP.s_addr;
	tempaddr.sin_port = (unsigned short) MULTICAST_PORT;
	
	printf("Node %s. Sending:<%s>\n", getThisVM(),msg);
	Sendto(send_sockfd, msg, strlen(msg), 0, (SA*)&tempaddr, sizeof(struct sockaddr_in));
}




//------------------------Debugging or very trivial methods-------------
//debugging method to print iP given Uint32_t
void printIP(uint32_t input){
	struct in_addr temp_addr;
	temp_addr.s_addr = input;
//	printf("ipNum is %d\n",input);
	printf("IP is %s\n",inet_ntoa(temp_addr));
}

//debugging method to print out the content of payload
void printIPPayload(struct IPPayload *input){
	int i;
	printf("mcastIP is ");
	printIP(input->mcastIP.s_addr);
	printf("Multicast prot num is %d\n",input->mcastPort);
	printf("Index is %d\n", input->index);
	printf("Num of nodes is %d\n", input->numofnodes);
	printf("Tourlist is:\n");
	for(i=0;i<(input->numofnodes);i++)
		printIP(input->tourlist[i]);
}



//Trival method to find max of three integers
int maxofthree(int one,int two,int three){
	int temp;
	if(one > two)	temp = one;
	else temp = two;
	
	if(temp > three) return temp;
	else return three;
}

void buildmcastmsg(){
	strcpy (msgone,"<<<<< This is node ");
	strcat (msgone,getThisVM());
	strcat (msgone," .  Tour has ended .  Group members please identify yourselves. >>>>>");
	
	strcpy (msgtwo,"<<<<< Node ");
	strcat (msgtwo,getThisVM());
	strcat (msgtwo," . I am a member of the group.>>>>>");

}












