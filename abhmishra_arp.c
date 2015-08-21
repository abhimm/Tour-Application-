#include "abhmishra_arp.h"
int main()
{

    /* General variable*/
    fd_set rset;
    int max_fd;

    /* ARP communication variables */
    int pf_sock_fd;
    struct arp_frame rcvd_arp_frame;
    struct sockaddr_ll remote_arp_sock_addr;
    socklen_t pf_sock_len;

    /* ARP routing application communication variables */
    int domain_listen_sock_fd, domain_conn_sock_fd;
    struct sockaddr_un tour_app_sock_addr;
    struct sockaddr_un local_arp_sock_addr;
    struct arp_request_data arp_req;
    socklen_t un_sock_len;
    int counter;

    /* Initialize global variables */
    hwa_info_head = NULL;

    arp_cache_entry_head = NULL;

    memset(incomplete_eth_addr, 0, sizeof(incomplete_eth_addr));

    /* set broadcast address to use later*/
    for(counter = 0; counter < 6; counter++)
    {
        broadcast_mac_addr[counter] = 0xff;
    }

    /* Generate HWA Information */
    prepare_hwa_info();

    /* Create socket for communication with routing application */
    unlink(ARP_SUN_PATH);

    memset(&local_arp_sock_addr, 0, sizeof(struct sockaddr_un));

    local_arp_sock_addr.sun_family = AF_UNIX;
    strcpy(local_arp_sock_addr.sun_path, ARP_SUN_PATH);

    if((domain_listen_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        fprintf(stderr, "Error while creating UNIX domain socket: %s\n", strerror(errno));
        exit(1);
    }

    if(bind(domain_listen_sock_fd, (struct sockaddr*)(&local_arp_sock_addr),  sizeof(struct sockaddr_un)) < 0)
    {
        fprintf(stderr, "Error while binding UNIX domain socket: %s\n", strerror(errno));
        exit(1);
    }

    /* Create socket for remote host-ARP communication */
    if((pf_sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ARP_PROTOCOL_ID))) < 0)
    {
        unlink(ARP_SUN_PATH);
        fprintf(stderr, "Error while creating PF_PACKET socket: %s", strerror(errno));
        exit(1);
    }

    /* start listening on unix domain socket */
    if(listen(domain_listen_sock_fd, 5) == -1)
    {
        unlink(ARP_SUN_PATH);
        fprintf(stderr, "Error while creating PF_PACKET socket: %s", strerror(errno));
        exit(1);
    }
    /* Process incoming data */
    while(1)
    {
        FD_ZERO(&rset);
        FD_SET(domain_listen_sock_fd, &rset);
        FD_SET(pf_sock_fd, &rset);
        max_fd = ((domain_listen_sock_fd > pf_sock_fd)? domain_listen_sock_fd : pf_sock_fd) + 1 ;

        if(select(max_fd, &rset, NULL, NULL, NULL) < 0)
        {
            if(errno == EINTR)
                continue;
            fprintf(stderr, "Error while select:%s\n", strerror(errno));
            unlink(ARP_SUN_PATH);
            exit(1);
        }

        /* message received from tour application */
        if(FD_ISSET(domain_listen_sock_fd, &rset))
        {
            /* accept the connecion from tour application */
            memset(&tour_app_sock_addr, 0, sizeof(struct sockaddr_un));
            un_sock_len = sizeof(struct sockaddr_un);

           if((domain_conn_sock_fd = accept(domain_listen_sock_fd, (struct sockaddr*)&tour_app_sock_addr, &un_sock_len)) < 0)
           {
                if(errno != EINTR)
                {
                    fprintf(stderr, "Error while accepting the connection: %s\n", strerror(errno));
                    unlink(ARP_SUN_PATH);
                    exit(1);
                }
           }

            /* process accepted connection from tour application */
            process_rcvd_arp_request(pf_sock_fd, domain_conn_sock_fd);

        }

        /* message received from remote host */
        if(FD_ISSET(pf_sock_fd, &rset))
        {
            memset(&remote_arp_sock_addr, 0, sizeof(struct sockaddr_ll));
            memset(&rcvd_arp_frame, 0, sizeof(struct arp_frame));
            pf_sock_len = sizeof(struct sockaddr_ll);

            if(recvfrom(pf_sock_fd, &rcvd_arp_frame, sizeof(struct arp_frame), 0, (struct sockaddr*)&remote_arp_sock_addr, &pf_sock_len) < 0)
            {
                unlink(ARP_SUN_PATH);
                fprintf(stderr, "Error while receiving ARP packet from remote host: %s\n", strerror(errno));
                exit(1);
            }
            /* process received arp frame containing either request or reply */
            process_rcvd_arp_frame(pf_sock_fd, remote_arp_sock_addr, rcvd_arp_frame);


        }

    }


}

/****************************************** start of prepare_hwa_info function ******************************************/
void prepare_hwa_info()
{
    struct hwa_info *temp_hwa_info;
    char prnt_hwa_addr[19];
    int i, j;

    temp_hwa_info = hwa_info_head = Get_hw_addrs();

    memset(prnt_hwa_addr, 0, sizeof(prnt_hwa_addr));

    /* Print all interfaces */
    fprintf(stdout, "-----------------------------<Available Interfaces>--------------------------------\n");

    while(temp_hwa_info != NULL)
    {
        /* check if interface is eth0 */
        if(strcmp(temp_hwa_info->if_name, "eth0") == 0)
        {
            if(temp_hwa_info->ip_addr != NULL)
            {
                if(temp_hwa_info->ip_alias != 1)
                {
                    strcpy(host_primary_ip_addr, (char *)sock_ntop(temp_hwa_info->ip_addr, sizeof(*temp_hwa_info->ip_addr)));
                    host_primary_hwa_info = temp_hwa_info;
                }

                /* Get MAC address in presentable form */
                for( i = 0, j = 0; i < 6; i++, j = j + 3)
                    sprintf((char*)(prnt_hwa_addr + j), (i != 5)? "%02x:" : "%02x", temp_hwa_info->if_haddr[i] & 0xff);

                /* print interface information */
                fprintf(stdout, "Interface Name: %s\tInterface Index: %d\tIP Address: %s\tHardware Address: %s\tAlias: %s\n",
                                temp_hwa_info->if_name, temp_hwa_info->if_index, sock_ntop(temp_hwa_info->ip_addr, sizeof(*temp_hwa_info->ip_addr)), prnt_hwa_addr,((temp_hwa_info->ip_alias == 1)? "Yes" : "No") );
            }
            memset(prnt_hwa_addr, 0, sizeof(prnt_hwa_addr));
        }
        temp_hwa_info = temp_hwa_info->hwa_next;
    }
    fprintf(stdout, "---------------------------------------<*>-----------------------------------------\n");
}
/****************************************** end of prepare_hwa_info function ******************************************/

/****************************************** start of process_rcvd_arp_request function ******************************************/
void process_rcvd_arp_request(int pf_sock_fd, int domain_conn_sock_fd)
{
    fd_set rset;
    struct arp_request_data rcvd_arp_req;
    int no_bytes_read;
    struct arp_frame *new_arp_frame;
    struct arp_cache_entry  *temp_arp_cache_entry = NULL;
    struct in_addr src_ip_addr;
    struct hwa_info *temp_hwa_info = hwa_info_head;
    struct arp_request_data arp_reply_to_api;
    while(1)
    {
        FD_ZERO(&rset);
        FD_SET(domain_conn_sock_fd, &rset);

        if(select(domain_conn_sock_fd+1, &rset, NULL, NULL, NULL) < 0)
        {
            if(errno == EINTR)
                continue;

            unlink(ARP_SUN_PATH);
            fprintf(stderr, "Error while select during receving message from tour application: %s\n", strerror(errno));
            exit(1);
        }

        if(FD_ISSET(domain_conn_sock_fd, &rset))
        {
            /* read request on socket */
            memset(&rcvd_arp_req, 0 , sizeof(struct arp_request_data));
            no_bytes_read = read(domain_conn_sock_fd, &rcvd_arp_req, sizeof(struct arp_request_data));
            if( no_bytes_read < 0)
            {
                if(errno == EINTR)
                    continue;
                fprintf(stderr, "Error while reading message from tour application:%s\n", strerror(errno));
                unlink(ARP_SUN_PATH);
                exit(1);
            }
            else if(no_bytes_read == 0) /* tour app closed the connection */
            {
                fprintf(stdout, "API closed the socket, removing incomplete entry\n");

                /* remove entry corresponding to that destination */
                remove_incomplete_cache_entry(domain_conn_sock_fd);

                /* close connection socket */
                close(domain_conn_sock_fd);

                break;
            }
            else
            {
                /* get arp cache entry if exists */
                temp_arp_cache_entry = get_arp_cache_entry(rcvd_arp_req.ip_addr.sin_addr);


                /* if entry is not present, discover destination ethernet address */
                if(temp_arp_cache_entry == NULL)
                {

                    fprintf(stdout, "Creating incomplete cache entry for IP address: %s\n", inet_ntoa(rcvd_arp_req.ip_addr.sin_addr));

                    /* add an incomplete entry to arp_cache */
                    add_arp_cache_entry(rcvd_arp_req.ip_addr.sin_addr, domain_conn_sock_fd, 0, NULL);

                    /* prepare and broadcast arp request message on eth0*/
                    memset(&src_ip_addr, 0, sizeof(struct in_addr));

                    if(inet_pton(AF_INET, host_primary_ip_addr, &src_ip_addr) != 1)
                    {
                        unlink(ARP_SUN_PATH);
                        fprintf(stderr, "Error while converting presentation format IP address to network format:%s\n", strerror(errno));
                        exit(1);
                    }

                    new_arp_frame = prepare_arp_frame(broadcast_mac_addr, host_primary_hwa_info->if_haddr, ARPOP_REQUEST, src_ip_addr, rcvd_arp_req.ip_addr.sin_addr, PACKET_BROADCAST);

                    send_arp_frame(pf_sock_fd, new_arp_frame, PACKET_BROADCAST);

                    break;
                }
                else
                {
                    if(temp_arp_cache_entry->client_domain_sock_fd != -1)
                    {
                        fprintf(stdout, "ARP request to retrieve ethernet address for IP address: %s already sent\n", inet_ntoa(temp_arp_cache_entry->ip_address));
                        return;
                    }

                    /* Entry avialable; reply directly */
                    memset(&arp_reply_to_api, 0, sizeof(struct arp_request_data));
                    arp_reply_to_api.ip_addr = rcvd_arp_req.ip_addr;
                    arp_reply_to_api.hw_addr.sll_halen = ETH_ALEN;
                    arp_reply_to_api.hw_addr.sll_hatype = ARPHRD_ETHER;
                    arp_reply_to_api.hw_addr.sll_ifindex = temp_arp_cache_entry->ifindex;
                    memcpy(arp_reply_to_api.hw_addr.sll_addr, temp_arp_cache_entry->hw_addr, 6);

                    fprintf(stdout, "Cache entry available for IP address: %s, replying to API\n", inet_ntoa(rcvd_arp_req.ip_addr.sin_addr));

                    if(write(domain_conn_sock_fd, &arp_reply_to_api, sizeof(struct arp_request_data)) < 0)
                    {
                        unlink(ARP_SUN_PATH);
                        fprintf(stderr, "Error while writing back to API:%s\n", strerror(errno));
                        exit(1);
                    }

                    close(domain_conn_sock_fd);
                    break;
                }
            }
        }
    }
}
/****************************************** end of process_rcvd_arp_request function ******************************************/

/****************************************** start of add_arp_cache_entry function ******************************************/
void add_arp_cache_entry(struct in_addr dest_ip_addr, int domain_conn_sock_fd, uint32_t ifindex, unsigned char* dest_hw_addr)
{
    struct arp_cache_entry *new_arp_cache_entry, *temp_arp_cache_entry= arp_cache_entry_head;

    new_arp_cache_entry = (struct arp_cache_entry*)malloc(sizeof(struct arp_cache_entry));
    memset(new_arp_cache_entry, 0, sizeof(struct arp_cache_entry));
    new_arp_cache_entry->client_domain_sock_fd = domain_conn_sock_fd;
    new_arp_cache_entry->hatype = ARPHRD_ETHER;
    new_arp_cache_entry->ip_address = dest_ip_addr;
    new_arp_cache_entry->ifindex = ifindex;
    if(dest_hw_addr != NULL)
        memcpy(new_arp_cache_entry->hw_addr, dest_hw_addr, 6);

    new_arp_cache_entry->next_entry = NULL;

    if(arp_cache_entry_head == NULL)
    {
        arp_cache_entry_head = new_arp_cache_entry;
    }
    else
    {
        while(temp_arp_cache_entry->next_entry != NULL)
        {
            temp_arp_cache_entry = temp_arp_cache_entry->next_entry;
        }

        temp_arp_cache_entry->next_entry = new_arp_cache_entry;
    }
}
/****************************************** end of add_arp_cache_entry function ******************************************/


/****************************************** start of remove_incomplete_cache_entry function ******************************************/
void remove_incomplete_cache_entry(int domain_conn_sock_fd)
{
    struct arp_cache_entry *temp_arp_cache_entry = arp_cache_entry_head;
    struct arp_cache_entry *prev_arp_cache_entry = NULL;

    while(temp_arp_cache_entry != NULL)
    {
        if(temp_arp_cache_entry->client_domain_sock_fd == domain_conn_sock_fd)
        {
            if(prev_arp_cache_entry != NULL)
            {
                prev_arp_cache_entry->next_entry = temp_arp_cache_entry->next_entry;
            }
            else
            {
                arp_cache_entry_head = temp_arp_cache_entry->next_entry;
            }

            fprintf(stdout, "Routing Application closed connection: removing incomplete entry due to time out\n");
            free(temp_arp_cache_entry);
            break;
        }

        prev_arp_cache_entry = temp_arp_cache_entry;
        temp_arp_cache_entry = temp_arp_cache_entry->next_entry;
    }
}
/****************************************** end of remove_incomplete_cache_entry function ******************************************/

/****************************************** start of get_arp_cache_entry function ******************************************/
struct arp_cache_entry* get_arp_cache_entry(struct in_addr dest_ip_addr)
{
    struct arp_cache_entry *temp_arp_cache_entry = arp_cache_entry_head;

    while(temp_arp_cache_entry != NULL)
    {
        if(temp_arp_cache_entry->ip_address.s_addr == dest_ip_addr.s_addr)
            break;
        temp_arp_cache_entry = temp_arp_cache_entry->next_entry;
    }

    return temp_arp_cache_entry;
}
/****************************************** end of get_arp_cache_entry function ******************************************/


/****************************************** start of prepare_arp_frame function ******************************************/
struct arp_frame* prepare_arp_frame(unsigned char* dest_eth_address, unsigned char *src_eth_address, uint16_t arp_operation, struct in_addr src_ip_addr, struct in_addr dest_ip_addr, uint16_t packet_type)
{
    struct arp_frame *temp_arp_frame;

    temp_arp_frame = (struct arp_frame*)malloc(sizeof(struct arp_frame));

    memset(temp_arp_frame, 0, sizeof(struct arp_frame));

    /* arp operation */
    temp_arp_frame->msg.arp_operation = arp_operation;
     /* frame type */
    temp_arp_frame->header.frame_type = htons(ARP_PROTOCOL_ID);
    /* arp message ID */
    temp_arp_frame->msg.arp_msg_id = ARP_MSG_ID;
    /* hardware protocol size */
    temp_arp_frame->msg.hardware_size = ETH_ALEN; /* 6 */
    /* hardware type */
    temp_arp_frame->msg.hardware_type = ARPHRD_ETHER;
    /* protocol size */
    temp_arp_frame->msg.protocol_size = 4;
    /* protocol type */
    temp_arp_frame->msg.protocol_type = ETH_P_IP;

    /* destination ethernet address */

    memcpy(temp_arp_frame->header.eth_dest_addr, dest_eth_address, 6);
    if ( packet_type == PACKET_OTHERHOST)
    {
        memcpy(temp_arp_frame->msg.target_eth_address, dest_eth_address, 6);
    }

    /* source ethernet address */
    memcpy(temp_arp_frame->header.eth_src_addr, src_eth_address, 6);
    memcpy(temp_arp_frame->msg.sender_eth_address, src_eth_address, 6);

    temp_arp_frame->msg.sender_ip_addr.s_addr = src_ip_addr.s_addr;
    temp_arp_frame->msg.target_ip_addr.s_addr = dest_ip_addr.s_addr;

    return temp_arp_frame;
}
/****************************************** end of prepare_arp_frame function ******************************************/


/****************************************** start of send_arp_frame function ******************************************/
void send_arp_frame(int pf_sock_fd, struct arp_frame* arp_frame_to_send, uint16_t packet_type)
{
    struct sockaddr_ll dest_sock_addr;
    int counter;


    memset(&dest_sock_addr, 0, sizeof(struct sockaddr_ll));

    /* set destination socket address */
    for(counter = 0; counter < 6; counter++)
    {
        dest_sock_addr.sll_addr[counter] = arp_frame_to_send->header.eth_dest_addr[counter];
    }

    /* Unused octate */
    dest_sock_addr.sll_addr[6] = 0x00;
    dest_sock_addr.sll_addr[7] = 0x00;

    dest_sock_addr.sll_family = PF_PACKET;
    dest_sock_addr.sll_hatype = ARPHRD_ETHER;
    dest_sock_addr.sll_pkttype = packet_type; /* contained in if_packet.h */
    dest_sock_addr.sll_halen = ETH_ALEN; /* contained in if_ether.h */
    dest_sock_addr.sll_ifindex = host_primary_hwa_info->if_index;
    dest_sock_addr.sll_protocol = ARP_PROTOCOL_ID;

    /* send arp frame */
    if(sendto(pf_sock_fd, arp_frame_to_send, sizeof(struct arp_frame), 0, (struct sockaddr*)&dest_sock_addr, sizeof(struct sockaddr_ll)) < 0)
    {
        if(packet_type == PACKET_BROADCAST)
            fprintf(stderr, "Error while broadcasting ARP request on interface - %s: %s\n", host_primary_hwa_info->if_name, strerror(errno));
        else if(packet_type == PACKET_OTHERHOST)
            fprintf(stderr, "Error while sending ARP reply on interface - %s: %s\n", host_primary_hwa_info->if_name, strerror(errno));

        unlink(ARP_SUN_PATH);
        exit(1);
    }

     fprintf(stdout, "Sending out an ARP %s\n", (arp_frame_to_send->msg.arp_operation == ARPOP_REQUEST) ? "REQUEST" : "REPLY");
    /* print sent ARP frame information */
    print_arp_frame_info(arp_frame_to_send);
}
/****************************************** end of send_arp_frame function ******************************************/

/****************************************** start of print_arp_frame_info function ******************************************/
void print_arp_frame_info(struct arp_frame *arp_frame_to_print)
{
    char *prnt_src_mac, *prnt_dest_mac, *prnt_arp_src_mac, *prnt_arp_dest_mac;
    int i,j;

    /* print information abount sent ARP requet/reply */
    prnt_src_mac = malloc(19);
    prnt_dest_mac = malloc(19);
    prnt_arp_src_mac = malloc(19);
    prnt_arp_dest_mac = malloc(19);

    memset(prnt_src_mac, 0, 19);
    memset(prnt_dest_mac, 0, 19);
    memset(prnt_arp_src_mac, 0, 19);
    memset(prnt_arp_dest_mac, 0, 19);


    for(i = 0, j = 0; i < 6; i++, j = j+3)
    {
        sprintf((char*)(prnt_src_mac + j), (i != 5)? "%02x:" : "%02x" ,  arp_frame_to_print->header.eth_src_addr[i]& 0xff);
        sprintf((char*)(prnt_dest_mac + j), (i != 5)? "%02x:" : "%02x", arp_frame_to_print->header.eth_dest_addr[i] & 0xff);
        sprintf((char*)(prnt_arp_src_mac + j), (i != 5)? "%02x:" : "%02x" , arp_frame_to_print->msg.sender_eth_address[i] & 0xff);
        sprintf((char*)(prnt_arp_dest_mac + j), (i != 5)? "%02x:" : "%02x", arp_frame_to_print->msg.target_eth_address[i] & 0xff);
    }


    fprintf(stdout, "***************************Header Information************************\n");
    fprintf(stdout, "Destination ethernet address: %s\n", prnt_dest_mac);
    fprintf(stdout, "Source ethernet address: %s\n", prnt_src_mac);
    fprintf(stdout, "Frame Type: %x\n \n", ARP_PROTOCOL_ID);

    fprintf(stdout, "***************************ARP Frame Information************************\n");
    fprintf(stdout, "ARP Message Type: %s\n", (arp_frame_to_print->msg.arp_operation == ARPOP_REQUEST) ? "REQUEST" : "REPLY");
    fprintf(stdout, "Target ethernet address: %s\n", prnt_arp_dest_mac);
    fprintf(stdout, "Sender ethernet address: %s\n", prnt_arp_src_mac);
    fprintf(stdout, "Target IP address: %s\n", inet_ntoa(arp_frame_to_print->msg.target_ip_addr));
    fprintf(stdout, "Sender IP address: %s\n", inet_ntoa(arp_frame_to_print->msg.sender_ip_addr));
    fprintf(stdout, "Hardware Type: %hu\n", ARPHRD_ETHER);
    fprintf(stdout, "Hardware size: %hu\n", ETH_ALEN);
    fprintf(stdout, "Protocol Type: %x\n", ETH_P_IP);
    fprintf(stdout, "Protocol size: %hu\n\n", 4);
}

/****************************************** end of print_arp_frame_info function ******************************************/

/****************************************** start of process_rcvd_arp_frame function ******************************************/
void process_rcvd_arp_frame(int pf_sock_fd, struct sockaddr_ll remote_arp_sock_addr, struct arp_frame rcvd_arp_frame)
{

    /* First received ARP frame information */
    fprintf(stdout, "Received an ARP %s\n", (rcvd_arp_frame.msg.arp_operation == ARPOP_REQUEST ? "REQUEST" : "REPLY") );
    print_arp_frame_info(&rcvd_arp_frame);

    switch(rcvd_arp_frame.msg.arp_operation)
    {
        case ARPOP_REQUEST:
            process_rcvd_arp_req_frame(pf_sock_fd, remote_arp_sock_addr, rcvd_arp_frame);
            break;

        case ARPOP_REPLY:
            process_rcvd_arp_rep_frame(pf_sock_fd, remote_arp_sock_addr, rcvd_arp_frame);
            break;

        default:
            fprintf(stderr, "Invalid ARP frame type: ARP frame can't be processed\n");
            unlink(ARP_SUN_PATH);
            exit(1);
    }

}
/****************************************** end of process_rcvd_arp_frame function ******************************************/

/****************************************** start of process_rcvd_arp_req_frame function ******************************************/
void process_rcvd_arp_req_frame(int pf_sock_fd, struct sockaddr_ll remote_arp_sock_addr, struct arp_frame rcvd_arp_frame)
{
    int is_host_destination = 0;
    struct sockaddr_in *host_sock_addr;
    struct arp_cache_entry *available_arp_cache_entry = NULL;
    struct arp_frame *new_arp_frame;
    struct arp_request_data arp_reply_to_api;
    /* check if received frame belongs to this modules ID*/
    if(rcvd_arp_frame.msg.arp_msg_id != ARP_MSG_ID)
    {
        return;
    }

    host_sock_addr = (struct sockaddr_in*)host_primary_hwa_info->ip_addr;

    /* check if the host intended destination */
    if( host_sock_addr->sin_addr.s_addr == rcvd_arp_frame.msg.target_ip_addr.s_addr )
    {
        is_host_destination = 1;
    }

    /* check if an ARP cache entry exists for this ARP request sender */
    available_arp_cache_entry = get_arp_cache_entry(rcvd_arp_frame.msg.sender_ip_addr);

    /* if an entry present, update it */
    if(available_arp_cache_entry != NULL)
    {
        /* check if entry is incomplete */
        if((available_arp_cache_entry->client_domain_sock_fd != -1) && (strncmp(available_arp_cache_entry->hw_addr, incomplete_eth_addr,6) == 0))
        {
            /* if entry is incomplete, result is present, send ethernet address to the waiting tour application first */

            /*prepare reply to the API */
            memset(&arp_reply_to_api, 0, sizeof(struct arp_request_data));

            arp_reply_to_api.ip_addr.sin_addr = rcvd_arp_frame.msg.sender_ip_addr;
            memcpy(arp_reply_to_api.hw_addr.sll_addr, rcvd_arp_frame.header.eth_src_addr, 6);
            arp_reply_to_api.hw_addr.sll_halen = ETH_ALEN;
            arp_reply_to_api.hw_addr.sll_hatype = ARPHRD_ETHER;
            arp_reply_to_api.hw_addr.sll_ifindex = remote_arp_sock_addr.sll_ifindex;

            /*send reply to the API */
            if(write(available_arp_cache_entry->client_domain_sock_fd, &arp_reply_to_api, sizeof(struct arp_request_data)) < 0)
            {
                unlink(ARP_SUN_PATH);
                fprintf(stderr, "Error while writing back to API:%s\n", strerror(errno));
                exit(1);
            }

            fprintf(stdout, "Incomplete cache entry for IP address got completed, replying to API\n", inet_ntoa(rcvd_arp_frame.msg.sender_ip_addr));

            close(available_arp_cache_entry->client_domain_sock_fd);
            available_arp_cache_entry->client_domain_sock_fd = -1;
        }
        /* update if_index and ethernet addresss */
        available_arp_cache_entry->ifindex = remote_arp_sock_addr.sll_ifindex;
        memcpy(available_arp_cache_entry->hw_addr, rcvd_arp_frame.header.eth_src_addr, 6);
    }
    else
    {
        /* if the host is destination, create one entry, else ignore */
        if(is_host_destination == 1)
        {

            fprintf(stdout, "Creating a new complete entry for IP address: %s\n", inet_ntoa(rcvd_arp_frame.msg.sender_ip_addr));

            /* create a new ARP cache entry corresponding to sender */
            add_arp_cache_entry(rcvd_arp_frame.msg.sender_ip_addr, -1, remote_arp_sock_addr.sll_ifindex, rcvd_arp_frame.header.eth_src_addr);

            /* send reply to sender of the request*/
            new_arp_frame = prepare_arp_frame(rcvd_arp_frame.header.eth_src_addr, host_primary_hwa_info->if_haddr, ARPOP_REPLY, host_sock_addr->sin_addr, rcvd_arp_frame.msg.sender_ip_addr, PACKET_OTHERHOST);

            send_arp_frame(pf_sock_fd, new_arp_frame, PACKET_OTHERHOST);
        }
    }
}
/****************************************** end of process_rcvd_arp_req_frame function ******************************************/

/****************************************** start of process_rcvd_arp_rep_frame function ******************************************/
void process_rcvd_arp_rep_frame(int pf_sock_fd, struct sockaddr_ll remote_arp_sock_addr, struct arp_frame rcvd_arp_frame)
{
    struct arp_cache_entry *incomplete_cache_entry;
    struct arp_request_data arp_reply_to_api;
    /* check if received frame belongs to this modules ID*/
    if(rcvd_arp_frame.msg.arp_msg_id != ARP_MSG_ID)
    {
        return;
    }

    incomplete_cache_entry = get_arp_cache_entry(rcvd_arp_frame.msg.sender_ip_addr);
    if(incomplete_cache_entry != NULL)
    {
        /* if entry is incomplete, API is still waiting; reply */
        if((incomplete_cache_entry->client_domain_sock_fd != -1) && (strncmp(incomplete_cache_entry->hw_addr, incomplete_eth_addr, 6) == 0))
        {
            /* prepare ARP reply */
            memset(&arp_reply_to_api, 0, sizeof(struct arp_request_data));
            arp_reply_to_api.ip_addr.sin_addr = rcvd_arp_frame.msg.sender_ip_addr;
            arp_reply_to_api.hw_addr.sll_halen = ETH_ALEN;
            arp_reply_to_api.hw_addr.sll_hatype = ARPHRD_ETHER;
            arp_reply_to_api.hw_addr.sll_ifindex = remote_arp_sock_addr.sll_ifindex;
            memcpy(arp_reply_to_api.hw_addr.sll_addr, rcvd_arp_frame.header.eth_src_addr, 6);

            /*send ARP reply to the API */
            if(write(incomplete_cache_entry->client_domain_sock_fd, &arp_reply_to_api, sizeof(struct arp_request_data)) < 0)
            {
                unlink(ARP_SUN_PATH);
                fprintf(stdout, "Error while writing back to API: %s\n", strerror(errno));
                exit(1);
            }

            fprintf(stdout, "Incomplete cache entry for IP address: %s got completed replying to API\n",inet_ntoa(rcvd_arp_frame.msg.sender_ip_addr) );

            close(incomplete_cache_entry->client_domain_sock_fd);

            incomplete_cache_entry->client_domain_sock_fd = -1;
            memcpy(incomplete_cache_entry->hw_addr, rcvd_arp_frame.header.eth_src_addr, 6);
        }
    }
    else
    {
        /* API already timed out; no need to process this reply anymore, ingore it */
        fprintf(stdout, "Recieved reply, but API closed connection, ignoring it");
    }

}
/****************************************** end of process_rcvd_arp_rep_frame function ******************************************/
