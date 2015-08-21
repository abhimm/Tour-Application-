#include "abhmishra_api.h"
int areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr)
{
    struct arp_request_data arp_req_to_arp;
    struct arp_request_data arp_rep_from_arp;
    struct sockaddr_in *dest_sock_addr;
    struct sockaddr_un arp_sock_addr;
    int domain_sock_fd, select_result, read_result;
    fd_set rset;
    struct timeval wait_time;
    char *prnt_dest_mac;
    int i,j;

    /* prepare ARP request */
    memset(&arp_req_to_arp, 0, sizeof(struct arp_request_data));

    dest_sock_addr = (struct sockaddr_in*)IPaddr;
    memcpy(&arp_req_to_arp.ip_addr, dest_sock_addr, sizeof(struct sockaddr_in));

    /* create domain socket */
    if((domain_sock_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
    {
        fprintf(stderr, "Error while creating unix domain socket in API: %s\n", strerror(errno));
        return -1;
    }

    /* prepare socket address to connect */
    memset(&arp_sock_addr, 0, sizeof(struct sockaddr_un));
    arp_sock_addr.sun_family = AF_UNIX;
    strcpy(arp_sock_addr.sun_path, ARP_SUN_PATH);

    /* connect the socket */
    if(connect(domain_sock_fd, (struct sockaddr*)&arp_sock_addr, sizeof(struct sockaddr_un)) == -1)
    {
        fprintf(stderr, "Error while connencting the unix domain socket to ARP in API: %s\n", strerror(errno));
        return -1;
    }

    /* send request to ARP */
    if(write(domain_sock_fd, &arp_req_to_arp, sizeof(struct arp_request_data)) == -1)
    {
        fprintf(stderr, "Error while writing ARP request on unix domain socket in API:%s\n", strerror(errno));
        close(domain_sock_fd);
        return -1;
    }
    /* print sent ARP request */
    fprintf(stdout, "Sending ARP request for IP address: %s\n", inet_ntoa(dest_sock_addr->sin_addr));


    /* wait for reply from ARP */

    while(1)
    {
        FD_ZERO(&rset);
        FD_SET(domain_sock_fd, &rset);
        select_result = 0;
        wait_time.tv_sec = 10;
        wait_time.tv_usec = 0;
        select_result = select(domain_sock_fd + 1, &rset, NULL, NULL, &wait_time);

        if(select_result < 0)
        {
            if(errno == EINTR)
                continue;
            fprintf(stderr, "Error in select in API: %s\n", strerror(errno));
            close(domain_sock_fd);
            fprintf(stderr, "Destination hardware address not obtained for IP address:%s\n", inet_ntoa(dest_sock_addr->sin_addr));
            return -1;
        }
        else if( select_result == 0)
        {
            fprintf(stdout, "Wait time expired; no response from ARP\n");
            close(domain_sock_fd);
            fprintf(stderr, "Destination hardware address not obtained for IP address:%s\n", inet_ntoa(dest_sock_addr->sin_addr));
            return -1;
        }
        else
        {
            memset(&arp_rep_from_arp, 0, sizeof(struct arp_request_data));
            read_result = read(domain_sock_fd, &arp_rep_from_arp, sizeof(struct arp_request_data));

            if(read_result == -1)
            {
                fprintf(stderr, "Error while reading reply from ARP: %s\n", strerror(errno));
                close(domain_sock_fd);
                fprintf(stderr, "Destination hardware address not obtained for IP address:%s\n", inet_ntoa(dest_sock_addr->sin_addr));
                return read_result;
            }

            HWaddr->sll_halen = arp_rep_from_arp.hw_addr.sll_halen;
            HWaddr->sll_halen = arp_rep_from_arp.hw_addr.sll_hatype;
            HWaddr->sll_ifindex = arp_rep_from_arp.hw_addr.sll_ifindex;
            memcpy(HWaddr->sll_addr, arp_rep_from_arp.hw_addr.sll_addr, 6);

            prnt_dest_mac = malloc(19);
            memset(prnt_dest_mac, 0, 19);
            for(i = 0, j = 0; i < 6; i++, j = j+3)
            {
                sprintf((char*)(prnt_dest_mac + j), (i != 5)? "%02x:" : "%02x", arp_rep_from_arp.hw_addr.sll_addr[i] & 0xff);
            }

            fprintf(stderr, "Destination hardware address:%s successfully obtained for IP address:%s\n", prnt_dest_mac, inet_ntoa(dest_sock_addr->sin_addr));
            return read_result;
        }
    }
}
