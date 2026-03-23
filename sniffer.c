#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

char* get_protocol_name(int protocol){
    switch(protocol){
        case 1:
            return "ICMP";
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        default:
            return "OTHER";
    }
}

int get_protocol_number(char *name){
    if(strcmp(name , "tcp") == 0) return 6;
    if(strcmp(name, "udp") == 0) return 17;
    if(strcmp(name, "icmp") == 0) return 1;
    if(strcmp(name, "all") == 0) return -1;
    return -2; // invalid 
}

int main(int argc, char * argv[]){

    int filter_protocol = -1;
    if(argc == 3 && strcmp(argv[1], "--protocol") == 0){
        filter_protocol = get_protocol_number(argv[2]);

        if(filter_protocol == -2){
            printf("Invalid protocol. Use tcp/udp/icmp/all\n");
        }
    }

    long packet_count = 0;

    printf("Packet Sniffer Started\n");

    int sockfd;

    sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);

    if(sockfd < 0){
        perror("Socket Creation Failed");
        return 1;
    }

    printf("Raw Socket Created\n");

    char buffer[65536];

    while(1){
        packet_count++;
        int data_size;
        data_size = recvfrom(sockfd,buffer,sizeof(buffer),0,NULL,NULL);
        if(data_size < 0){
        perror("RecvFrom error");
        return 1;
        }

        // printf("Packet Received: %d bytes\n",data_size);

        struct iphdr *ip = (struct iphdr*) buffer;
        struct sockaddr_in src,dest;

        if(filter_protocol != -1 && ip->protocol != filter_protocol){
            continue;
        }

        src.sin_addr.s_addr = ip->saddr;
        dest.sin_addr.s_addr = ip->daddr;

        int ip_header_len = ip->ihl * 4;
        char *payload = buffer + ip_header_len;

        int payload_size = data_size - ip_header_len;

        // get current time
        time_t now;
        struct tm *local_time;

        time(&now);
        local_time = localtime(&now);

        char time_str[20];
        strftime(time_str,sizeof(time_str), "%H:%M:%S", local_time);

        // better logging
        printf("[%s] %s | %s -> %s | TTL=%d | Len=%d | Count=%ld\n",
        time_str,get_protocol_name(ip->protocol),
        inet_ntoa(src.sin_addr),
        inet_ntoa(dest.sin_addr),
        ip->ttl,
        ntohs(ip->tot_len),
        packet_count);
        
        // printf("\nPacket Captured\n");
        // printf("\n");
        // printf("Source Ip : %s\n", inet_ntoa(src.sin_addr));
        // printf("Destination Ip : %s\n", inet_ntoa(dest.sin_addr));
        // printf("Protocol : %s\n", get_protocol_name(ip->protocol));
        // printf("TTL : %d\n", ip->ttl);
        // printf("Total Length : %d\n" , ntohs(ip->tot_len));
        // printf("Payload Size : %d\n", payload_size);
        // printf("Payload Data : ");
        for(int i = 0;i<payload_size && i < 20;i++){
            printf("%02X " , (unsigned char)payload[i]);
        }
        printf("\n");
    }

    return 0;
}


