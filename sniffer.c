#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(){
    printf("Packet Sniffer Started\n");

    int sockfd;

    sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_IP);

    if(sockfd < 0){
        perror("Socket Creation Failed");
        return 1;
    }
    

    return 0;
}


