#include "main.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"

#include "protocol_structure.h"

// 下面是一些网络编程的参数API
#define SERVER_IP "192.168.50.10"
#define SERVER_PORT 8889
// 发送网络消息到目标位置
#define HEADER_LEN 8
#define DATA_LEN 3064
#define MAX_LINE_BUFFER 4096

int main() {

    printf("client start!\n");

    // how to write the code here? tmply unknown.

    // 首先要连接服务器,现在先暂时写死，后面再做修改



    int sockfd, num;    /* files descriptors */
    char buf[MAX_LINE_BUFFER];    /* buf will store received text */
    struct protocol_header* tmp_header = NULL;
    struct sockaddr_in server;
 
 
    if((sockfd=socket(AF_INET,SOCK_STREAM, 0))==-1)
    {
        printf("socket() error\n");
        exit(1);
    }
    // set the space to zero
    bzero(&server,sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(SERVER_PORT);
    server.sin_addr.s_addr = inet_addr(SERVER_IP);

    // 下面正式访问对应的IP地址
    if(connect(sockfd, (struct sockaddr *)&server, sizeof(server))==-1)
    {
        printf("connect() error\n");
        exit(1);
    }
    
    tmp_header = (struct protocol_header*) buf;
    tmp_header->sig_pro = 1;

    char* data_point = (char*)(buf + HEADER_LEN);
    strcpy(data_point, "Hello Server! I am Client!");
    tmp_header->length = strlen(data_point); // 存入对应的信息即可得部分结果


    if((num=send(sockfd,buf,HEADER_LEN + tmp_header->length, 0)==-1)){
        printf("send() error\n");
        exit(1);
    }
    if((num=recv(sockfd,buf,MAX_LINE_BUFFER,0))==-1)
    {
        printf("recv() error\n");
        exit(1);
    }
    buf[num-1]='\0';
    printf("server message: %s\n",buf);
    close(sockfd);

    while(1) {

    };
    return 0;
}