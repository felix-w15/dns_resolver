#include<stdlib.h>
#include<stdio.h>
#include<winsock2.h>


#include"pkg_pro.h"

#pragma comment(lib,"ws2_32.lib")

int it_length = 0;//当前存入的ID数目
int last;//接受数据的长度
short int old_id_table[IDTABLE_SIZE];//原始ID表
short int new_id_table[IDTABLE_SIZE];//更改后的ID表

SOCKET serverSocket;

int main() {
	WSADATA WSAData;//windows socket初始化信息
	char receiveBuffer[BUFFER_SIZE];

	//*********************************
	init_table(old_id_table, -1);//初始化原始ID表
	init_table(new_id_table, -1);//初始化更改后的ID表
	//*********************************

	if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0)
	{
		printf("fail to initialize\n");
		exit(0);
	}

	serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (serverSocket == INVALID_SOCKET)
	{
		printf("fail to create socket\n");
		exit(0);
	}

	SOCKADDR_IN serverAddress; //服务器的地址等信息
	serverAddress.sin_family = AF_INET;
	serverAddress.sin_port = htons(53);
	serverAddress.sin_addr.S_un.S_addr = INADDR_ANY;
	if (bind(serverSocket, (SOCKADDR*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR)
	{//服务器与本地地址绑定
		printf("Failed socket() %d \n", WSAGetLastError());
		return 0;
	}

	SOCKADDR_IN addr_Clt;

	int fromlen = sizeof(SOCKADDR);
	while (1)
	{
		last = recvfrom(serverSocket, receiveBuffer, BUFFER_SIZE, 0, (SOCKADDR*)&addr_Clt, &fromlen);
		if (last > 0)
		{      //判断接收到的数据是否为空
			receiveBuffer[last] = '\0';//给字符数组加一个'\0'，表示结束了。不然输出有乱码
			if (strcmp(receiveBuffer, "bye") == 0)
			{
				printf("客户端不跟我聊天了...");
				closesocket(serverSocket);
				return 0;
			}
			else
			{
				//printf("接收到数据（%s）：%s\n", inet_ntoa(addr_Clt.sin_addr), receBuf);
				//printf("接收到数据（%s）\n", inet_ntoa(addr_Clt.sin_addr));				
	/*			for (int i = 0; i < last; i++)
				{
					printf("%c ", receiveBuffer[i]);
				}
*/
//创建header
				dns_header *header;
				header = (dns_header *)receiveBuffer;
				header->ID = ntohs(header->ID);
				header->FLAGS = ntohs(header->FLAGS);
				header->QDCOUNT = ntohs(header->QDCOUNT);
				header->ANCOUNT = ntohs(header->ANCOUNT);
				header->NSCOUNT = ntohs(header->NSCOUNT);
				header->ARCOUNT = ntohs(header->ARCOUNT);

				//			printf("\n-----ID:%d FLAGS:%d qcount:%d------\n%d\n", header->ID, header->FLAGS, header->QDCOUNT,last);


				if ((header->FLAGS & 0x8000) == 0x8000)//为响应包
				{
					printf("\n\n-------Response Package-------\n");
					resp_pro(header, receiveBuffer);
				}
				else//请求包
				{
					printf("\n\n-------Query Package-------\n");
					query_pro(header, receiveBuffer, addr_Clt);//请求处理
				}


			}
		}
		//cout << "回复客户端消息:";
		//cin >> Response; //给客户端回复消息
		//sendto(sockServer, Response, strlen(Response), 0, (SOCKADDR*)&addr_Clt, sizeof(SOCKADDR));
	}

	closesocket(serverSocket);

	WSACleanup();
	return 0;
}

