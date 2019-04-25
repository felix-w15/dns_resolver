#ifndef PKG_PRO_H__
#define PKG_PRO_H__

#include<winsock2.h>
#include<string>

#include"sqlite3.h"

#define IDTABLE_SIZE 256

#define BUFFER_SIZE 1024
#define QNAME_MAX_LENTH 256
#define SUPERIOR_SERVER_ADDRESS 10.3.9.6

using namespace std;

typedef struct
{
	unsigned short ID;
	unsigned short FLAGS;
	unsigned short QDCOUNT;
	unsigned short ANCOUNT;
	unsigned short NSCOUNT;
	unsigned short ARCOUNT;
} dns_header;

//********************************
extern int it_length;//当前存入的ID数目
extern int last;//接受数据的长度
extern short int old_id_table[IDTABLE_SIZE];//原始ID表
extern short int new_id_table[IDTABLE_SIZE];//更改后的ID表
extern SOCKADDR_IN client_ip[IDTABLE_SIZE];//存放客户机的ip地址，用以发答复包以及并发处理
//******************************

extern SOCKET serverSocket;

void init_table(short int t[], short int q);//数组初始化

void query_pro(dns_header *header, char *receiveBuffer, SOCKADDR_IN cli_ip);//请求包处理

void query_for_superior_server(char *receiveBuffer);//转发至高一级域名服务器

void resp_pro(dns_header *header, char *receiveBuffer);//响应包处理

void query_record(sqlite3 *db, char *zErrMsg, string domainName);

void query_cnamerecord(sqlite3 *db, char *zErrMsg, string domainName);

void query_mxrecord(sqlite3 *db, char *zErrMsg, string domainName);

void query_nsrecord(sqlite3 *db, char *zErrMsg, string domainName);

//*******************************************************
int do_name_reso(int clength, int addlength, int c_byte, char doname[], char *receiveBuffer);//域名解析
//********************************************************



#endif // PKG_PRO_H__

