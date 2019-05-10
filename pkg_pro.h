#ifndef PKG_PRO_H__
#define PKG_PRO_H__

#include<winsock2.h>
#include<string>
#include<iostream>
#include<map>
#include<sstream>
#include<time.h>

#include"sqlite3.h"

#define IDTABLE_SIZE 256

#define BUFFER_SIZE 1024
#define QNAME_MAX_LENTH 256
#define SUPERIOR_SERVER_ADDRESS "10.3.9.5"
#define SQL_MAX 4096
#define RESO_MAX 1024 //资源最多记录数不超过1024
#define DOMAIN_LEN_MAX 256//域名最长长度


using namespace std;


//dns包头结构
/*-------------------------------------*/
/*                  ID                 */
/*-------------------------------------*/
/*                 FLAGS               */
/*-------------------------------------*/
/*                QDCOUNT              */
/*-------------------------------------*/
/*                ANCOUNT              */
/*-------------------------------------*/
/*                NSCOUNT              */
/*-------------------------------------*/
/*                ARCOUNT              */
/*-------------------------------------*/


typedef struct
{
	unsigned short ID;
	unsigned short FLAGS;
	unsigned short QDCOUNT;
	unsigned short ANCOUNT;
	unsigned short NSCOUNT;
	unsigned short ARCOUNT;
} dns_header;

//dns资源记录结构
/*-------------------------------------*/
/*                NAME                 */
/*-------------------------------------*/
/*                TYPE                 */
/*-------------------------------------*/
/*                CLASS                */
/*-------------------------------------*/
/*                TTL                  */
/*                                     */
/*-------------------------------------*/
/*               RDLENGTH              */
/*-------------------------------------*/
/*                RDATA                */
/*-------------------------------------*/


//dns资源记录结构
typedef struct 
{
	char *NAME;//资源记录匹配的域名
	unsigned short TYPE;//资源类型
	unsigned short CLASS;//规定RDATA数据类
	unsigned long TTL;//生存时间
	unsigned short DATALENGTH;//RDATA字段长度
	char *RDATA;//资源
	unsigned short PREFERENCE;//MX记录优先级
} resRecord;

extern int it_length;//当前存入的ID数目
extern int last;//接受数据的长度
extern long timestamp[IDTABLE_SIZE];//存放向上级请求包发出时间
extern SOCKADDR_IN client_ip[IDTABLE_SIZE];//存放客户机的ip地址，用以发答复包以及并发处理
extern short int old_id_table[IDTABLE_SIZE];//原始ID表
extern short int new_id_table[IDTABLE_SIZE];//更改后的ID表，按ID从小到大的顺序存储
extern sqlite3 *db;//sqlite3数据库初始化信息
extern map<string, unsigned short> *mapDomainName;

extern SOCKET serverSocket;

void init_table(short int t[], short int q);//数组初始化
void query_pro(dns_header *header, char *receiveBuffer, SOCKADDR_IN cli_ip);//请求包处理
void query_for_superior_server(char *receiveBuffer, dns_header *header, SOCKADDR_IN cli_ip);//转发至高一级域名服务器
void resp_pro(dns_header *header, char *receiveBuffer);//响应包处理
void connect_string(char *a, char *b);
void connect_const_string(char *a, const char *b);

int query_A_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, resRecord *records);
int query_A_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, const char *Address, int addLength);
void insert_A_record(sqlite3 *db, char *zErrMsg, char *Name, char *Alias, char *Type, char *Class, int TTL, int DataLength,const char *Address, int *length);

void insert_CNAME_record(sqlite3 *db, char *zErrMsg, char *Name, char *Alias, char *Type, char *Class, int TTL, int DataLength, char *CNAME, int *length);
int query_CNAME_record(sqlite3 *db, char *zErrMsg, char *Alias, int nameLength, resRecord *record);//查询特定权威名记录
int query_CNAME_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, char *CNAME, int CNLength);

void connect_string(char *a, const char *b, int aLength, int bLength);//连接字符串
void connect_string(char *a, char *b, int aLength, int bLength);//连接字符串

string translate_IP(unsigned char* ip);
void insert_IP(char *ip, char *sendBuf, int *bytePos);//将ip存入发送缓冲区

int do_name_reso(int clength, int addlength, int c_byte, char doname[], char *receiveBuffer);//域名解析

void a_records_pro(resRecord *records, int len, char *sendBuf, int *bytePos);//a类型记录处理
void cn_records_pro(resRecord record, char *sendBuf, int *bytePos);//cname类型记录处理
void cn_records_pro(resRecord record, char *sendBuf, int *bytePos, int len);//cn_records_pro重载，只执行一次
void domain_pro(char* name, char *sendBuf, int *bytePos);//域名处理
void domainStore(char *domain, int len, int iniBytePos, string res);//将域名部分存入字典中

void insert_NS_record(sqlite3 *db, char *zErrMsg, char *Name, char *Alias, char *Type, char *Class, int TTL, int DataLength, char *NS, int *length);//插入NS类型记录
void insert_MX_record(sqlite3 *db, char *zErrMsg, char *Name, char *Alias, char *Type, char *Class, int TTL, int DataLength, int Preference, char *MX, int *length);//插入MX类型记录

int query_MX_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, resRecord *records);
int query_MX_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, char *mName, int mNameLen);
int query_NS_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, char *NAME_SERVER, int nameServerLen);//查询NS记录
int query_NS_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, resRecord *records);//查询NS记录的重载

void ns_records_pro(resRecord *records, int len, char *sendBuf, int *bytePos);
void mx_records_pro(resRecord *records, int len, char *sendBuf, int *bytePos);
#endif // PKG_PRO_H__

