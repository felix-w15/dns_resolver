#include<stdlib.h>
#include<stdio.h>

#include"pkg_pro.h"



SOCKADDR_IN client_ip[IDTABLE_SIZE];//存放客户机的ip地址，用以发答复包以及并发处理



static int callback(void *NotUsed, int argc, char **argv, char **azColName) {
	int i;
	for (i = 0; i < argc; i++)
	{
		printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	}
	printf("\n");
	return 0;
}

int str_len(char *str)
{
	int i = 0;
	while (str[i])
	{
		i++;
	}
	return i;
}

string translate_IP(unsigned char* ip)//把以unsigned char类型存储的ip地址转换成字符串
{
	string result = "";
	for (int i = 0; i < 4; i++)
	{
		result = result + to_string(ip[i]) + ".";
	}
	return result.substr(0, result.length() - 1);
}

void init_table(short int t[], short int q)
{
	for (int i = 0; i < IDTABLE_SIZE; i++)
	{
		t[i] = q;
	}
}

void query_for_superior_server(char *receiveBuffer, dns_header *header, SOCKADDR_IN cli_ip)
{
	//转换DNS数据包头ID,存客户机ip地址
	int k = 0;//判断是否有相同ID
	short int hid = header->ID;
	short int nhid;//更改后的ID
	for (int i = 0; i < it_length; i++)
	{
		if (hid == new_id_table[i]) {
			k = 1;
			break;
		}
	}
	if (k == 0) {//没有相同的ID
		nhid = hid;//不用更改ID
		int i = 0;
		for (i = 0; i < it_length; i++)
		{
			if (nhid < new_id_table[i]) {//将新ID插入更改后的表
				for (int j = it_length; j > i; j--)
				{//后移
					new_id_table[j] = new_id_table[j - 1];
					old_id_table[j] = old_id_table[j - 1];
					client_ip[j] = client_ip[j - 1];
				}
				old_id_table[i] = hid;
				new_id_table[i] = nhid;
				client_ip[i] = cli_ip;
				it_length++;
				break;
			}
		}
		if (i == it_length)
		{//若新表中所有ID都小于此ID
			old_id_table[i] = hid;
			new_id_table[it_length] = nhid;
			client_ip[i] = cli_ip;
			it_length++;
		}
	}
	else
	{//有相同的id
		nhid = 0;//从0开始构造ID
		int i = 0;
		for (int i = 0; i < it_length; i++)
		{
			if (nhid == new_id_table[i])  nhid++;//构造的ID已被使用
			else {//构造的ID未被使用，由于是有序的，故直接在此插入
				for (int j = it_length; j > i; j--)
				{//后移
					new_id_table[j] = new_id_table[j - 1];
					old_id_table[j] = old_id_table[j - 1];
					client_ip[j] = client_ip[j - 1];
				}
				old_id_table[i] = hid;
				new_id_table[i] = nhid;
				client_ip[i] = cli_ip;
				it_length++;
				break;
			}
		}
		if (i == it_length)
		{//若新表中所有ID都小于此ID
			old_id_table[i] = hid;
			new_id_table[it_length] = nhid;
			client_ip[i] = cli_ip;
			it_length++;
		}
	}
	header->ID = nhid;//将新ID字段赋给包头

	//将收到header中字节序改为网络字节序
	header->ID = htons(header->ID);
	header->FLAGS = htons(header->FLAGS);
	header->QDCOUNT = htons(header->QDCOUNT);
	header->ANCOUNT = htons(header->ANCOUNT);
	header->NSCOUNT = htons(header->NSCOUNT);
	header->ARCOUNT = htons(header->ARCOUNT);

	SOCKADDR_IN to_address;
	int addr_len = sizeof(SOCKADDR_IN);
	to_address.sin_family = AF_INET;
	to_address.sin_port = htons(53);
	to_address.sin_addr.S_un.S_addr = inet_addr(SUPERIOR_SERVER_ADDRESS);
	if (sendto(serverSocket, receiveBuffer, last, 0, (const struct sockaddr *)&to_address, addr_len))
	{
		printf("转发至上一级域名服务器成功！\n");
	}
	else
	{
		printf("转发至上一级域名服务器失败！\n");
	}
}

void query_pro(dns_header *header, char *receiveBuffer, SOCKADDR_IN cli_ip)
{
	char *question_sec = receiveBuffer + sizeof(dns_header);
	char QNAME[QNAME_MAX_LENTH + 1];
	int index = 0, now_pos = 0;
	while (question_sec[index] != 0x00)//提取域名
	{
		int temp = question_sec[index], i;
		for (i = 0; i < temp; i++)
		{
			QNAME[i + now_pos] = question_sec[index + i + 1];
		}
		index += temp + 1;
		now_pos += temp;
		if (question_sec[index] != 0x00)
			QNAME[now_pos++] = '.';
	}
	QNAME[now_pos] = '\0';
	//	printf("%s\n", QNAME);
	
	/*判断本地数据库是否存有该域名记录*/
	char doName[QNAME_MAX_LENTH];//查询域名或邮件地址后缀名
	int length = 0;//域名或邮件地址后缀名占用的字节数
	int c_byte = sizeof(dns_header);//当前拆分到的字节位置
	unsigned short *type;//查询类型

	length = do_name_reso(0, 0, c_byte, doName, receiveBuffer);//解析域名或邮件地址后缀名
	c_byte += length;
	type = (unsigned short*)(receiveBuffer + c_byte);
	c_byte += 2;

	int tp = ntohs(*type);
	printf("请求查询类型: %d\n",tp);

	int doNameLen = str_len(doName);


	char *zErrMsg = 0;
	if(tp == 1)//为A类型查询请求
	{
		int queryResult = query_A_record(db, zErrMsg, doName, doNameLen);
		if (queryResult)//本地数据库有缓存,给客户端发送response包
		{
			printf("本地存有%s域名的A类型记录!\n\n", doName);
		}
		else
		{
			query_for_superior_server(receiveBuffer, header, cli_ip);//向高一级域名服务器发送查询
		}
		return;
	}
	//else if (*type == 5)//为CNAME类型查询请求
	//{

	//}

	//如果都没有记录则向高一级域名服务器查询
	query_for_superior_server(receiveBuffer, header, cli_ip);//向高一级域名服务器发送查询
}

void resp_pro(dns_header *header, char *receiveBuffer)
{
	//还原DNS数据包头ID
	SOCKADDR_IN q_ip;//此包应回复给的客户机ip
	short int hid = header->ID;
	short int rehid;//还原后后的ID
	int i = 0;
	for (i = 0; i < it_length; i++)
	{//找到ID在新表中对应的下标
		if (hid == new_id_table[i])  break;
	}
	rehid = old_id_table[i];//取原始ID
	q_ip = client_ip[i];

	for (int j = i; j < it_length - 1; j++)
	{//删除此ID数据，后面ID数据前移
		old_id_table[i] = old_id_table[i + 1];
		new_id_table[i] = new_id_table[i + 1];
		client_ip[i] = client_ip[i + 1];
	}
	it_length--;//长度减1
	header->ID = rehid;//还原ID

	//取应答内容，插入数据库

	//取AA
	if ((header->FLAGS & 0x0400) == 0x0400) {//答案来授权域名解析服务器（在此为本地服务器）
		printf("答案来自本地服务器\n");
	}
	else {
		printf("答案来自上级服务器\n");
	}

	//判断RCODE
	if ((header->FLAGS & 0x000F) == 0x0003) {//RCODE为3表示域名出错
		printf("未查询到此域名\n\n");
	}
	else {//解析响应包
		printf("\n");
		//判断请求个数和资源记录个数
		int ques = header->QDCOUNT;//query字段个数
		int requ = header->ANCOUNT;//anwser字段个数
		int aure = header->NSCOUNT;//authority字段个数
		int adre = header->ARCOUNT;//additional字段个数
		int reso = requ + aure + adre;//总的资源记录个数

		int c_byte = sizeof(dns_header);//当前拆分到的字节位置
//		printf("请求和资源记录个数%d   %d\n", ques, reso);
		//拆分Question Section部分

		
		char doName[QNAME_MAX_LENTH];//查询域名或邮件地址后缀名

		for (int i = 0; i < ques; i++)
		{
			if (i == 0)  printf("Question Section（%d个）：\n\n", ques);

			
			int length = 0;//域名或邮件地址后缀名占用的字节数
			unsigned short *type;//查询类型
			unsigned short *Class;//查询类


			length = do_name_reso(0, 0, c_byte, doName, receiveBuffer);//解析域名或邮件地址后缀名
			c_byte += length;
			type = (unsigned short*)(receiveBuffer + c_byte);
			c_byte += 2;
			Class = (unsigned short*)(receiveBuffer + c_byte);
			c_byte += 2;

			*type = ntohs(*type);
			*Class = ntohs(*Class);
			printf("    qname：%s\n", doName);
			printf("    qtype：%d\n", *type);
			printf("    qclass：%d\n\n", *Class);
			*type = htons(*type);
			*Class = htons(*Class);
		}

		//拆分后三段资源记录部分，因为格式相同，故同时解析
		for (int i = 0; i < reso; i++)
		{
			if (i == 0)  printf("Anwser Section（%d个）：\n\n", requ);
			if (i == requ)  printf("Authority Records Section（%d个）：\n\n", aure);
			if (i == requ + aure)  printf("Additional Records Section（%d个）：\n\n", adre);

			char doname[QNAME_MAX_LENTH];//域名或邮件地址后缀名
			int length = 0;//域名或邮件地址后缀名占用的字节数
			unsigned short *type;//查询类型
			unsigned short *Class;//查询类
			unsigned long *ttl;//生存时间
			unsigned short *relength;//资源数据长度

			length = do_name_reso(0, 0, c_byte, doname, receiveBuffer);//解析域名或邮件地址后缀名
			//printf("域名长度%d\n", *relength);
			c_byte += length;
			type = (unsigned short*)(receiveBuffer + c_byte);
			c_byte += 2;
			Class = (unsigned short*)(receiveBuffer + c_byte);
			c_byte += 2;
			ttl = (unsigned long*)(receiveBuffer + c_byte);
			c_byte += 4;
			relength = (unsigned short*)(receiveBuffer + c_byte);
			c_byte += 2;

			*type = ntohs(*type);
			*Class = ntohs(*Class);
			*ttl = ntohl(*ttl);
			*relength = ntohs(*relength);
			printf("    name：%s\n", doname);
			printf("    type：%d\n", *type);
			printf("    class：%d\n", *Class);
			printf("    time to live：%ld\n", *ttl);
			//printf("    dataLenth: %d\n", *relength);

			char storeData[BUFFER_SIZE];
			char *zErrMsg = 0;

			int TTL = (int)*ttl;
			int ttlLen = (std::to_string(TTL)).length();
			int doNameLen = str_len(doName);
			int aliasLen = str_len(doname);
			int lenth[7];//各项资源长度数据	

			lenth[0] = doNameLen;//域名长度
			lenth[1] = aliasLen;//别名长度
			lenth[3] = 2;//class长度
			lenth[4] = ttlLen;

			printf("    dataLenth: %d\n", doNameLen);
			printf("    TTL:%d\n", TTL);
			if (*type == 1)
			{//IP地址类型
				unsigned char ip_address[4];
				storeData[0] = 'A';
				storeData[1] = 'I';
				storeData[2] = 'N';
				storeData[4] = ip_address[0] = receiveBuffer[c_byte];
				storeData[5] = ip_address[1] = receiveBuffer[c_byte + 1];
				storeData[6] = ip_address[2] = receiveBuffer[c_byte + 2];
				storeData[7] = ip_address[3] = receiveBuffer[c_byte + 3];
				storeData[8] = '\0';
				printf("    ip：%d.%d.%d.%d\n\n", ip_address[0], ip_address[1], ip_address[2], ip_address[3]);
				
				string ip = translate_IP(ip_address);	
				int ipLen = ip.length();//ip地址长度
				lenth[2] = 1;//type长度
				lenth[5] = 1;//DataLength字段长度
				lenth[6] = ipLen;
				const char *ipRes = ip.data();

				if(!query_A_record(db, zErrMsg,  doName, doNameLen, ipRes, ipLen))
				    insert_A_record(db, zErrMsg, doName, doname, storeData, storeData + 1, TTL, 4, ipRes, lenth);
			}
			else if (*type == 2)
			{//NS类型
				char dname[QNAME_MAX_LENTH];//存储域名服务器的名字
				length = do_name_reso(0, 0, c_byte, dname, receiveBuffer);//解析域名服务器的名字
				printf("    name server：%s\n\n", dname);
			}
			else if (*type == 5)
			{//CNAME类型
				lenth[2] = 2;//type数据长度为2
				storeData[0] = 'C';//CN类型
				storeData[1] = 'N';
				storeData[2] = 'I';//INclass
				storeData[3] = 'N';

				char cname[QNAME_MAX_LENTH];//存储规范名
				length = do_name_reso(0, 0, c_byte, cname, receiveBuffer);//解析规范名
				lenth[5] = (std::to_string(length)).length();
				lenth[6] = str_len(cname);
				if(!query_CNAME_record(db, zErrMsg, doName, doNameLen, cname, lenth[6]))//如果数据库中无该CN记录则存储
				  insert_CNAME_record(db, zErrMsg, doName, doname, storeData, storeData + 2, TTL, length, cname, lenth);
				printf("    cname：%s\n\n", cname);
			}
			else if (*type == 15)
			{//MX类型
				char mname[QNAME_MAX_LENTH];//存储邮件服务器名
				unsigned short *preference;//邮件服务器的优先级
				preference = (unsigned short*)(receiveBuffer + c_byte);
				length = do_name_reso(0, 0, c_byte + 2, mname, receiveBuffer);//解析邮件服务器名
				*preference = ntohs(*preference);
				printf("    preference：%d\n", *preference);
				printf("    mail exchange：%s\n\n", mname);
				*preference = htons(*preference);
			}
			c_byte += *relength;

			*type = htons(*type);
			*Class = htons(*Class);
			*ttl = htonl(*ttl);
			*relength = htons(*relength);
		}
	}

	header->ID = htons(header->ID);
	header->FLAGS = htons(header->FLAGS);
	header->QDCOUNT = htons(header->QDCOUNT);
	header->ANCOUNT = htons(header->ANCOUNT);
	header->NSCOUNT = htons(header->NSCOUNT);
	header->ARCOUNT = htons(header->ARCOUNT);

	//转发给客户机
	sendto(serverSocket, receiveBuffer, last, 0, (SOCKADDR*)&q_ip, sizeof(SOCKADDR));
}

int do_name_reso(int clength, int addlength, int c_byte, char doname[], char *receivebuffer)
{
	int length = clength;//记录域名占用长度
	int alength = addlength;//记录加入点的长度
	int cu_byte = c_byte;
	//printf("当前字节数：%d\n", cu_byte);
	unsigned char  c;

	c = receivebuffer[cu_byte];//取第一块域名的字节数
	//printf("当前域名字节数：%d\n", c);
	while (c != 0)
	{//未到域名结束符
		if ((c & 0xc0) == 0xc0)
		{
			unsigned short *x = (unsigned short *)(receivebuffer + cu_byte);
			*x = ntohs(*x);//转化为主机字节序
			*x = (*x) & 0x3fff;//前两bit置零
			int offset = *x;
			int k = do_name_reso(length, alength, offset, doname, receivebuffer);//递归解析域名，不增加占用长度
			*x = (*x) | 0xc000;//前两bit复原
			*x = htons(*x);//还原为网络字节序
			return length + 2;
		}
		else
		{
			cu_byte++;
			length++;
			//printf("当前字节数：%d\n", cu_byte);
			int le = c;//转化为整数
			//printf("当前域名字节数：%d\n", le);
			for (int i = 0; i < le; i++)
			{
				doname[alength++] = receivebuffer[cu_byte++];
				length++;
			}
			c = receivebuffer[cu_byte];//取下一块域名的字节数
			//printf("当前域名字节数：%d\n", c);
			if (c != 0)  doname[alength++] = '.';
		}
	}
	cu_byte++;
	length++;//域名结束符也算在占用长度里
	doname[alength] = '\0';
	return length;

}

void connect_string(char *a, char *b, int aLength, int bLength)
{
	int i;
	for (i = 0; i < bLength; i++)
	{
		a[aLength + i] = b[i];
	}
	a[aLength + i] = 0;
}

void connect_string(char *a, const char *b, int aLength, int bLength)
{
	int i;
	for (i = 0; i < bLength; i++)
	{
		a[aLength + i] = b[i];
	}
	a[aLength + i] = 0;
}

void insert_A_record(sqlite3 *db, char *zErrMsg, char *Name, char *Alias, char *Type, char *Class, int TTL, int DataLength, const char *Address, int *length)
{
	int sqlLength;
	char temSql[4096] = "INSERT INTO A_RECORD (Name, Alias, Type, Class, Time_to_live, Data_length, Address) VALUES (";
	sqlLength = strlen(temSql);
	//temSql = temSql + "'" + domainName + "'" + ", " + "'" + ARecord + "'" + ", " + std::to_string(TTL) + ");";
	connect_string(temSql, "'", sqlLength, 1);
	sqlLength += 1;
	connect_string(temSql, Name, sqlLength, length[0]);
	sqlLength += length[0];
	connect_string(temSql, "', '", sqlLength, 4);
	sqlLength += 4;
	connect_string(temSql, Alias, sqlLength, length[1]);
	sqlLength += length[1];
	connect_string(temSql, "', '", sqlLength, 4);
	sqlLength += 4;
	connect_string(temSql, Type, sqlLength, length[2]);
	sqlLength += length[2];
	connect_string(temSql, "', '", sqlLength, 4);
	sqlLength += 4;
	connect_string(temSql, Class, sqlLength, length[3]);
	sqlLength += length[3];
	connect_string(temSql, "', ", sqlLength, 3);
	sqlLength += 3;
	connect_string(temSql, std::to_string(TTL).c_str(), sqlLength, length[4]);
	sqlLength += length[4];
	connect_string(temSql, ", ", sqlLength, 2);
	sqlLength += 2;
	connect_string(temSql, std::to_string(DataLength).c_str(), sqlLength, length[5]);
	sqlLength += length[5];
	connect_string(temSql, ", '", sqlLength, 3);
	sqlLength += 3;
	connect_string(temSql, Address, sqlLength, length[6]);
	sqlLength += length[6];
	connect_string(temSql, "');", sqlLength, 3);
	//printf("%s", temSql);
	//return;
	int rc = sqlite3_exec(db, temSql, callback, 0, &zErrMsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	else {
		fprintf(stdout, "Operation done successfully\n");
	}

}

int query_A_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, const char *Address, int addLength)
{
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[4096] = "SELECT * from A_RECORD where Name = '";
	sqlLength = strlen(sql);
	connect_string(sql, Name, sqlLength, nameLength);
	sqlLength += nameLength;
	connect_string(sql, "' and Address = '", sqlLength, 17);
	sqlLength += 17;
	connect_string(sql, Address, sqlLength, addLength);
	sqlLength += addLength;
	connect_string(sql, "';", sqlLength, 2);
	sqlite3_prepare(db, sql, -1, &statement, NULL);
	if (ret != SQLITE_OK)
	{
		printf("prepare error ret : %d\n", ret);
		return 0;
	}
	int res = 0;
	while (sqlite3_step(statement) == SQLITE_ROW)
	{
		char* domainName1 = (char *)sqlite3_column_text(statement, 0);
		char* ARecord = (char *)sqlite3_column_text(statement, 6);

		printf("domainName = %s\nARecord = %s\n\n", domainName1, ARecord);
		res++;
	}
	return res;
} 

int query_A_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength)
{
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[4096] = "SELECT * from A_RECORD where Name = '";
	sqlLength = strlen(sql);
	connect_string(sql, Name, sqlLength, nameLength);
	sqlLength += nameLength;
	connect_string(sql, "';", sqlLength, 2);
	sqlite3_prepare(db, sql, -1, &statement, NULL);
	//printf("%s-------sql------\n", sql);
	if (ret != SQLITE_OK)
	{
		printf("prepare error ret : %d\n", ret);
		return 0;
	}
	int res = 0;
	while (sqlite3_step(statement) == SQLITE_ROW)
	{
		char* domainName1 = (char *)sqlite3_column_text(statement, 0);
		char* alias = (char *)sqlite3_column_text(statement, 1);
		int TTL = sqlite3_column_int(statement, 4);
		char *address = (char *)sqlite3_column_text(statement, 6);

		printf("domainName = %s\nARecord = %s\nTTL = %d\nadress = %s\n\n", domainName1, alias, TTL, address);
		res++;
	}
	//printf("%d--------query-------\n", res);
	return res;
}

void insert_CNAME_record(sqlite3 *db, char *zErrMsg, char *Name, char *Alias, char *Type, char *Class, int TTL, int DataLength, char *CNAME, int *length)
{
	int sqlLength;
	char temSql[4096] = "INSERT INTO CNAME_RECORD (Name, Alias, Type, Class, Time_to_live, Data_length, CNAME) VALUES (";
	sqlLength = strlen(temSql);
	//temSql = temSql + "'" + domainName + "'" + ", " + "'" + ARecord + "'" + ", " + std::to_string(TTL) + ");";
	connect_string(temSql, "'", sqlLength, 1);
	sqlLength += 1;
	connect_string(temSql, Name, sqlLength, length[0]);
	sqlLength += length[0];
	connect_string(temSql, "', '", sqlLength, 4);
	sqlLength += 4;
	connect_string(temSql, Alias, sqlLength, length[1]);
	sqlLength += length[1];
	connect_string(temSql, "', '", sqlLength, 4);
	sqlLength += 4;
	connect_string(temSql, Type, sqlLength, length[2]);
	sqlLength += length[2];
	connect_string(temSql, "', '", sqlLength, 4);
	sqlLength += 4;
	connect_string(temSql, Class, sqlLength, length[3]);
	sqlLength += length[3];
	connect_string(temSql, "', ", sqlLength, 3);
	sqlLength += 3;
	connect_string(temSql, std::to_string(TTL).c_str(), sqlLength, length[4]);
	sqlLength += length[4];
	connect_string(temSql, ", ", sqlLength, 2);
	sqlLength += 2;
	connect_string(temSql, std::to_string(DataLength).c_str(), sqlLength, length[5]);
	sqlLength += length[5];
	connect_string(temSql, ", '", sqlLength, 3);
	sqlLength += 3;
	connect_string(temSql, CNAME, sqlLength, length[6]);
	sqlLength += length[6];
	connect_string(temSql, "');", sqlLength, 3);
	//printf("%s", temSql);
	//return;
	int rc = sqlite3_exec(db, temSql, callback, 0, &zErrMsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	else {
		fprintf(stdout, "Operation done successfully\n");
	}

}

int query_CNAME_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength)
{
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[4096] = "SELECT * from CNAME_RECORD where Name = '";
	sqlLength = strlen(sql);
	connect_string(sql, Name, sqlLength, nameLength);
	sqlLength += nameLength;
	connect_string(sql, "';", sqlLength, 2);
	sqlite3_prepare(db, sql, -1, &statement, NULL);
	if (ret != SQLITE_OK)
	{
		printf("prepare error ret : %d\n", ret);
		return 0;
	}
	int res = 0;
	while (sqlite3_step(statement) == SQLITE_ROW)
	{
		char* domainName1 = (char *)sqlite3_column_text(statement, 0);
		char* CNAME_Record = (char *)sqlite3_column_text(statement, 6);


		//printf("domainName = %s\nCNAME = %s\n\n", domainName1, CNAME_Record);
		res++;
	}
	return res;
}

int query_CNAME_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, char *CNAME, int CNLength)
{
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[4096] = "SELECT * from CNAME_RECORD where Name = '";
	sqlLength = strlen(sql);
	connect_string(sql, Name, sqlLength, nameLength);
	sqlLength += nameLength;
	connect_string(sql, "' and CNAME = '", sqlLength, 15);
	sqlLength += 15;
	connect_string(sql, CNAME, sqlLength, CNLength);
	sqlLength += CNLength;
	connect_string(sql, "';", sqlLength, 2);
	sqlite3_prepare(db, sql, -1, &statement, NULL);
	if (ret != SQLITE_OK)
	{
		printf("prepare error ret : %d\n", ret);
		return 0;
	}
	int res = 0;
	while (sqlite3_step(statement) == SQLITE_ROW)
	{
		char* domainName1 = (char *)sqlite3_column_text(statement, 0);
		char* CNAME_Record = (char *)sqlite3_column_text(statement, 6);

		printf("domainName = %s\nCNAME = %s\n\n", domainName1, CNAME_Record);
		res++;
	}
	return res;
}
