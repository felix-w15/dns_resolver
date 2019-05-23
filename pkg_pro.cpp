#include<stdlib.h>
#include<stdio.h>
#include<mutex>

#include"pkg_pro.h"

long timestamp[IDTABLE_SIZE];//存放向上级请求包发出时间
SOCKADDR_IN client_ip[IDTABLE_SIZE];//存放客户机的ip地址，用以发答复包以及并发处理
stringstream sstream;//转换格式流
map<string, unsigned short> *mapDomainName;

std::mutex mt;//互斥器

static int callback(void *NotUsed, int argc, char **argv, char **azColName) {//打印错误信息相关
	int i;
	for (i = 0; i < argc; i++)
	{
		printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
	}
	printf("\n");
	return 0;
}

int str_len(char *str)//求某字符串长度
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

void insert_IP(char *ip, char *sendBuf, int *bytePos)//将ip存入发送缓冲区
{
	int ipLen = str_len(ip);
	string tmp = "";
	for (int i = 0; i <= ipLen; i++)
	{
		if (i != ipLen && ip[i] != '.')//未到结尾或未碰到'.'则连接string
		{
			char s[2] = { ip[i], 0 };
			string c = s;
			tmp = tmp + c;
		}
		else//转换成字节存入发送缓冲区
		{
			sstream.clear();//清空sstream缓冲区
			unsigned short singleIP;
			sstream << tmp;
			sstream >> singleIP;
			sstream.str("");
			sendBuf[*bytePos] = (char)singleIP;
			*bytePos = *bytePos + 1;
			tmp = "";
		}
	}
}

void init_table(short int t[], short int q)
{
	for (int i = 0; i < IDTABLE_SIZE; i++)
	{
		t[i] = q;
	}
}

void domainStore(char *domain, int len, int iniBytePos, string res)//域名-字节位置存储以便实现压缩规则
{	
	if (len <= 0) return;
	string tmp =  (res == "") ? "" : ('.' + res);//为了存储完整域名
	int index = len - 1;
	while (index >= -1)
	{
		if (domain[index] != '.' && index != -1)//为域名字符
		{
			char s[2] = { domain[index], 0 };
			string c = s;
			tmp = c + tmp;
		}
		else
		{
			unsigned short namePos = (unsigned short)(iniBytePos + index + 1);
			mapDomainName->insert(pair<string, unsigned short>(tmp, namePos));
			tmp = '.' + tmp;
		}
		index--;
	}
}

unsigned short domain_pro(char* name, char *sendBuf, int *bytePos)
{
	int j = str_len(name) - 1;
	int nameEndPos = j + 1;//查询name数组截止的位置
	unsigned short ptrPos, dataLen = 0;//指针定位的值
	string tmp = "", res = "";
	while (j >= -1)//域名压缩定位
	{
		if (name[j] != '.' && j != -1)
		{
			char s[2] = { name[j], 0 };
			string c = s;
			tmp = c + tmp;
		}
		else//碰到.则判断该域名是否已经保存
		{
			map<string, unsigned short>::iterator iter;
			iter = mapDomainName->find(tmp);
			if (iter != mapDomainName->end())
			{
				nameEndPos = j;
				ptrPos = iter->second;
				res = iter->first;
			}
			else
				break;
			tmp = '.' + tmp;
		}
		j--;
	}
	int i = 0, lastPos = 0, iniBytePos = *bytePos;
	while (i <= (nameEndPos))//如果全可以用指针替代则不需要下面存的步骤
	{
		if (name[i] == '.' or name[i] == '\0')
		{
			sendBuf[*bytePos] = i - lastPos;
			dataLen = dataLen + 1;//dataLen值增加
			for (int j = 0; j < i - lastPos; j++)//将域名放入发送缓冲区
			{
				dataLen = dataLen + 1;//dataLen值增加
				*bytePos = *bytePos + 1;
				sendBuf[*bytePos] = name[j + lastPos];
			}
			*bytePos = *bytePos + 1;
			lastPos = i + 1;
		}
		i++;
	}
	i--;//i定位到'\0'
	//将指针放入发送缓冲区
	if (res != "")//使用了指针
	{
		dataLen = dataLen + 2;
		sendBuf[*bytePos] = (char)192;
		*bytePos = *bytePos + 1;

		sendBuf[*bytePos] = (char)ptrPos;
		*bytePos = *bytePos + 1;	
	}
	else
	{
		sendBuf[*bytePos] = 0;
		*bytePos = *bytePos + 1;
	}
	

	//域名-字节位置存储
	domainStore(name, i, iniBytePos, res);
	return dataLen;
}

void a_records_pro(resRecord *records, int len, char *sendBuf, int *bytePos)
{
	for (int i = 0; i < len; i++)
	{
		domain_pro(records[i].NAME, sendBuf, bytePos);//域名处理
		sendBuf[*bytePos + 1] = (char)(records[i].TYPE);
		sendBuf[*bytePos + 0] = (records[i].TYPE) >> 8;
		*bytePos = *bytePos + 2;
		sendBuf[*bytePos + 1] = (char)(records[i].CLASS);
		sendBuf[*bytePos + 0] = (records[i].CLASS) >> 8;
		*bytePos = *bytePos + 2;
		sendBuf[*bytePos + 3] = (char)(records[i].TTL);
		sendBuf[*bytePos + 2] = (char)((records[i].TTL) >> 8);
		sendBuf[*bytePos + 1] = (char)((records[i].TTL) >> 16);
		sendBuf[*bytePos + 0] = (records[i].TTL) >> 24;
		*bytePos = *bytePos + 4;
		sendBuf[*bytePos + 1] = (char)records[i].DATALENGTH;
		sendBuf[*bytePos + 0] = records[i].DATALENGTH >> 8;
		*bytePos = *bytePos + 2;
		insert_IP(records[i].RDATA, sendBuf, bytePos);
	}
}

void cn_records_pro(resRecord record, char *sendBuf, int *bytePos)
{
	resRecord newRecord = record;
	char *cname = record.NAME;
	char *zErrMsg = 0;
	while (query_CNAME_record(db, zErrMsg, cname, str_len(cname), &newRecord))
	{
		domain_pro(newRecord.NAME, sendBuf, bytePos);//域名处理
		sendBuf[*bytePos + 1] = (char)(newRecord.TYPE);
		sendBuf[*bytePos + 0] = (newRecord.TYPE) >> 8;
		*bytePos = *bytePos + 2;
		sendBuf[*bytePos + 1] = (char)(newRecord.CLASS);
		sendBuf[*bytePos + 0] = (newRecord.CLASS) >> 8;
		*bytePos = *bytePos + 2;
		sendBuf[*bytePos + 3] = (char)(newRecord.TTL);
		sendBuf[*bytePos + 2] = (char)((newRecord.TTL) >> 8);
		sendBuf[*bytePos + 1] = (char)((newRecord.TTL) >> 16);
		sendBuf[*bytePos + 0] = (newRecord.TTL) >> 24;
		*bytePos = *bytePos + 4;
		int dataLenPos = *bytePos;
		*bytePos = *bytePos + 2;
		unsigned short dataLen = domain_pro(newRecord.RDATA, sendBuf, bytePos);//求出data字段所占字节数
		sendBuf[dataLenPos + 1] = (char)dataLen;
		sendBuf[dataLenPos + 0] = dataLen >> 8;
		cname = newRecord.RDATA;//继续查询下一个CN
	}
}

void cn_records_pro(resRecord record, char *sendBuf, int *bytePos, int len)//cn_records_pro重载，只执行一次
{
	resRecord newRecord = record;
	char *cname = record.NAME;
	char *zErrMsg = 0;
	domain_pro(newRecord.NAME, sendBuf, bytePos);//域名处理
	sendBuf[*bytePos + 1] = (char)(newRecord.TYPE);
	sendBuf[*bytePos + 0] = (newRecord.TYPE) >> 8;
	*bytePos = *bytePos + 2;
	sendBuf[*bytePos + 1] = (char)(newRecord.CLASS);
	sendBuf[*bytePos + 0] = (newRecord.CLASS) >> 8;
	*bytePos = *bytePos + 2;
	sendBuf[*bytePos + 3] = (char)(newRecord.TTL);
	sendBuf[*bytePos + 2] = (char)((newRecord.TTL) >> 8);
	sendBuf[*bytePos + 1] = (char)((newRecord.TTL) >> 16);
	sendBuf[*bytePos + 0] = (newRecord.TTL) >> 24;
	*bytePos = *bytePos + 4;
	int dataLenPos = *bytePos;
	*bytePos = *bytePos + 2;
	unsigned short dataLen = domain_pro(newRecord.RDATA, sendBuf, bytePos);//求出data字段所占字节数
	sendBuf[dataLenPos + 1] = (char)dataLen;
	sendBuf[dataLenPos + 0] = dataLen >> 8;
	
}

void ns_records_pro(resRecord *records, int len, char *sendBuf, int *bytePos)
{
	for (int i = 0; i < len; i++)
	{
		domain_pro(records[i].NAME, sendBuf, bytePos);//域名处理
		sendBuf[*bytePos + 1] = (char)(records[i].TYPE);
		sendBuf[*bytePos + 0] = (records[i].TYPE) >> 8;
		*bytePos = *bytePos + 2;
		sendBuf[*bytePos + 1] = (char)(records[i].CLASS);
		sendBuf[*bytePos + 0] = (records[i].CLASS) >> 8;
		*bytePos = *bytePos + 2;
		sendBuf[*bytePos + 3] = (char)(records[i].TTL);
		sendBuf[*bytePos + 2] = (char)((records[i].TTL) >> 8);
		sendBuf[*bytePos + 1] = (char)((records[i].TTL) >> 16);
		sendBuf[*bytePos + 0] = (records[i].TTL) >> 24;
		*bytePos = *bytePos + 4;
		int dataLenPos = *bytePos;
		*bytePos = *bytePos + 2;
		unsigned short dataLen = domain_pro(records[i].RDATA, sendBuf, bytePos);//求出data字段所占字节数
		sendBuf[dataLenPos + 1] = (char)dataLen;
		sendBuf[dataLenPos + 0] = dataLen >> 8;	
	}
}

void mx_records_pro(resRecord *records, int len, char *sendBuf, int *bytePos)
{
	for (int i = 0; i < len; i++)
	{
		domain_pro(records[i].NAME, sendBuf, bytePos);//域名处理
		sendBuf[*bytePos + 1] = (char)(records[i].TYPE);
		sendBuf[*bytePos + 0] = (records[i].TYPE) >> 8;
		*bytePos = *bytePos + 2;
		sendBuf[*bytePos + 1] = (char)(records[i].CLASS);
		sendBuf[*bytePos + 0] = (records[i].CLASS) >> 8;
		*bytePos = *bytePos + 2;
		sendBuf[*bytePos + 3] = (char)(records[i].TTL);
		sendBuf[*bytePos + 2] = (char)((records[i].TTL) >> 8);
		sendBuf[*bytePos + 1] = (char)((records[i].TTL) >> 16);
		sendBuf[*bytePos + 0] = (records[i].TTL) >> 24;
		*bytePos = *bytePos + 4;
		int dataLenPos = *bytePos;
		*bytePos = *bytePos + 4;
		unsigned short dataLen = domain_pro(records[i].RDATA, sendBuf, bytePos) + 2;////求出data字段所占字节数，+2是由于包括preference字段两字节
		sendBuf[dataLenPos + 1] = (char)dataLen;
		sendBuf[dataLenPos + 0] = dataLen >> 8;
		sendBuf[dataLenPos + 3] = (char)records[i].PREFERENCE;
		sendBuf[dataLenPos + 2] = records[i].PREFERENCE >> 8;
	}
}

void query_for_superior_server(char *receiveBuffer, dns_header *header, SOCKADDR_IN cli_ip)
{
	//转换DNS数据包头ID,存客户机ip地址
	long current_time = GetTickCount();//记录下接收到包的时间
	int k = 0;//判断是否有相同ID
	short int hid = header->ID;//取ID字段
	short int nhid;//更改后的ID
	for (int i = 0; i < it_length; i++)
	{
		if (hid == new_id_table[i]) 
		{//已有相同ID
			k = 1;
			break;
		}
	}
	int i = 0;
	if (k == 0) 
	{//没有相同的ID
		nhid = hid;//不用更改ID
		for (i = 0; i < it_length; i++)
		{
			if (nhid < new_id_table[i]) {//将ID插入更改后的表
				for (int j = it_length; j > i; j--)
				{//大于此ID的包信息后移
					new_id_table[j] = new_id_table[j - 1];
					old_id_table[j] = old_id_table[j - 1];
					client_ip[j] = client_ip[j - 1];
					timestamp[j] = timestamp[j - 1];
				}
				//给新的向上级的请求包存储信息
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
			new_id_table[i] = nhid;
			client_ip[i] = cli_ip;
			it_length++;
		}
	}
	else
	{//有相同的id
		nhid = 0;//从0开始构造ID
		int i = 0;
		for (int i = 0; i < it_length; i++)
		{//找一个未被使用的ID或可被替换的ID
			if ((nhid == new_id_table[i]) && (current_time - timestamp[i] <= 50000))  nhid++;//构造的ID已被使用
			else {//构造的ID未被使用或超时时间过长可被替换，由于是有序的，故直接在此插入
				for (int j = it_length; j > i; j--)
				{//后移
					new_id_table[j] = new_id_table[j - 1];
					old_id_table[j] = old_id_table[j - 1];
					client_ip[j] = client_ip[j - 1];
					timestamp[j] = timestamp[j - 1];
				}
				//存储当前包信息
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
	header->ID = htons(header->ID);//转换字节序
	
	

	SOCKADDR_IN to_address;
	int addr_len = sizeof(SOCKADDR_IN);
	to_address.sin_family = AF_INET;
	to_address.sin_port = htons(53);
	to_address.sin_addr.S_un.S_addr = inet_addr(SUPERIOR_SERVER_ADDRESS);
	if (sendto(serverSocket, receiveBuffer, last, 0, (const struct sockaddr *)&to_address, addr_len))
	{
		timestamp[i] = GetTickCount();//记录发出包的时间
		//printf("转发至上一级域名服务器成功！\n");
	}
	else
	{
		//printf("转发至上一级域名服务器失败！\n");
		for (int j = i; j < IDTABLE_SIZE; i++)
		{//更改后的信息删除
			new_id_table[j] = new_id_table[j + 1];
			old_id_table[j] = old_id_table[j + 1];
			client_ip[j] = client_ip[j + 1];
			timestamp[j] = timestamp[j + 1];
		}
		it_length--;
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

	if (dFlag)
	{
		printf("time = %lld\nID = %u\nclientIP = %s\nrequestedDomainName = %s\n\n\n", time(NULL), header->ID, inet_ntoa(cli_ip.sin_addr), QNAME);
	}
	if (ddFlag)
	{
		printf("    HEADER:\n");
		printf("        opcode = ");
		if ((header->FLAGS & 0x7800) == 0x0000)
		{
			printf("Query, ");
		}
		else if ((header->FLAGS & 0x7800) == 0x0800)
		{
			printf("IQuery, ");
		}
		else if ((header->FLAGS & 0x7800) == 0x1000)
		{
			printf("Status, ");
		}
		else if ((header->FLAGS & 0x7800) == 0x2000)
		{
			printf("Notify, ");
		}
		else if ((header->FLAGS & 0x7800) == 0x2800)
		{
			printf("Update, ");
		}
		else
		{
			printf("Unassigned, ");
		}
		printf("id = %u, ", header->ID);
		printf("rcode = ");
		if ((header->FLAGS & 0x000F) == 0x0000)
		{
			printf("NoError\n");
		}
		else if ((header->FLAGS & 0x000F) == 0x0001)
		{
			printf("FormErr\n");
		}
		else if ((header->FLAGS & 0x000F) == 0x0002)
		{
			printf("ServFail\n");
		}
		else if ((header->FLAGS & 0x000F) == 0x0003)
		{
			printf("NXDomain\n");
		}
		else if ((header->FLAGS & 0x000F) == 0x0004)
		{
			printf("NotImp\n");
		}
		else if ((header->FLAGS & 0x000F) == 0x0005)
		{
			printf("Refused\n");
		}
		else if ((header->FLAGS & 0x000F) == 0x0006)
		{
			printf("YXDomain\n");
		}
		else if ((header->FLAGS & 0x000F) == 0x0007)
		{
			printf("YXRRSet\n");
		}
		else if ((header->FLAGS & 0x000F) == 0x0008)
		{
			printf("NXRRSet\n");
		}
		else if ((header->FLAGS & 0x000F) == 0x0009)
		{
			printf("NotAuth\n");
		}
		else if ((header->FLAGS & 0x000F) == 0x000A)
		{
			printf("NotZone\n");
		}
		else
		{
			printf("Unassigned\n");
		}
		printf("        questions = %u, answers = %u, authority records = %u, additional = %u\n\n", header->QDCOUNT, header->ANCOUNT, header->NSCOUNT, header->ARCOUNT);
		printf("    QUESTIONS:\n");
		printf("        QName = %s\n", QNAME);
		

	}

	//将收到header中字节序改为网络字节序
	
	header->FLAGS = htons(header->FLAGS);
	header->QDCOUNT = htons(header->QDCOUNT);
	header->ANCOUNT = htons(header->ANCOUNT);
	header->NSCOUNT = htons(header->NSCOUNT);
	header->ARCOUNT = htons(header->ARCOUNT);

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
	if (ddFlag)
	{
		printf("        QType = %d\n", tp);
		printf("        QClass = %d\n", ntohs(*(unsigned short*)(receiveBuffer + c_byte)));
	}
	//printf("请求查询类型: %d\n",tp);
	char *zErrMsg = 0;

	char *sendBuf = new char[BUFFER_SIZE];//发送缓冲区
	int bytePos = last;//发送缓冲区当前填充数据的位置
	
	delete mapDomainName;//建立新“域名-字节位置”字典之前，将之前字典删除
	mapDomainName = new map<string, unsigned short>;//用来建立压缩规则的字典

	if(tp == 1)//为A类型查询请求
	{	
		if (query_undesirable_web_record(db, zErrMsg, doName, str_len(doName)))//网站被屏蔽
		{
			header->ID = htons(header->ID);//转换成网络字节序
			memcpy(sendBuf, receiveBuffer, last);//拷贝N个字节到发送缓冲区
			unsigned short Flags = 0x8183;//网站不存在
			unsigned short Questions = (unsigned short)1;
			unsigned short Answer = (unsigned short)0;

			*(sendBuf + 3) = (char)Flags;
			*(sendBuf + 2) = Flags >> 8;
			*(sendBuf + 5) = (char)Questions;
			*(sendBuf + 4) = Questions >> 8;
			*(sendBuf + 7) = (char)Answer;
			*(sendBuf + 6) = Answer >> 8;
			//printf("----------\n");
			sendto(serverSocket, sendBuf, bytePos, 0, (SOCKADDR*)&cli_ip, sizeof(SOCKADDR));
		}
		else
		{
			resRecord cnameRecord[RESO_MAX];//存储cname类型记录
			int queryCNameRes = query_CNAME_record(db, zErrMsg, doName, str_len(doName), cnameRecord, 1);
			resRecord aRecord[RESO_MAX];//存储A类型记录
			int queryAResult = query_A_record(db, zErrMsg, doName, str_len(doName), aRecord);
			if (queryAResult)//本地数据库有缓存,给客户端发送response包
			{
				header->ID = htons(header->ID);
				memcpy(sendBuf, receiveBuffer, last);//拷贝N个字节到发送缓冲区

				//将QNAME存入字典
				domainStore(QNAME, str_len(QNAME), 12, "");//12为QNAME开始字节数
				//printf("%s/*/*/*/%d*/*/*/\n", QNAME, str_len(QNAME));

				unsigned short Flags = 0x8180;
				unsigned short Questions = (unsigned short)1;
				unsigned short Answer = (unsigned short)(queryCNameRes + queryAResult);
				//printf("/*/*/*/%c*/*answer/*/\n", Answer);
				//printf("/*/*/*/%u*/*/answer*/\n", Answer);
				*(sendBuf + 3) = (char)Flags;
				*(sendBuf + 2) = Flags >> 8;
				*(sendBuf + 5) = (char)Questions;
				*(sendBuf + 4) = Questions >> 8;
				*(sendBuf + 7) = (char)Answer;
				*(sendBuf + 6) = Answer >> 8;
				//printf("/*/*/*/%d/*%d/*/\n", sendBuf[6], sendBuf[7]);

				if (queryCNameRes)//如果存在CN类型记录
				{
					cn_records_pro(*cnameRecord, sendBuf, &bytePos);//cname记录处理成dns包数据流形式并存入发送缓冲区
				}
				a_records_pro(aRecord, queryAResult, sendBuf, &bytePos);

				printf("本地存有%s域名的A类型记录!\n\n", doName);
				//转发给客户机
				sendto(serverSocket, sendBuf, bytePos, 0, (SOCKADDR*)&cli_ip, sizeof(SOCKADDR));
			}
			else
			{
				query_for_superior_server(receiveBuffer, header, cli_ip);//向高一级域名服务器发送查询
			}
			if (!cnameRecord->NAME)
				delete cnameRecord->NAME;
			if (!cnameRecord->RDATA)
				delete cnameRecord->RDATA;
			if (!cnameRecord)
				delete cnameRecord;
		}
	}
	else if (tp == 5)//CNAME请求
	{
		resRecord *cnameRecord = new resRecord;//存储cname类型记录
		//cnameRecord ;
		int queryCNameRes = query_CNAME_record(db, zErrMsg, doName, str_len(doName), cnameRecord);
		if (queryCNameRes)
		{
			header->ID = htons(header->ID);
			memcpy(sendBuf, receiveBuffer, last);//拷贝N个字节到发送缓冲区
			unsigned short Flags = 0x8180;
			unsigned short Questions = (unsigned short)1;
			unsigned short Answer = (unsigned short)1;
			//printf("/*/*/*/%c*/*answer/*/\n", Answer);
			//printf("/*/*/*/%u*/*/answer*/\n", Answer);
			*(sendBuf + 3) = (char)Flags;
			*(sendBuf + 2) = Flags >> 8;
			*(sendBuf + 5) = (char)Questions;
			*(sendBuf + 4) = Questions >> 8;
			*(sendBuf + 7) = (char)Answer;
			*(sendBuf + 6) = Answer >> 8;

			cn_records_pro(*cnameRecord, sendBuf, &bytePos, 1);//cname记录处理成dns包数据流形式并存入发送缓冲区
			printf("本地存有%s域名的CNAME类型记录!\n\n", doName);
			//转发给客户机
			
			sendto(serverSocket, sendBuf, bytePos, 0, (SOCKADDR*)&cli_ip, sizeof(SOCKADDR));
		}
		else
		{
			query_for_superior_server(receiveBuffer, header, cli_ip);//向高一级域名服务器发送查询
		}
	}
	else if (tp == 2)//NS类型查询
	{
		resRecord nsRecord[RESO_MAX];//存储NS类型记录
		int queryNSResult = query_NS_record(db, zErrMsg, doName, str_len(doName), nsRecord);
		if (queryNSResult)
		{
			header->ID = htons(header->ID);
			memcpy(sendBuf, receiveBuffer, last);//拷贝N个字节到发送缓冲区

			//将QNAME存入字典
			domainStore(QNAME, str_len(QNAME), 12, "");//12为QNAME开始字节数
			//printf("%s/*/*/*/%d*/*/*/\n", QNAME, str_len(QNAME));

			unsigned short Flags = 0x8180;
			unsigned short Questions = (unsigned short)1;
			unsigned short Answer = (unsigned short)(queryNSResult);
			//printf("/*/*/*/%c*/*answer/*/\n", Answer);
			//printf("/*/*/*/%u*/*/answer*/\n", Answer);
			*(sendBuf + 3) = (char)Flags;
			*(sendBuf + 2) = Flags >> 8;
			*(sendBuf + 5) = (char)Questions;
			*(sendBuf + 4) = Questions >> 8;
			*(sendBuf + 7) = (char)Answer;
			*(sendBuf + 6) = Answer >> 8;
			//printf("/*/*/*/%d/*%d/*/\n", sendBuf[6], sendBuf[7]);

			//cn_records_pro(*cnameRecord, sendBuf, &bytePos);//cname记录处理成dns包数据流形式并存入发送缓冲区

			ns_records_pro(nsRecord, queryNSResult, sendBuf, &bytePos);

			printf("本地存有%s域名的NS类型记录!\n\n", doName);
			//转发给客户机
			sendto(serverSocket, sendBuf, bytePos, 0, (SOCKADDR*)&cli_ip, sizeof(SOCKADDR));
		}
		else
			query_for_superior_server(receiveBuffer, header, cli_ip);//向高一级域名服务器发送查询
	}
	else if (tp == 15)//MX类型查询
	{
		resRecord mxRecord[RESO_MAX];//存储NS类型记录
		int queryMXResult = query_MX_record(db, zErrMsg, doName, str_len(doName), mxRecord);
		if (queryMXResult)
		{
			header->ID = htons(header->ID);
			memcpy(sendBuf, receiveBuffer, last);//拷贝N个字节到发送缓冲区

			//将QNAME存入字典
			domainStore(QNAME, str_len(QNAME), 12, "");//12为QNAME开始字节数
			//printf("%s/*/*/*/%d*/*/*/\n", QNAME, str_len(QNAME));

			unsigned short Flags = 0x8180;
			unsigned short Questions = (unsigned short)1;
			unsigned short Answer = (unsigned short)(queryMXResult);
			//printf("/*/*/*/%c*/*answer/*/\n", Answer);
			//printf("/*/*/*/%u*/*/answer*/\n", Answer);
			*(sendBuf + 3) = (char)Flags;
			*(sendBuf + 2) = Flags >> 8;
			*(sendBuf + 5) = (char)Questions;
			*(sendBuf + 4) = Questions >> 8;
			*(sendBuf + 7) = (char)Answer;
			*(sendBuf + 6) = Answer >> 8;
			//printf("/*/*/*/%d/*%d/*/\n", sendBuf[6], sendBuf[7]);

			//cn_records_pro(*cnameRecord, sendBuf, &bytePos);//cname记录处理成dns包数据流形式并存入发送缓冲区

			mx_records_pro(mxRecord, queryMXResult, sendBuf, &bytePos);

			printf("本地存有%s域名的MX类型记录!\n\n", doName);
			//转发给客户机
			sendto(serverSocket, sendBuf, bytePos, 0, (SOCKADDR*)&cli_ip, sizeof(SOCKADDR));
		}
		else
			query_for_superior_server(receiveBuffer, header, cli_ip);//向高一级域名服务器发送查询
	}
	else
	{
		query_for_superior_server(receiveBuffer, header, cli_ip);//向高一级域名服务器发送查询
	}
}

void resp_pro(dns_header *header, char *receiveBuffer)
{
	
	SOCKADDR_IN q_ip;//此包应回复给的客户机ip
	long ctime = GetTickCount();//记录当前接收到包的时间
	int time_out = 0;//记录是否是超时包

	//还原DNS数据包头ID
	short int hid = header->ID;//取包中ID
	short int rehid;//存储还原后后的ID
	int i = 0;
	for (i = 0; i < it_length; i++)
	{//找到ID在新表中对应的下标
		if (hid == new_id_table[i])  break;
	}
	if (i == it_length)
	{//为迟到包且ID已被替换过
		time_out = 1;
	}
	else if (ctime - timestamp[i] > 2000)
	{//为迟到包且ID未被替换
		time_out = 1;
		for (int j = i; j < it_length - 1; j++)
		{//删除此ID数据，后面ID数据前移
			old_id_table[i] = old_id_table[i + 1];
			new_id_table[i] = new_id_table[i + 1];
			client_ip[i] = client_ip[i + 1];
		}
		it_length--;//长度减1
	}
	else 
	{//非超时包
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
	}

	//取应答内容，插入数据库
	//取AA
	if ((header->FLAGS & 0x0400) == 0x0400) 
	{//授权答案
		if (ddFlag)
		{
			printf("\n------------\n");
			printf("权威应答\n");
			printf("------------\n");
		}
	}
	else 
	{
		if (ddFlag)
		{
			printf("\n------------\n");
			printf("非权威应答\n");
			printf("------------\n");
		}
	}

	//判断RCODE
	if ((header->FLAGS & 0x000F) == 0x0003) 
	{//RCODE为3表示域名出错
		//printf("未查询到此域名\n\n");
		//printf("Non-existent domain\n\n");
	}
	else 
	{
		if (ddFlag)
		{
			printf("Got answer:\n");
			printf("    HEADER:\n");
			printf("        opcode = ");
			if ((header->FLAGS & 0x7800) == 0x0000)
			{
				printf("Query, ");
			}
			else if ((header->FLAGS & 0x7800) == 0x0800)
			{
				printf("IQuery, ");
			}
			else if ((header->FLAGS & 0x7800) == 0x1000)
			{
				printf("Status, ");
			}
			else if ((header->FLAGS & 0x7800) == 0x2000)
			{
				printf("Notify, ");
			}
			else if ((header->FLAGS & 0x7800) == 0x2800)
			{
				printf("Update, ");
			}
			else
			{
				printf("Unassigned, ");
			}
			printf("id = %u, ", header->ID);
			printf("rcode = ");
			if ((header->FLAGS & 0x000F) == 0x0000)
			{
				printf("NoError\n");
			}
			else if ((header->FLAGS & 0x000F) == 0x0001)
			{
				printf("FormErr\n");
			}
			else if ((header->FLAGS & 0x000F) == 0x0002)
			{
				printf("ServFail\n");
			}
			else if ((header->FLAGS & 0x000F) == 0x0003)
			{
				printf("NXDomain\n");
			}
			else if ((header->FLAGS & 0x000F) == 0x0004)
			{
				printf("NotImp\n");
			}
			else if ((header->FLAGS & 0x000F) == 0x0005)
			{
				printf("Refused\n");
			}
			else if ((header->FLAGS & 0x000F) == 0x0006)
			{
				printf("YXDomain\n");
			}
			else if ((header->FLAGS & 0x000F) == 0x0007)
			{
				printf("YXRRSet\n");
			}
			else if ((header->FLAGS & 0x000F) == 0x0008)
			{
				printf("NXRRSet\n");
			}
			else if ((header->FLAGS & 0x000F) == 0x0009)
			{
				printf("NotAuth\n");
			}
			else if ((header->FLAGS & 0x000F) == 0x000A)
			{
				printf("NotZone\n");
			}
			else
			{
				printf("Unassigned\n");
			}
			printf("        questions = %u, answers = %u, authority records = %u, additional = %u\n\n", header->QDCOUNT, header->ANCOUNT, header->NSCOUNT, header->ARCOUNT);
		}
		
		//解析响应包
		//printf("\n");
		//判断请求个数和资源记录个数
		int ques = header->QDCOUNT;//query字段个数
		int requ = header->ANCOUNT;//anwser字段个数
		int aure = header->NSCOUNT;//authority字段个数
		int adre = header->ARCOUNT;//additional字段个数
		int reso = requ + aure + adre;//总的资源记录个数

		int c_byte = sizeof(dns_header);//当前拆分到的字节位置
		//拆分Question Section部分

		
		char doName[QNAME_MAX_LENTH];//查询域名或邮件地址后缀名

		for (int i = 0; i < ques; i++)
		{
			/*if (i == 0)  printf("Question Section（%d个）：\n\n", ques);*/

			
			int length = 0;//域名或邮件地址后缀名占用的字节数
			unsigned short *type;//查询类型
			unsigned short *Class;//查询类


			length = do_name_reso(0, 0, c_byte, doName, receiveBuffer);//解析域名或邮件地址后缀名
			c_byte += length;
			type = (unsigned short*)(receiveBuffer + c_byte);//取查询类型
			c_byte += 2;
			Class = (unsigned short*)(receiveBuffer + c_byte);//取Class
			c_byte += 2;

			*type = ntohs(*type);
			*Class = ntohs(*Class);
			//输出查询问题信息
			if (ddFlag)
			{
				printf("    QUESTIONS:\n");
				printf("        QName = %s\n", doName);
				printf("        QType = %d\n", *type);
				printf("        QClass = %d\n", *Class);
			}
			*type = htons(*type);
			*Class = htons(*Class);
		}

		//拆分后三段资源记录部分，因为格式相同，故同时解析
		for (int i = 0; i < reso; i++)
		{
			//当解析到某种字段时，输出提示信息
			if (ddFlag)
			{
				
				if (i == 0)
				{
					printf("    ANSWERS:\n");
					printf("        number of Anwser Section = %d\n", requ);
				}
				if (i == requ)  printf("        number of Authority Records Section = %d\n", aure);
				if (i == requ + aure)  printf("        number of Additional Records Section = %d\n", adre);
			}

			char doname[QNAME_MAX_LENTH];//域名或邮件地址后缀名
			int length = 0;//域名或邮件地址后缀名占用的字节数
			unsigned short *type;//查询类型
			unsigned short *Class;//查询类
			unsigned long *ttl;//生存时间
			unsigned short *relength;//资源数据长度

			//取公共字段
			length = do_name_reso(0, 0, c_byte, doname, receiveBuffer);//解析域名或邮件地址后缀名
			c_byte += length;
			type = (unsigned short*)(receiveBuffer + c_byte);
			c_byte += 2;
			Class = (unsigned short*)(receiveBuffer + c_byte);
			c_byte += 2;
			ttl = (unsigned long*)(receiveBuffer + c_byte);
			c_byte += 4;
			relength = (unsigned short*)(receiveBuffer + c_byte);
			c_byte += 2;

			//输出公共字段信息
			*type = ntohs(*type);
			*Class = ntohs(*Class);
			*ttl = ntohl(*ttl);
			*relength = ntohs(*relength);
			if (ddFlag)
			{
				printf("    ->  Name = %s\n", doname);
				printf("        Type = %d\n", *type);
				printf("        Class = %d\n", *Class);
				printf("        TTL = %ld (%ld secs)\n", *ttl, *ttl);
			}

			char storeData[BUFFER_SIZE];
			char *zErrMsg = 0;

			int TTL = (int)*ttl;
			int ttlLen = (std::to_string(TTL)).length();
			int doNameLen = str_len(doName);
			int aliasLen = str_len(doname);
			int lenth[RESO_MAX];//各项资源长度数据	

			lenth[0] = doNameLen;//域名长度
			lenth[1] = aliasLen;//别名长度
			lenth[3] = 2;//class长度
			lenth[4] = ttlLen;
			if (ddFlag)
			{
				printf("        DataLenth = %d\n", doNameLen);
				//printf("        TTL:%d\n", TTL);
			}
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
				if (ddFlag)
				{
					printf("        Internet Address = %d.%d.%d.%d\n", ip_address[0], ip_address[1], ip_address[2], ip_address[3]);
				}
				
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
				lenth[2] = 2;//type类型长度为2
				storeData[0] = 'N';
				storeData[1] = 'S';
				storeData[2] = 'I';
				storeData[3] = 'N';

				char dname[QNAME_MAX_LENTH];//存储域名服务器的名字
				length = do_name_reso(0, 0, c_byte, dname, receiveBuffer);//解析域名服务器的名字
				
 				lenth[5] = (std::to_string(length)).length();
				lenth[6] = str_len(dname);
				if (ddFlag)
				{
					printf("        Name Length = %d\n", length);
					printf("        Name Server = %s\n", dname);
				}
				if (!query_NS_record(db, zErrMsg, doName, doNameLen, dname, lenth[6]))//如果数据库中无该NS记录则存储
					insert_NS_record(db, zErrMsg, doName, doname, storeData, storeData + 2, TTL, length, dname, lenth);
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
				if (ddFlag)
				{
					printf("        CName = %s\n", cname);
				}
			}
			else if (*type == 15)
			{//MX类型
				lenth[2] = 2;//type类型长度为2
				storeData[0] = 'M';
				storeData[1] = 'X';
				storeData[2] = 'I';
				storeData[3] = 'N';


				char mname[QNAME_MAX_LENTH];//存储邮件服务器名
				unsigned short *preference;//邮件服务器的优先级
				preference = (unsigned short*)(receiveBuffer + c_byte);
				length = do_name_reso(0, 0, c_byte + 2, mname, receiveBuffer);//解析邮件服务器名
				*preference = ntohs(*preference);
				lenth[5] = (std::to_string(length)).length();
				lenth[6] = (std::to_string((int)*preference)).length();
				lenth[7] = str_len(mname);
				if (ddFlag)
				{
					printf("        Preference = %d\n", *preference);
					printf("        Mail Exchange = %s\n", mname);
				}
				if (!query_MX_record(db, zErrMsg, doName, doNameLen, mname, lenth[7]))//判断数据库中是否有MX记录
					insert_MX_record(db, zErrMsg, doName, doname, storeData, storeData + 2, TTL, length + lenth[6], (int)*preference, mname, lenth);
				*preference = htons(*preference);
			}
			c_byte += *relength;//解析到的字节数更新

			//转换字节序
			*type = htons(*type);
			*Class = htons(*Class);
			*ttl = htonl(*ttl);
			*relength = htons(*relength);
		}
	}

	//转换字节序
	
	header->ID = htons(header->ID);
	header->FLAGS = htons(header->FLAGS);
	header->QDCOUNT = htons(header->QDCOUNT);
	header->ANCOUNT = htons(header->ANCOUNT);
	header->NSCOUNT = htons(header->NSCOUNT);
	header->ARCOUNT = htons(header->ARCOUNT);

	//转发给客户机
	if (time_out == 0)
	{//不是超时包
		sendto(serverSocket, receiveBuffer, last, 0, (SOCKADDR*)&q_ip, sizeof(SOCKADDR));
	}
}

int do_name_reso(int clength, int addlength, int c_byte, char doname[], char *receivebuffer)
{
	int length = clength;//记录域名占用长度
	int alength = addlength;//记录加入点的长度
	int cu_byte = c_byte;
	unsigned char  c;

	c = receivebuffer[cu_byte];//取第一块域名的字节数
	while (c != 0)
	{//未到域名结束符
		if ((c & 0xc0) == 0xc0)
		{//解析到指针，已到末尾，固定占用2字节长度
			unsigned short *x = (unsigned short *)(receivebuffer + cu_byte);
			*x = ntohs(*x);//转化为主机字节序
			*x = (*x) & 0x3fff;//前两bit置零
			int offset = *x;
			int k = do_name_reso(length, alength, offset, doname, receivebuffer);//递归解析并存储域名，不增加占用长度
			*x = (*x) | 0xc000;//前两bit复原
			*x = htons(*x);//还原为网络字节序
			return length + 2;//指针说明域名存储已到末尾，返回占用长度
		}
		else
		{//不是指针
			cu_byte++;
			length++;
			int le = c;//转化为整数
			for (int i = 0; i < le; i++)
			{
				//存储此块域名
				doname[alength++] = receivebuffer[cu_byte++];
				length++;
			}
			c = receivebuffer[cu_byte];//取下一块域名的字节数
			if (c != 0)  doname[alength++] = '.';
		}
	}
	cu_byte++;
	length++;//域名结束符也算在占用长度里
	doname[alength] = '\0';
	return length;//返回域名占用长度
}

void connect_string(char *a, char *b, int aLength, int bLength)//将字符串b连接到字符串a的末端
{
	int i;
	for (i = 0; i < bLength; i++)
	{
		a[aLength + i] = b[i];
	}
	a[aLength + i] = 0;
}

void connect_string(char *a, const char *b, int aLength, int bLength)//将字符串b连接到字符串a的末端
{
	int i;
	for (i = 0; i < bLength; i++)
	{
		a[aLength + i] = b[i];
	}
	a[aLength + i] = 0;
}

void insert_A_record(sqlite3 *db, char *zErrMsg, char *Name, char *Alias, char *Type, char *Class, int TTL, int DataLength, const char *Address, int *length)
{//向数据库的A_RECORD表中插入一条数据
	int sqlLength;
	char temSql[SQL_MAX] = "INSERT INTO A_RECORD (Name, Alias, Type, Class, Time_to_live, Data_length, Address) VALUES (";
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
	int rc = sqlite3_exec(db, temSql, callback, 0, &zErrMsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	else {
		//fprintf(stdout, "Operation done successfully\n");
	}

}

int query_A_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, const char *Address, int addLength)
{//根据域名和Address在A_RECORD中查询数据
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[SQL_MAX] = "SELECT * from A_RECORD where Name = '";
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
		res++;
	}
	return res;
} 

int query_A_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, resRecord *records)
{//根据域名在A_RECORD中查询数据
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[SQL_MAX] = "SELECT * from A_RECORD where Name = '";
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
		char* domainName1 = (char *)sqlite3_column_text(statement, 1);
		unsigned short type = 1;//资源类型为A类型
		unsigned short cla = 1;//CLASS字段值为1
		unsigned long TTL = (unsigned long)sqlite3_column_int(statement, 4);
		unsigned short dataLen = (unsigned short)sqlite3_column_int(statement, 5);
		char* addrRecord = (char *)sqlite3_column_text(statement, 6);
		int domainLen = str_len(domainName1);
		int addrLen = str_len(addrRecord);//ip地址四个字节
		records[res].NAME = new char[domainLen + 1];
		memcpy(records[res].NAME, domainName1, domainLen);//拷贝domainLen个字节到record-NAME
		records[res].NAME[domainLen] = '\0';
		records[res].TYPE = type;
		records[res].CLASS = cla;
		records[res].TTL = TTL;
		records[res].DATALENGTH = dataLen;
		records[res].RDATA = new char[addrLen + 1];
		memcpy(records[res].RDATA, addrRecord, addrLen);//拷贝addrLen个字节到record-RDATA
		records[res].RDATA[addrLen] = '\0';

		res++;
	}
	return res;
}

void insert_CNAME_record(sqlite3 *db, char *zErrMsg, char *Name, char *Alias, char *Type, char *Class, int TTL, int DataLength, char *CNAME, int *length)
{//向数据库的表CNAME_RECORD中插入一条数据
	int sqlLength;
	char temSql[SQL_MAX] = "INSERT INTO CNAME_RECORD (Name, Alias, Type, Class, Time_to_live, Data_length, CNAME) VALUES (";
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
	//return;
	int rc = sqlite3_exec(db, temSql, callback, 0, &zErrMsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	else {
		//fprintf(stdout, "Operation done successfully\n");
	}

}

int query_CNAME_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, resRecord *record, int tag)
{//根据域名在CNAME_RECORD中查找数据
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[SQL_MAX] = "SELECT * from CNAME_RECORD where Name = '";
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
		if (res == 0)
		{
			char* domainName1 = (char *)sqlite3_column_text(statement, 1);
			unsigned short type = 5;//资源类型为CNAME类型
			unsigned short cla = 1;//CLASS字段值为1
			unsigned long TTL = (unsigned long)sqlite3_column_int(statement, 4);
			unsigned short dataLen = (unsigned short)sqlite3_column_int(statement, 5);
			char* cnameRecord = (char *)sqlite3_column_text(statement, 6);
			int domainLen = str_len(domainName1);
			int cnLen = str_len(cnameRecord);
			record->NAME = new char[domainLen + 1];
			memcpy(record->NAME, domainName1, domainLen);//拷贝N个字节到record-NAME
			record->NAME[domainLen] = '\0';
			record->RDATA = new char[cnLen + 1];
			memcpy(record->RDATA, cnameRecord, cnLen);//拷贝N个字节到record-RDATA
			record->RDATA[cnLen] = '\0';
			record->TYPE = type;
			record->CLASS = cla;
			record->TTL = TTL;
			record->DATALENGTH = dataLen;
		}
		res++;
	}
	return res;
}

int query_CNAME_record(sqlite3 *db, char *zErrMsg, char *Alias, int nameLength,  resRecord *record)
{//根据域名在CNAME_RECORD中查找数据
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[SQL_MAX] = "SELECT * from CNAME_RECORD where Alias = '";
	sqlLength = strlen(sql);
	connect_string(sql, Alias, sqlLength, nameLength);
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
		char* domainName1 = (char *)sqlite3_column_text(statement, 1);
		unsigned short type = 5;//资源类型为CNAME类型
		unsigned short cla = 1;//CLASS字段值为1
		unsigned long TTL = (unsigned long)sqlite3_column_int(statement, 4);
		unsigned short dataLen = (unsigned short)sqlite3_column_int(statement, 5);
		char* cnameRecord = (char *)sqlite3_column_text(statement, 6);
		int domainLen = str_len(domainName1);
		int cnLen = str_len(cnameRecord);
		record->NAME = new char[domainLen + 1];
		memcpy(record->NAME, domainName1, domainLen);//拷贝N个字节到record-NAME
		record->NAME[domainLen] = '\0';
		record->RDATA = new char[cnLen + 1];
		memcpy(record->RDATA, cnameRecord, cnLen);//拷贝N个字节到record-RDATA
		record->RDATA[cnLen] = '\0';
		record->TYPE = type;
		record->CLASS = cla;
		record->TTL = TTL;
		record->DATALENGTH = dataLen;
		res++;
	}
	return res;
}

int query_CNAME_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, char *CNAME, int CNLength)
{//根据域名和CNAME在CNAME_RECORD中查询数据
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[SQL_MAX] = "SELECT * from CNAME_RECORD where Name = '";
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

//		printf("domainName = %s\nCNAME = %s\n\n", domainName1, CNAME_Record);
		res++;
	}
	return res;
}

void insert_MX_record(sqlite3 *db, char *zErrMsg, char *Name, char *Alias, char *Type, char *Class, int TTL, int DataLength, int Preference, char *MX, int *length)
{//向数据库的MX_RECORD表中插入一条数据
	int sqlLength;
	char temSql[SQL_MAX] = "INSERT INTO MX_RECORD (Name, Alias, Type, Class, Time_to_live, Data_length, Preference, Mail_Exchange) VALUES (";
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
	connect_string(temSql, ", ", sqlLength, 2);
	sqlLength += 2;
	connect_string(temSql, std::to_string(Preference).c_str(), sqlLength, length[6]);
	sqlLength += length[6];
	connect_string(temSql, ", '", sqlLength, 3);
	sqlLength += 3;
	connect_string(temSql, MX, sqlLength, length[7]);
	sqlLength += length[7];
	connect_string(temSql, "');", sqlLength, 3);
	int rc = sqlite3_exec(db, temSql, callback, 0, &zErrMsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	else {
		//fprintf(stdout, "Operation done successfully\n");
	}

}

void insert_NS_record(sqlite3 *db, char *zErrMsg, char *Name, char *Alias, char *Type, char *Class, int TTL, int DataLength, char *NS, int *length)
{//向数据库的NS_RECORD表中插入一条数据
	int sqlLength;
	char temSql[SQL_MAX] = "INSERT INTO NS_RECORD (Name, Alias, Type, Class, Time_to_live, Data_length, Name_Server) VALUES (";
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
	connect_string(temSql, NS, sqlLength, length[6]);
	sqlLength += length[6];
	connect_string(temSql, "');", sqlLength, 3);
	int rc = sqlite3_exec(db, temSql, callback, 0, &zErrMsg);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
	}
	else {
		//fprintf(stdout, "Operation done successfully\n");
	}

}

int query_MX_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, resRecord *records)
{//根据域名在MX_RECORD中查询数据
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[SQL_MAX] = "SELECT * from MX_RECORD where Name = '";
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
		char* domainName1 = (char *)sqlite3_column_text(statement, 1);
		unsigned short type = 15;//资源类型为NS类型
		unsigned short cla = 1;//CLASS字段值为1
		unsigned long TTL = (unsigned long)sqlite3_column_int(statement, 4);
		unsigned short dataLen = (unsigned short)sqlite3_column_int(statement, 5);
		unsigned short preference = (unsigned short)sqlite3_column_int(statement, 6);
		char* mxServer = (char *)sqlite3_column_text(statement, 7);
		int domainLen = str_len(domainName1);
		int mxServerLen = str_len(mxServer);//NS记录的长度
		records[res].NAME = new char[domainLen + 1];
		memcpy(records[res].NAME, domainName1, domainLen);//拷贝domainLen个字节到record-NAME
		records[res].NAME[domainLen] = '\0';
		records[res].TYPE = type;
		records[res].CLASS = cla;
		records[res].TTL = TTL;
		records[res].DATALENGTH = dataLen;
		records[res].RDATA = new char[mxServerLen + 1];
		memcpy(records[res].RDATA, mxServer, mxServerLen);//拷贝addrLen个字节到record-RDATA
		records[res].RDATA[mxServerLen] = '\0';
		records[res].PREFERENCE = preference;
		res++;
	}
	return res;
}

int query_MX_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, char *mName, int mNameLen)
{//根据域名和MX在MX_RECORD中查询数据
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[SQL_MAX] = "SELECT * from MX_RECORD where Name = '";
	sqlLength = strlen(sql);
	connect_string(sql, Name, sqlLength, nameLength);
	sqlLength += nameLength;
	connect_string(sql, "' and Mail_Exchange = '", sqlLength, 23);
	sqlLength += 23;
	connect_string(sql, mName, sqlLength, mNameLen);
	sqlLength += mNameLen;

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
		res++;
	}
	return res;
}

int query_NS_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, char *NAME_SERVER, int nameServerLen)
{//根据域名和NS在数据库中查询数据
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[SQL_MAX] = "SELECT * from NS_RECORD where Name = '";
	sqlLength = strlen(sql);
	connect_string(sql, Name, sqlLength, nameLength);
	sqlLength += nameLength;
	connect_string(sql, "' and NAME_SERVER = '", sqlLength, 21);
	sqlLength += 21;
	connect_string(sql, NAME_SERVER, sqlLength, nameServerLen);
	sqlLength += nameServerLen;
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
		res++;
	}
	return res;
}

int query_NS_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength, resRecord *records)
{//根据域名在NS_RECORD中查找数据
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[SQL_MAX] = "SELECT * from NS_RECORD where Name = '";
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
		//char* domainName1 = (char *)sqlite3_column_text(statement, 0);
		//char* NameServer = (char *)sqlite3_column_text(statement, 6);
		char* domainName1 = (char *)sqlite3_column_text(statement, 1);
		unsigned short type = 2;//资源类型为NS类型
		unsigned short cla = 1;//CLASS字段值为1
		unsigned long TTL = (unsigned long)sqlite3_column_int(statement, 4);
		unsigned short dataLen = (unsigned short)sqlite3_column_int(statement, 5);
		char* nameServer = (char *)sqlite3_column_text(statement, 6);
		int domainLen = str_len(domainName1);
		int nameServerLen = str_len(nameServer);//NS记录的长度
		records[res].NAME = new char[domainLen + 1];
		memcpy(records[res].NAME, domainName1, domainLen);//拷贝domainLen个字节到record-NAME
		records[res].NAME[domainLen] = '\0';
		records[res].TYPE = type;
		records[res].CLASS = cla;
		records[res].TTL = TTL;
		records[res].DATALENGTH = dataLen;
		records[res].RDATA = new char[nameServerLen + 1];
		memcpy(records[res].RDATA, nameServer, nameServerLen);//拷贝addrLen个字节到record-RDATA
		records[res].RDATA[nameServerLen] = '\0';
		res++;
	}
	return res;
}

int query_undesirable_web_record(sqlite3 *db, char *zErrMsg, char *Name, int nameLength)
{//根据域名在UNDESIRABLE_WEB_TABLE中查找数据
	int ret = 0;
	sqlite3_stmt *statement;
	int sqlLength;
	char sql[SQL_MAX] = "SELECT * from UNDESIRABLE_WEB where Name = '";
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
		char* address = (char *)sqlite3_column_text(statement, 1);
		res++;
		//printf("address = %s\n", address);
	}
	return res;
}

void delete_expired_data(sqlite3 *db, char *zErrMsg)
{//定期删除数据库中超时的记录
	int ret = 0;
	sqlite3_stmt *statement;
	time_t a1 = time(NULL);
	while (1)
	{
		mt.lock();
		//printf("passed %d second(s)\n", (int)(time(0) - a1));
		char sql[SQL_MAX] = "SELECT Name, Time_to_live, Address, Time_Stamp from A_RECORD";
		ret = sqlite3_prepare(db, sql, -1, &statement, NULL);
		if (ret != SQLITE_OK)
		{
			printf("prepare error ret : %d\n", ret);
			return;
		}
		while (sqlite3_step(statement) == SQLITE_ROW)
		{
			char* Name = (char *)sqlite3_column_text(statement, 0);
			int TTL = sqlite3_column_int(statement, 1);
			char* Address = (char *)sqlite3_column_text(statement, 2);
			char* timeStamp = (char *)sqlite3_column_text(statement, 3);
			//printf("%s %d %s %s\n", Name, TTL, Address, timeStamp);
			tm tmTimeStamp = { 0,0,0,0,0,0,0,0 };
			sscanf_s(timeStamp, "%d-%d-%d %d:%d:%d", &tmTimeStamp.tm_year, &tmTimeStamp.tm_mon, &tmTimeStamp.tm_mday, \
				&tmTimeStamp.tm_hour, &tmTimeStamp.tm_min, &tmTimeStamp.tm_sec);
			tmTimeStamp.tm_year -= 1900;
			tmTimeStamp.tm_mon--;
			time_t timeStampToSec = mktime(&tmTimeStamp);
			time_t currentTime = time(NULL);
			long timeDifferece = (long)(currentTime - timeStampToSec);
			if (timeDifferece >= TTL)
			{
				int temSqlLength;
				char temSql[SQL_MAX] = "delete from A_RECORD where Name = '";
				temSqlLength = strlen(temSql);
				connect_string(temSql, Name, temSqlLength, strlen(Name));
				temSqlLength += strlen(Name);
				connect_string(temSql, "' and Address = '", temSqlLength, 17);
				temSqlLength += 17;
				connect_string(temSql, Address, temSqlLength, strlen(Address));
				temSqlLength += strlen(Address);
				connect_string(temSql, "';", temSqlLength, 2);

				ret = sqlite3_exec(db, temSql, callback, 0, &zErrMsg);
				if (ret != SQLITE_OK)
				{
					fprintf(stderr, "SQL error: %s\n", zErrMsg);
					sqlite3_free(zErrMsg);
				}
				else
				{
					//fprintf(stdout, "delete %s %s from A_RECORD\n", Name, Address);
				}
			}

		}


		for (int i = 0; i < SQL_MAX; i++)
		{
			sql[i] = 0;
		}
		connect_string(sql, "SELECT Name, Time_to_live, CNAME, Time_Stamp from CNAME_RECORD", 0, 62);

		ret = sqlite3_prepare(db, sql, -1, &statement, NULL);
		if (ret != SQLITE_OK)
		{
			printf("prepare error ret : %d\n", ret);
			return;
		}
		while (sqlite3_step(statement) == SQLITE_ROW)
		{
			char* Name = (char *)sqlite3_column_text(statement, 0);
			int TTL = sqlite3_column_int(statement, 1);
			char* CNAME = (char *)sqlite3_column_text(statement, 2);
			char* timeStamp = (char *)sqlite3_column_text(statement, 3);
			tm tmTimeStamp = { 0,0,0,0,0,0,0,0 };
			sscanf_s(timeStamp, "%d-%d-%d %d:%d:%d", &tmTimeStamp.tm_year, &tmTimeStamp.tm_mon, &tmTimeStamp.tm_mday, \
				&tmTimeStamp.tm_hour, &tmTimeStamp.tm_min, &tmTimeStamp.tm_sec);
			tmTimeStamp.tm_year -= 1900;
			tmTimeStamp.tm_mon--;
			time_t timeStampToSec = mktime(&tmTimeStamp);
			time_t currentTime = time(NULL);
			long timeDifferece = (long)(currentTime - timeStampToSec);
			if (timeDifferece >= TTL)
			{
				int temSqlLength;
				char temSql[SQL_MAX] = "delete from CNAME_RECORD where Name = '";
				temSqlLength = strlen(temSql);
				connect_string(temSql, Name, temSqlLength, strlen(Name));
				temSqlLength += strlen(Name);
				connect_string(temSql, "' and CNAME = '", temSqlLength, 15);
				temSqlLength += 15;
				connect_string(temSql, CNAME, temSqlLength, strlen(CNAME));
				temSqlLength += strlen(CNAME);
				connect_string(temSql, "';", temSqlLength, 2);

				ret = sqlite3_exec(db, temSql, callback, 0, &zErrMsg);
				if (ret != SQLITE_OK)
				{
					fprintf(stderr, "SQL error: %s\n", zErrMsg);
					sqlite3_free(zErrMsg);
				}
				else
				{
					//fprintf(stdout, "delete %s %s from CNAME_RECORD\n", Name, CNAME);
				}
			}

		}


		for (int i = 0; i < SQL_MAX; i++)
		{
			sql[i] = 0;
		}
		connect_string(sql, "SELECT Name, Time_to_live, Mail_Exchange, Time_Stamp from MX_RECORD", 0, 67);

		ret = sqlite3_prepare(db, sql, -1, &statement, NULL);
		if (ret != SQLITE_OK)
		{
			printf("prepare error ret : %d\n", ret);
			return;
		}
		while (sqlite3_step(statement) == SQLITE_ROW)
		{
			char* Name = (char *)sqlite3_column_text(statement, 0);
			int TTL = sqlite3_column_int(statement, 1);
			char* MX = (char *)sqlite3_column_text(statement, 2);
			char* timeStamp = (char *)sqlite3_column_text(statement, 3);
			tm tmTimeStamp = { 0,0,0,0,0,0,0,0 };
			sscanf_s(timeStamp, "%d-%d-%d %d:%d:%d", &tmTimeStamp.tm_year, &tmTimeStamp.tm_mon, &tmTimeStamp.tm_mday, \
				&tmTimeStamp.tm_hour, &tmTimeStamp.tm_min, &tmTimeStamp.tm_sec);
			tmTimeStamp.tm_year -= 1900;
			tmTimeStamp.tm_mon--;
			time_t timeStampToSec = mktime(&tmTimeStamp);
			time_t currentTime = time(NULL);
			long timeDifferece = (long)(currentTime - timeStampToSec);
			if (timeDifferece >= TTL)
			{
				int temSqlLength;
				char temSql[SQL_MAX] = "delete from MX_RECORD where Name = '";
				temSqlLength = strlen(temSql);
				connect_string(temSql, Name, temSqlLength, strlen(Name));
				temSqlLength += strlen(Name);
				connect_string(temSql, "' and Mail_Exchange = '", temSqlLength, 23);
				temSqlLength += 23;
				connect_string(temSql, MX, temSqlLength, strlen(MX));
				temSqlLength += strlen(MX);
				connect_string(temSql, "';", temSqlLength, 2);

				ret = sqlite3_exec(db, temSql, callback, 0, &zErrMsg);
				if (ret != SQLITE_OK)
				{
					fprintf(stderr, "SQL error: %s\n", zErrMsg);
					sqlite3_free(zErrMsg);
				}
				else
				{
					//fprintf(stdout, "delete %s %s from MX_RECORD\n", Name, MX);
				}
			}

		}


		for (int i = 0; i < SQL_MAX; i++)
		{
			sql[i] = 0;
		}
		connect_string(sql, "SELECT Name, Time_to_live, Name_Server, Time_Stamp from NS_RECORD", 0, 65);

		ret = sqlite3_prepare(db, sql, -1, &statement, NULL);
		if (ret != SQLITE_OK)
		{
			printf("prepare error ret : %d\n", ret);
			return;
		}
		while (sqlite3_step(statement) == SQLITE_ROW)
		{
			char* Name = (char *)sqlite3_column_text(statement, 0);
			int TTL = sqlite3_column_int(statement, 1);
			char* NS = (char *)sqlite3_column_text(statement, 2);
			char* timeStamp = (char *)sqlite3_column_text(statement, 3);
			tm tmTimeStamp = { 0,0,0,0,0,0,0,0 };
			sscanf_s(timeStamp, "%d-%d-%d %d:%d:%d", &tmTimeStamp.tm_year, &tmTimeStamp.tm_mon, &tmTimeStamp.tm_mday, \
				&tmTimeStamp.tm_hour, &tmTimeStamp.tm_min, &tmTimeStamp.tm_sec);
			tmTimeStamp.tm_year -= 1900;
			tmTimeStamp.tm_mon--;
			time_t timeStampToSec = mktime(&tmTimeStamp);
			time_t currentTime = time(NULL);
			long timeDifferece = (long)(currentTime - timeStampToSec);
			if (timeDifferece >= TTL)
			{
				int temSqlLength;
				char temSql[SQL_MAX] = "delete from NS_RECORD where Name = '";
				temSqlLength = strlen(temSql);
				connect_string(temSql, Name, temSqlLength, strlen(Name));
				temSqlLength += strlen(Name);
				connect_string(temSql, "' and Name_Server = '", temSqlLength, 21);
				temSqlLength += 21;
				connect_string(temSql, NS, temSqlLength, strlen(NS));
				temSqlLength += strlen(NS);
				connect_string(temSql, "';", temSqlLength, 2);

				ret = sqlite3_exec(db, temSql, callback, 0, &zErrMsg);
				if (ret != SQLITE_OK)
				{
					fprintf(stderr, "SQL error: %s\n", zErrMsg);
					sqlite3_free(zErrMsg);
				}
				else
				{
					//fprintf(stdout, "delete %s %s from NS_RECORD\n", Name, NS);
				}
			}

		}
		mt.unlock();
		Sleep(DELETE_INTERVAL);
	}
}