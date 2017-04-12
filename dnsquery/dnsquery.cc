
/* 
 * ===================================================================================== 
 * 
 *       Filename:  dnsquery.cpp 
 * 
 *    Description:  1.重组dns报文,解析dns报文.2支持ipv6，ipv4 3.发包收包循环3次4.检测自己的ip—stack  
 * 
 *        Version:  参照微信mars实现
 *        Created:  2017年04月01日
 *       Revision:  none 
 *       Compiler:  g++ 
 *       Author:  Qi    
 * 
 * ===================================================================================== 
 */ 
#include "dnsquery.h"


#if defined __APPLE__
#include <fstream>
#endif



#define TRAFFIC_LIMIT_RET_CODE (INT_MIN)
#define DNS_PORT (53)
#define DEFAULT_TIMEOUT (3000)
#define NAME_SVR ("nameserver")
#define NAME_SVR_LEN (40)

// Type field of Query and Answer
#define A         1       /* host address */
#define NS        2       /* authoritative server */
#define CNAME     5       /* canonical name */
#define SOA       6       /* start of authority zone */
#define PTR       12      /* domain name pointer */
#define MX        15      /* mail routing information */
#define AAAA      0x1c
 bool ipv4=true;

#pragma pack(push, 1)
struct DNS_HEADER {
    unsigned    short id;           // identification number

    unsigned    char rd     : 1;    // recursion desired
    unsigned    char tc     : 1;    // truncated message
    unsigned    char aa     : 1;    // authoritive answer
    unsigned    char opcode : 4;    // purpose of message
    unsigned    char qr     : 1;    // query/response flag

    unsigned    char rcode  : 4;    // response code
    unsigned    char cd     : 1;    // checking disabled
    unsigned    char ad     : 1;    // authenticated data
    unsigned    char z      : 1;    // its z! reserved
    unsigned    char ra     : 1;    // recursion available

    unsigned    short q_count;      // number of question entries
    unsigned    short ans_count;    // number of answer entries
    unsigned    short auth_count;   // number of authority entries
    unsigned    short add_count;    // number of resource entries
};



// Constant sized fields of query structure
struct QUESTION {
    unsigned short qtype;
    unsigned short qclass;
};


// Constant sized fields of the resource record structure
struct  R_DATA {
    unsigned short type;
    unsigned short _class;
    unsigned int   ttl;
    unsigned short data_len;
};
#pragma pack(pop)

// Pointers to resource record contents
struct RES_RECORD {
    unsigned char*  name;
    struct R_DATA*  resource;
    unsigned char*  rdata;
};

// Structure of a Query
typedef struct {
    unsigned char*       name;
    struct QUESTION*     ques;
} QUERY;



//函数原型声明
static void           ChangetoDnsNameFormat(unsigned char*, std::string);
static unsigned char* ReadName(unsigned char*, unsigned char*, int*);
static void           GetHostDnsServerIP(std::vector<std::string>& _dns_servers);
static void           PrepareDnsQueryPacket(unsigned char* _buf, struct DNS_HEADER* _dns, unsigned char* _qname, const std::string& _host);
static void           ReadRecvAnswer(unsigned char* _buf, struct DNS_HEADER* _dns, unsigned char* _reader, struct RES_RECORD* _answers);
static int            RecvWithinTime(int _fd, char* _buf, size_t _buf_n, struct sockaddr* _addr, socklen_t* _len, unsigned int _sec, unsigned _usec);
static void           FreeAll(struct RES_RECORD* _answers);
static bool           isValidIpAddress(const char* _ipaddress);

/**
 *函数名:    socket_gethostbyname
 *功能: 输入域名，可得到该域名下所对应的IP地址列表
 *输入:       _host：输入的要查询的主机域名
 *输入:       _timeout：设置查询超时时间，单位为毫秒
 *输入:       _dnsserver 指定的dns服务器的IP
 *输出:        _ipinfo为要输出的ip信息结构体
 *返回值:          当返回-1表示查询失败，当返回0则表示查询成功
 *
 */
typedef enum TLocalIPStack {
    ELocalIPStack_None = 0,
    ELocalIPStack_IPv4 = 1,
    ELocalIPStack_IPv6 = 2,
    ELocalIPStack_Dual = 3,
}ipstack_type_t;

static ipstack_type_t net_family;

static int _test_connect(int pf, struct sockaddr *addr, size_t addrlen) 
{
    int s = socket(pf, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0)
        return 0;
    int ret;
    do {
        ret = connect(s, addr, addrlen);
    } while (ret < 0 && errno == EINTR);
    int success = (ret == 0);
    
    return success;
}

static int _have_ipv6() 
{
    struct sockaddr_in6 sin_test; 
    memset(&sin_test, 0, sizeof(sin_test));
    sin_test.sin6_family = AF_INET6;
    sin_test.sin6_port = htons(0XFFFF);
    //uint8_t ip[16] = {0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    //memcpy(sin_test.sin6_addr.s6_addr, ip, sizeof(sin_test.sin6_addr.s6_addr));
    //sin_test.sin6_addr.s6_addr = {0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    //2001:4860:4860::8888
     inet_pton(AF_INET6, "2001:4860:4860::8888", &(sin_test.sin6_addr));  

    return _test_connect(PF_INET6, (struct sockaddr *)&sin_test, sizeof(sin_test));
}

static int _have_ipv4() 
{
    struct sockaddr_in sin_test; 
    memset(&sin_test, 0, sizeof(sin_test));
    sin_test.sin_family = AF_INET;
    sin_test.sin_port = htons(0XFFFF);
    sin_test.sin_addr.s_addr = htonl(0x08080808L);
    return _test_connect(PF_INET, (struct sockaddr *)&sin_test, sizeof(sin_test));
}
bool checknetfamily()
{
    net_family = ELocalIPStack_None;
    int have_ipv4 = _have_ipv4();
    int have_ipv6 = _have_ipv6();
    if (have_ipv4) {
        net_family = ELocalIPStack_IPv4;      
       // return true;
    }
    if (have_ipv6) {
        net_family = ELocalIPStack_IPv6;    
       
    }
     if(have_ipv4&&have_ipv6)
   {
     net_family=ELocalIPStack_Dual;
    }
    //dananet_family = ELocalIPStack_IPv4;
printf("net_family:%d\n",net_family);
    return true;

}
int socketv6_gethostbyname(const char* _host, socket_ipinfo_t* _ipinfo, int _timeout /*ms*/, const char* _dnsserver) {
  ipv4=false;  
  if (NULL == _host) return -1;

    if (NULL == _ipinfo) return -1;

    if (_timeout <= 0) _timeout = DEFAULT_TIMEOUT;

      int sockfd = socket(AF_INET6,SOCK_DGRAM,IPPROTO_UDP);
      /*
   socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  // UDP packet for DNS queries
       if (sock < 0) {
        return -1;
    }*/   
    if (sockfd  < 0) 
	    { 
		exit(-1);  
	    }  
      printf("sockfd:%d\n",sockfd);
    struct sockaddr_in6 dest = {0};
    dest.sin6_family = AF_INET6;
    inet_pton(AF_INET6, _dnsserver, &(dest.sin6_addr)); 
     dest.sin6_port = htons(DNS_PORT);
    struct RES_RECORD answers[SOCKET_MAX_IP_COUNT];  // the replies from the DNS server
    memset(answers, 0, sizeof(RES_RECORD)*SOCKET_MAX_IP_COUNT);

    int ret = -1;

    do {
        const unsigned int BUF_LEN = 65536;
        unsigned char send_buf[BUF_LEN] = {0};
        unsigned char recv_buf[BUF_LEN] = {0};
        struct DNS_HEADER* dns = (struct DNS_HEADER*)send_buf;
        unsigned char* qname = (unsigned char*)&send_buf[sizeof(struct DNS_HEADER)];
        PrepareDnsQueryPacket(send_buf, dns, qname, _host);
        unsigned long send_packlen = sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION);
      int sendfd;
      for(int i=0;i<3;i++)
      {
           sendfd = sendto(sockfd, (char*)send_buf, send_packlen, 0, (struct sockaddr*)&dest, sizeof(dest));
      printf("sendlen:%d\n",sendfd);
        if (sendfd==-1)
        {  
            break;
        }

        struct sockaddr_in6 recv_src = {0};

        socklen_t recv_src_len = sizeof(recv_src);

        int recvPacketLen = 0;
          if ((recvPacketLen = RecvWithinTime(sockfd, (char*)recv_buf, BUF_LEN, (struct sockaddr*)&recv_src, &recv_src_len, _timeout / 1000, (_timeout % 1000) * 1000)) > -1) {
            
            break;
        }
     
        printf("recvPacketLen:%d\n",recvPacketLen);
    }
  
        // move ahead of the dns header and the query field
        unsigned char* reader = &recv_buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION)];
        dns = (struct DNS_HEADER*)recv_buf;   // 指向recv_buf的header
        ReadRecvAnswer(recv_buf, dns, reader, answers);

        // 把查询到的IP放入返回参数_ipinfo结构体中
        int answer_count = std::min(SOCKET_MAX_IP_COUNT, (int)ntohs(dns->ans_count));
        _ipinfo->size = 0;
         for (int i = 0; i < answer_count; ++i) {
            if (AAAA == ntohs(answers[i].resource->type)) {  // IPv6 address
              std::string v6_addr;
              for(int p=0;p<16;p++)
            {  _ipinfo->v6_addr[_ipinfo->size].s6_addr[p]=answers[i].rdata[p];
               printf("%02x",answers[i].rdata[p]);
               if((p+1)%2==0&&p<15) printf(":");
               //v6_addr+=atoi(answers[i].rdata[p];
            }
            printf("\n");
               // _ipinfo->v6_addr[_ipinfo->size].s6_addr = (*p);  // working without ntohl
                _ipinfo->size++;
            }
        }

        if (0 >= _ipinfo->size) {  // unkown host, dns->rcode == 3
           
            break;
        }

        //      _ipinfo->dns = ;
        ret = 0;
    } while (false);

    FreeAll(answers);
    close(sockfd);
  
    return ret;  //* 查询DNS服务器超时
}
int socketv4_gethostbyname(const char* _host, socket_ipinfo_t* _ipinfo, int _timeout /*ms*/, const char* _dnsserver) {
   ipv4=true;
    if (NULL == _host) return -1;

    if (NULL == _ipinfo) return -1;

    if (_timeout <= 0) _timeout = DEFAULT_TIMEOUT;

    std::vector<std::string> dns_servers;

    if (_dnsserver && isValidIpAddress(_dnsserver)) {
       
        dns_servers.push_back(_dnsserver);
    } else {
       
        GetHostDnsServerIP(dns_servers);
    }
      int sockfd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
      /*
   socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  // UDP packet for DNS queries
       if (sock < 0) {
        return -1;
    }*/   
    if (sockfd  < 0) 
	    { 
		exit(-1);  
	    }  
      printf("sockfd:%d\n",sockfd);
    struct sockaddr_in dest = {0};
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, "8.8.8.8", &(dest.sin_addr)); 
     dest.sin_port = htons(DNS_PORT);
    struct RES_RECORD answers[SOCKET_MAX_IP_COUNT];  // the replies from the DNS server
    memset(answers, 0, sizeof(RES_RECORD)*SOCKET_MAX_IP_COUNT);

    int ret = -1;

    do {
        const unsigned int BUF_LEN = 65536;
        unsigned char send_buf[BUF_LEN] = {0};
        unsigned char recv_buf[BUF_LEN] = {0};
        struct DNS_HEADER* dns = (struct DNS_HEADER*)send_buf;
        unsigned char* qname = (unsigned char*)&send_buf[sizeof(struct DNS_HEADER)];
        PrepareDnsQueryPacket(send_buf, dns, qname, _host);
        unsigned long send_packlen = sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION);
      int sendfd;
      for(int i=0;i<3;i++)
      {


      sendfd = sendto(sockfd, (char*)send_buf, send_packlen, 0, (struct sockaddr*)&dest, sizeof(dest));
      printf("sendlen:%d\n",sendfd);
        if (sendfd==-1)
        {  
            break;
        }

        struct sockaddr_in recv_src = {0};

        socklen_t recv_src_len = sizeof(recv_src);

        int recvPacketLen = 0;
       
             if ((recvPacketLen = RecvWithinTime(sockfd, (char*)recv_buf, BUF_LEN, (struct sockaddr*)&recv_src, &recv_src_len, _timeout / 1000, (_timeout % 1000) * 1000)) > -1) {
            
            break;
        
      }
        printf("recvPacketLen:%d\n",recvPacketLen);
    }
  
        // move ahead of the dns header and the query field
        unsigned char* reader = &recv_buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1) + sizeof(struct QUESTION)];
        dns = (struct DNS_HEADER*)recv_buf;   // 指向recv_buf的header
        ReadRecvAnswer(recv_buf, dns, reader, answers);

        // 把查询到的IP放入返回参数_ipinfo结构体中
        int answer_count = std::min(SOCKET_MAX_IP_COUNT, (int)ntohs(dns->ans_count));
        _ipinfo->size = 0;
         for (int i = 0; i < answer_count; ++i) {
            if (A == ntohs(answers[i].resource->type)) {  // IPv6 address
                              //  answers[i].rdata;
                    //char v6_ip[64] = {0};
		//inet_ntop(AF_INET6, &v6_addr, v6_ip, sizeof(v6_ip));
		//_nat64_v6_ip = std::string(v6_ip);
              std::string v4_addr;
              for(int p=0;p<4;p++)
            { _ipinfo->v4_addr[_ipinfo->size].s_addr=*answers[i].rdata; 
              printf("%d",answers[i].rdata[p]);
               if(p<3) printf(".");
               //v6_addr+=atoi(answers[i].rdata[p];
            }
            printf("\n");
               // _ipinfo->v6_addr[_ipinfo->size].s6_addr = (*p);  // working without ntohl
                _ipinfo->size++;
            }
        }

        if (0 >= _ipinfo->size) {  // unkown host, dns->rcode == 3
           
            break;
        }

        //      _ipinfo->dns = ;
        ret = 0;
    } while (false);

    FreeAll(answers);
    close(sockfd);
  
    return ret;  //* 查询DNS服务器超时
}
void socket_gethostbyname(const char* _host, socket_ipinfo_t* _ipinfo, int _timeout /*ms*/, const char* _dnsserver)
{  checknetfamily();
    if(net_family==2) { 
     
     socketv6_gethostbyname(_host,  _ipinfo,  _timeout /*ms*/,  _dnsserver);
   }
  else
   socketv4_gethostbyname( _host,  _ipinfo,  _timeout /*ms*/,  _dnsserver);
}
bool isValidIpAddress(const char* _ipaddress) {
    if(ipv4){
    struct sockaddr_in sa;
    int result =inet_pton(AF_INET, _ipaddress, (void*) & (sa.sin_addr));
    return result != 0;}
  else {
    struct sockaddr_in6 sa;
    int result =inet_pton(AF_INET6, _ipaddress, (void*) & (sa.sin6_addr));
    return result != 0;}
}

void FreeAll(struct RES_RECORD* _answers) {
    int i;

    for (i = 0; i < SOCKET_MAX_IP_COUNT; i++) {
        if (_answers[i].name != NULL)
            free(_answers[i].name);

        if (_answers[i].rdata != NULL)
            free(_answers[i].rdata);
    }
}

void ReadRecvAnswer(unsigned char* _buf, struct DNS_HEADER* _dns, unsigned char* _reader, struct RES_RECORD* _answers) {
    // reading answers
    int i, j, stop = 0;
    int answer_count = std::min(SOCKET_MAX_IP_COUNT, (int)ntohs(_dns->ans_count));

    for (i = 0; i < answer_count; i++) {
        _answers[i].name = ReadName(_reader, _buf, &stop);
        _reader = _reader + stop;

        _answers[i].resource = (struct R_DATA*)(_reader);
        _reader = _reader + sizeof(struct R_DATA);//指针偏移

       if(ipv4)// if (ntohs(_answers[i].resource->type) == 1) {  // if its an ipv4 address
     { 
      if (ntohs(_answers[i].resource->type) == A) {  // if its an ipv6 address
           _answers[i].rdata = (unsigned char*)malloc(ntohs(_answers[i].resource->data_len));
          
            if (NULL == _answers[i].rdata) 
            {
                return;
            }

            for (j = 0 ; j < ntohs(_answers[i].resource->data_len) ; j++)
                { _answers[i].rdata[j] = _reader[j];
                  printf("%d ",_reader[j]);
             }
              printf("\n");
            _answers[i].rdata[ntohs(_answers[i].resource->data_len)] = '\0';
            _reader = _reader + ntohs(_answers[i].resource->data_len);
        } else {
            _answers[i].rdata = ReadName(_reader, _buf, &stop);
            _reader = _reader + stop;
        }
     }
    else {   

      if (ntohs(_answers[i].resource->type) == AAAA) {  // if its an ipv6 address
           _answers[i].rdata = (unsigned char*)malloc(ntohs(_answers[i].resource->data_len));
          
            if (NULL == _answers[i].rdata) 
            {
                return;
            }

            for (j = 0 ; j < ntohs(_answers[i].resource->data_len) ; j++)
                { _answers[i].rdata[j] = _reader[j];
                  printf("%02x ",_reader[j]);
             }
              printf("\n");
            _answers[i].rdata[ntohs(_answers[i].resource->data_len)] = '\0';
            _reader = _reader + ntohs(_answers[i].resource->data_len);
        } else {
            _answers[i].rdata = ReadName(_reader, _buf, &stop);
            _reader = _reader + stop;
        }
   } 
    }
}

unsigned char* ReadName(unsigned char* _reader, unsigned char* _buffer, int* _count) {
    unsigned char* name;
    unsigned int p = 0, jumped = 0, offset;
    const unsigned int INIT_SIZE = 256, INCREMENT = 64;
    int timesForRealloc = 0;
    int i , j;

    *_count = 1;
    name   = (unsigned char*)malloc(INIT_SIZE);

    if (NULL == name) {
        
        return NULL;
    }

    name[0] = '\0';

    // read the names in 3www6google3com format
    while (*_reader != 0) {
        if (*_reader >= 192) {  // 192 = 11000000 ,如果该字节前两位bit为11，则表示使用的是地址偏移来表示name
            offset = (*_reader) * 256 + *(_reader + 1) - 49152;  // 49152 = 11000000 00000000  计算相对于报文起始地址的偏移字节数，即去除两位为11的bit，剩下的14位表示的值
            _reader = _buffer + offset - 1;
            jumped = 1;  // we have jumped to another location so counting wont go up!
        } else
            name[p++] = *_reader;

        _reader = _reader + 1;

        if (jumped == 0) *_count = *_count + 1;  // if we have not jumped to another location then we can count up

        if (*_count >= (int)(INIT_SIZE + INCREMENT * timesForRealloc)) {
            timesForRealloc++;

            unsigned char* more_name = NULL;
            more_name = (unsigned char*)realloc(name, (INIT_SIZE + INCREMENT * timesForRealloc));

            if (NULL == more_name) {
             
                free(name);
                return NULL;
            }

            name = more_name;
        }
    }

    name[p] = '\0';  // string complete

    if (jumped == 1) *_count = *_count + 1;  // number of steps we actually moved forward in the packet

    // now convert 3www6google3com0 to www.google.com
    for (i = 0; i < (int)strlen((const char*)name); i++) {
        p = name[i];

        for (j = 0; j < (int)p; j++) {
            name[i] = name[i + 1];
            i = i + 1;
        }

        name[i] = '.';
    }

    name[i - 1] = '\0';  // remove the last dot
    return name;
}

// this will convert www.google.com to 3www6google3com
void ChangetoDnsNameFormat(unsigned char* _qname, std::string _hostname) {
    int lock = 0 , i;
    _hostname.append(".");
    const char* host = _hostname.c_str();

    for (i = 0; i < (int)strlen(host); i++) {
        if (host[i] == '.') {
            *_qname++ = i - lock;

            for (; lock < i; lock++) {
                *_qname++ = host[lock];
            }

            lock++;
        }
    }

    *_qname++ = '\0';
}

void PrepareDnsQueryPacket(unsigned char* _buf, struct DNS_HEADER* _dns, unsigned char* _qname, const std::string& _host) {
    struct QUESTION*  qinfo = NULL;
    // Set the DNS structure to standard queries
    _dns->id = getpid();
    _dns->qr = 0;      // This is a query
    _dns->opcode = 0;  // This is a standard query
    _dns->aa = 0;      // Not Authoritative
    _dns->tc = 0;      // This message is not truncated
    _dns->rd = 1;      // Recursion Desired
    _dns->ra = 0;      // Recursion not available!
    _dns->z  = 0;
    _dns->ad = 0;
    _dns->cd = 0;
    _dns->rcode = 0;
    _dns->q_count = htons(1);   // we have only 1 question
    _dns->ans_count  = 0;
    _dns->auth_count = 0;
    _dns->add_count  = 0;
    // point to the query portion
    _qname = (unsigned char*)&_buf[sizeof(struct DNS_HEADER)];
    ChangetoDnsNameFormat(_qname, _host);  // 将传入的域名host转换为标准的DNS报文可用的格式，存入qname中
    qinfo = (struct QUESTION*)&_buf[sizeof(struct DNS_HEADER) + (strlen((const char*)_qname) + 1)];  // fill it

    //qinfo->qtype = htons(0x1c);  //只查询 ipv4 address
   if(ipv4) qinfo->qtype = htons(A);
else
    qinfo->qtype = htons(AAAA);  //查询 ipv6 address
    qinfo->qclass = htons(1);  // its internet
}

int RecvWithinTime(int _fd, char* _buf, size_t _buf_n, struct sockaddr* _addr, socklen_t* _len, unsigned int _sec, unsigned _usec) {
    struct timeval tv;
    fd_set readfds, exceptfds;
    int n = 0;

    FD_ZERO(&readfds);
    FD_SET(_fd, &readfds);
    FD_ZERO(&exceptfds);
    FD_SET(_fd, &exceptfds);

    tv.tv_sec = _sec;
    tv.tv_usec = _usec;

    int ret = -1;
label:
    ret = select(_fd + 1, &readfds, NULL, &exceptfds, &tv);

    if (-1 == ret) {
        if (EINTR == errno) {
            // select被信号中断 handler
            FD_ZERO(&readfds);
            FD_SET(_fd, &readfds);
            FD_ZERO(&exceptfds);
            FD_SET(_fd, &exceptfds);
            goto label;
        }
    }

    if (FD_ISSET(_fd, &exceptfds)) {
        // socket异常处理
        return -1;
    }

    if (FD_ISSET(_fd, &readfds)) {
        if ((n = (int)recvfrom(_fd, _buf, _buf_n, 0, _addr, _len)) >= 0) {
            return n;
        }
    }

    return -1;  // 超时或者select失败
}

#ifdef ANDROID

#include <sys/system_properties.h>
void GetHostDnsServerIP(std::vector<std::string>& _dns_servers) {
    char buf1[PROP_VALUE_MAX];
    char buf2[PROP_VALUE_MAX];
    __system_property_get("net.dns1", buf1);
    __system_property_get("net.dns2", buf2);
    _dns_servers.push_back(std::string(buf1));  // 主DNS
    _dns_servers.push_back(std::string(buf2));  // 备DNS

}

#elif defined __APPLE__ 
#include <TargetConditionals.h>
#include <resolv.h>
#define RESOLV_CONFIG_PATH ("/etc/resolv.conf")
#if TARGET_OS_IPHONE
void GetHostDnsServerIP(std::vector<std::string>& _dns_servers) {
	_dns_servers.clear();
    std::ifstream fin(RESOLV_CONFIG_PATH);

    const int LINE_LENGTH = 256;
    char str[LINE_LENGTH];

    if (fin.good()) {
        while (!fin.eof()) {
            if (fin.getline(str, LINE_LENGTH).good()) {
                std::string s(str);
                int num = (int)s.find(NAME_SVR, 0);

                if (num >= 0) {
                    s.erase(std::remove_if(s.begin(), s.end(), isspace), s.end());
                    s = s.erase(0, NAME_SVR_LEN);
                    _dns_servers.push_back(s);
                }
            } else {
                break;
            }
        }
    } else {
        //  /etc/resolv.conf 不存在
        struct __res_state stat = {0};
        res_ninit(&stat);

//        if (stat.nsaddr_list != 0) {
            struct sockaddr_in nsaddr;

            for (int i = 0; i < stat.nscount; i++) {
                nsaddr = stat.nsaddr_list[i];
                const char* nsIP = socket_address(nsaddr).ip();

                if (NULL != nsIP)
                	_dns_servers.push_back(std::string(nsIP));
            }
//        }

        res_ndestroy(&stat);
    }
}
#else
void GetHostDnsServerIP(std::vector<std::string>& _dns_servers)
{
    //EMPTY FOR MAC
}
#endif //endif TARGET_OS_IPHONE
#elif defined WP8
void GetHostDnsServerIP(std::vector<std::string>& _dns_servers) {
}
#elif defined _WIN32
#include <stdio.h>
#include <windows.h>
#include <Iphlpapi.h>

#pragma comment(lib, "Iphlpapi.lib")

void GetHostDnsServerIP(std::vector<std::string>& _dns_servers) {
    FIXED_INFO fi;
    ULONG ulOutBufLen = sizeof(fi);

    if (::GetNetworkParams(&fi, &ulOutBufLen) != ERROR_SUCCESS) {

        return;
    }

    IP_ADDR_STRING* pIPAddr = fi.DnsServerList.Next;

    while (pIPAddr != NULL) {
    	_dns_servers.push_back(pIPAddr->IpAddress.String);
        pIPAddr = pIPAddr->Next;
    }

    return;
}
#else

void GetHostDnsServerIP(std::vector<std::string>& _dns_servers) {
}

#endif

