
/* 
 * ===================================================================================== 
 * 
 *       Filename:  dnsquery.h 
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
#ifndef DNSQUERY_H_
#define DNSQUERY_H_

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include<netdb.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <algorithm>
#include <errno.h>
#include <iostream>
using namespace std;

#ifdef __cplusplus
extern "C"{
#endif
/**
 *函数名:    socket_gethostbyname
 *功能: 输入域名，可得到该域名下所对应的IP地址列表
 *输入:       _host：输入的要查询的主机域名
 *输入:       _timeout：设置查询超时时间，单位为毫秒
 *输入:       _dnsserver 指定的dns服务器的IP
 *输出:		 _ipinfo为要输出的ip信息结构体
 *返回值:		  当返回-1表示查询失败，当返回0则表示查询成功
 *
 */
#define SOCKET_MAX_IP_COUNT (20)

struct socket_ipinfo_t
{
    int  size;

    struct  in6_addr v6_addr[SOCKET_MAX_IP_COUNT];
    struct  in_addr v4_addr[SOCKET_MAX_IP_COUNT];
};
bool checknetfamily();
int socketv4_gethostbyname(const char* _host, struct socket_ipinfo_t* _ipinfo, int _timeout /*ms*/, const char* _dnsserver);
int socketv6_gethostbyname(const char* _host, struct socket_ipinfo_t* _ipinfo, int _timeout /*ms*/, const char* _dnsserver);
void socket_gethostbyname(const char* _host, socket_ipinfo_t* _ipinfo, int _timeout /*ms*/, const char* _dnsserver);
#ifdef __cplusplus
}



#endif

#endif 


