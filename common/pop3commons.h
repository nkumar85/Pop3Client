#ifndef __POP3__COMMON__H
#define __POP3__COMMON__H

//Standard library headers
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdarg.h>
#include<stdlib.h>
#include<stdint.h>
#include<time.h>
#include<limits.h>

//Socket+File includes
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<sys/socket.h>
#include<netdb.h>
#include<sys/select.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<arpa/inet.h>

//CPP Includes
#include<iostream>
#include<map>
#include<vector>
#include<sstream>

using namespace std;

typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;

#define UCHAR UINT8
#define UINT UINT32

#endif
