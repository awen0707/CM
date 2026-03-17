#ifndef CMA_CONNECT_CLIENT_H
#define CMA_CONNECT_CLIENT_H

#include <sys/un.h>

#define AGENT_INVALID_SOCKET (-1)
#define MAX_EVENTS 512
#define MAX_CONNECTIONS 10
#define EPOLL_WAIT_TIMEOUT 5000
#define DOMAIN_SOCKET_PERMISSION 0600

typedef struct DomainsSocketAddrSt {
    struct sockaddr_un addr;
    socklen_t addrLen;
} DomainsSocketAddr;

typedef struct ListenPortSt {
    int sock;
    DomainsSocketAddr addr;
} ListenPort;

typedef struct ClientConnSt {
    int sock;
    timespec recvTime;
    char resName[CM_MAX_RES_NAME];
    volatile bool isClosed;
    DomainsSocketAddr addr;
    uint32 cmInstanceId;
    uint32 resInstanceId;
} ClientConn;

ClientConn *GetClientConnect();
void *RecvClientEventsMain(void * const arg);
void *SendMessageToClientMain(void * const arg);
void *ProcessMessageMain(void * const arg);

#endif // CMA_CONNECT_CLIENT_H
