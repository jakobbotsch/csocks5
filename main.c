#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

const char* s_username = "username";
const char* s_password = "password";

int ReceiveFull(int socket, void* buffer, size_t len)
{
    size_t received = 0;

    while (received < len)
    {
        ssize_t receivedNow = recv(socket, &((uint8_t*)buffer)[received], len - received, 0);
        if (receivedNow == 0 || receivedNow == -1)
            return 0;

        received += receivedNow;
    }

    return 1;
}

int SendFull(int socket, void* buffer, size_t len)
{
    size_t sent = 0;
    while (sent < len)
    {
        ssize_t sentNow = send(socket, &((uint8_t*)buffer)[sent], len - sent, 0);
        if (sentNow == -1)
            return 0;

        sent += sentNow;
    }

    return 1;
}

int ReceiveString(int socket, char* str)
{
    uint8_t len;
    if (!ReceiveFull(socket, &len, 1))
        return 0;

    if (!ReceiveFull(socket, str, len))
        return 0;

    str[len] = '\0';
    return 1;
}

void PrintSocketAddress(struct sockaddr_storage* addr)
{
    if (addr->ss_family == AF_INET)
    {
        char str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &((struct sockaddr_in*)addr)->sin_addr, str, INET_ADDRSTRLEN);
        printf("%s:%u", str, ntohs(((struct sockaddr_in*)addr)->sin_port));
    }
    else if (addr->ss_family == AF_INET6)
    {
        char str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &((struct sockaddr_in6*)addr)->sin6_addr, str, INET6_ADDRSTRLEN);
        printf("%s:%u", str, ntohs(((struct sockaddr_in6*)addr)->sin6_port));
    }
    else
        printf("[unknown socket address]");
}

int FillSocketAddress(int client, struct sockaddr_storage* target, uint8_t kind)
{
    if (kind == 1)
    {
        struct sockaddr_in* in = (struct sockaddr_in*)target;
        in->sin_family = AF_INET;
        if (!ReceiveFull(client, &in->sin_addr.s_addr, 4))
        {
            printf("Could not receive IPv4 address\n");
            return 0;
        }

        if (!ReceiveFull(client, &in->sin_port, 2))
        {
            printf("Could not receive IPv4 port\n");
            return 0;
        }

        return 1;
    }
    
    if (kind == 4)
    {
        struct sockaddr_in6* in6 = (struct sockaddr_in6*)target;
        in6->sin6_family = AF_INET6;
        if (!ReceiveFull(client, &in6->sin6_addr.s6_addr, 16))
        {
            printf("Could not receive IPv6 address\n");
            return 0;
        }

        if (!ReceiveFull(client, &in6->sin6_port, 2))
        {
            printf("Could not receive IPv6 port\n");
            return 0;
        }

        return 1;
    }

    if (kind == 3)
    {
        char domainName[256];
        if (!ReceiveString(client, domainName))
        {
            printf("Could not receive domain name\n");
            return 0;
        }
        printf("Received domain name %s\n", domainName);

        struct addrinfo hints = {0};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo* res;
        int status = getaddrinfo(domainName, 0, &hints, &res) != 0;
        if (status != 0)
        {
            printf("getaddrinfo returned %d\n", status);
            return 0;
        }

        void* pport;
        if (res->ai_family == AF_INET)
        {
            memcpy(target, res->ai_addr, sizeof(struct sockaddr_in));
            pport = &((struct sockaddr_in*)target)->sin_port;
        }
        else if (res->ai_family == AF_INET6)
        {
            memcpy(target, res->ai_addr, sizeof(struct sockaddr_in6));
            pport = &((struct sockaddr_in6*)target)->sin6_port;
        }
        else
        {
            printf("Unknown address family %d\n", res->ai_family);
            return 0;
        }

        if (!ReceiveFull(client, pport, 2))
        {
            printf("Could not receive domain name port\n");
            return 0;
        }

        return 1;
    }

    printf("Invalid connect address kind %d\n", kind);
    return 0;
}

int Forward(int source, int destination)
{
    uint8_t data[4096];
    ssize_t received = recv(source, data, sizeof(data), 0);
    if (received <= 0)
        return 0;

    return SendFull(destination, data, (size_t)received);
}

void HandleClient(int client, struct sockaddr_storage clientLocalAddr)
{
    uint8_t header[2];
    if (!ReceiveFull(client, header, 2))
    {
        printf("Could not receive header\n");
        return;
    }

    // Verify Socks5
    if (header[0] != 5)
    {
        printf("Header is not SOCKS5\n");
        return;
    }

    uint8_t methods[256];
    if (!ReceiveFull(client, methods, header[1]))
    {
        printf("Could not receive methods\n");
        return;
    }

    // Verify username/password
    int found = 0;
    for (int i = 0; i < header[1]; i++)
    {
        if (methods[i] != 2)
            continue;

        found = 1;
        break;
    }

    if (!found)
    {
        printf("No user/pass auth. Methods:");
        for (int i = 0; i < header[1]; i++)
            printf(" %d", methods[i]);
        printf("\n");
        return;
    }

    uint8_t headerResp[2] = {5, 2};
    if (!SendFull(client, headerResp, 2))
    {
        printf("Could not send response header\n");
        return;
    }

    uint8_t unPassVer = 1;
    if (!ReceiveFull(client, &unPassVer, 1) || unPassVer != 1)
    {
        printf("Could not receive user/pass version, or wrong version specified (%d)\n", unPassVer);
        return;
    }

    char username[256];
    if (!ReceiveString(client, username))
    {
        printf("Could not receive username\n");
        return;
    }

    char password[256];
    if (!ReceiveString(client, password))
    {
        printf("Could not receive password\n");
        return;
    }

    int isValid = strcmp(username, s_username) == 0 && strcmp(password, s_password) == 0;

    uint8_t response[2] = {1, (uint8_t)(isValid ? 0 : 1)};
    if (!SendFull(client, response, 2) || !isValid)
    {
        printf("Could not send auth result, or auth failed. Username: %s, password: %s\n", username, password);
        return;
    }

    uint8_t reqHeader[4];
    if (!ReceiveFull(client, reqHeader, 4))
    {
        printf("Could not receive request header\n");
        return;
    }

    if (reqHeader[0] != 5 || reqHeader[1] != 1)
    {
        printf("Wrong request header\n");
        return;
    }

    struct sockaddr_storage targetAddr = {0};
    if (!FillSocketAddress(client, &targetAddr, reqHeader[3]))
        return;

    int target = socket(PF_INET, SOCK_STREAM, 0);
    if (target == -1)
    {
        printf("Could not receive target socket\n");
        return;
    }

    struct sockaddr_storage localAddr = {0};
    socklen_t localLen = sizeof(localAddr);
    if (getsockname(client, (struct sockaddr*)&localAddr, &localLen) != 0)
    {
        printf("getsockname 1 returned %d\n", errno);
        goto done;
    }

    // Bind to IP client connected to, so we get same outgoing IP
    if (localAddr.ss_family == AF_INET)
        ((struct sockaddr_in*)&localAddr)->sin_port = 0;
    else if (localAddr.ss_family == AF_INET6)
        ((struct sockaddr_in6*)&localAddr)->sin6_port = 0;
    else
    {
        printf("Unknown family %d\n", localAddr.ss_family);
        goto done;
    }

    if (bind(target, (struct sockaddr*)&localAddr, sizeof(localAddr)) != 0)
    {
        printf("Could not bind target socket: %d\n", errno);
        goto done;
    }

    if (connect(target, (struct sockaddr*)&targetAddr, sizeof(targetAddr)) != 0)
        goto done;

    int flag = 1;
    if (setsockopt(target, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) != 0)
        goto done;

    memset(&localAddr, 0, sizeof(localAddr));
    localLen = sizeof(localAddr);
    if (getsockname(target, (struct sockaddr*)&localAddr, &localLen) != 0)
    {
        printf("getsockname 2 returned %d\n", errno);
        goto done;
    }

    if (localAddr.ss_family != AF_INET && localAddr.ss_family != AF_INET6)
    {
        printf("Invalid local address kind %d\n", localAddr.ss_family);
        goto done;
    }

    uint8_t connectRespHeader[4] = {5, 0, 0, (uint8_t)(localAddr.ss_family == AF_INET ? 1 : 4)};
    if (!SendFull(client, connectRespHeader, 4))
    {
        printf("Could not send connect response header\n");
        goto done;
    }

    void* pport;
    if (localAddr.ss_family == AF_INET)
    {
        if (!SendFull(client, &((struct sockaddr_in*)&localAddr)->sin_addr.s_addr, 4))
        {
            printf("Could not send IPv4 response\n");
            goto done;
        }

        pport = &((struct sockaddr_in*)&localAddr)->sin_port;
    }
    else
    {
        if (!SendFull(client, &((struct sockaddr_in6*)&localAddr)->sin6_addr.s6_addr, 16))
        {
            printf("Could not send IPv6 response\n");
            goto done;
        }

        pport = &((struct sockaddr_in6*)&localAddr)->sin6_port;
    }

    if (!SendFull(client, pport, 2))
    {
        printf("Could not send port response\n");
        goto done;
    }

    while (1)
    {
        fd_set readfs = {0};
        FD_ZERO(&readfs);
        FD_SET(target, &readfs);
        FD_SET(client, &readfs);

        struct timeval tv = {0};
        tv.tv_sec = 5;
        tv.tv_usec = 0;

        if (select((target > client ? target : client) + 1, &readfs, 0, 0, &tv) == -1)
        {
            printf("Select returned %d\n", errno);
            goto done;
        }

        if (FD_ISSET(target, &readfs))
        {
            if (!Forward(target, client))
                goto done;
        }

        if (FD_ISSET(client, &readfs))
        {
            if (!Forward(client, target))
                goto done;
        }
    }

done:
    close(target);
}

struct ClientInfo
{
    int Socket;
    struct sockaddr_storage LocalAddress;
};

void* ThreadMain(void* arg)
{
    pthread_detach(pthread_self());

    struct ClientInfo* pCliInfo = arg;
    int client = pCliInfo->Socket;
    struct sockaddr_storage localAddr = pCliInfo->LocalAddress;
    free(arg);

    static pthread_mutex_t countMutex;
    pthread_mutex_lock(&countMutex);

    static size_t s_numClients;
    s_numClients++;

    printf("Client connected: ");
    PrintSocketAddress(&localAddr);
    printf(". %zu clients connected.\n", s_numClients);

    pthread_mutex_unlock(&countMutex);

    HandleClient(client, localAddr);

    close(client);

    pthread_mutex_lock(&countMutex);
    s_numClients--;

    printf("RIP client ");
    PrintSocketAddress(&localAddr);
    printf(". %zu clients connected.\n", s_numClients);

    pthread_mutex_unlock(&countMutex);
    return 0;
}

int main()
{
    int server = socket(PF_INET, SOCK_STREAM, 0);
    if (server == -1)
    {
        printf("Could not create server socket: %d\n", errno);
        return 1;
    }

    int retVal = 0;

    int enable = 1;
    if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0)
    {
        printf("Could not set SO_REUSEADDR: %d\n", errno);
        retVal = 2;
        goto end;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(2191);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server, (struct sockaddr*)&addr, sizeof(addr)) != 0)
    {
        printf("Could not bind: %d\n", errno);
        retVal = 3;
        goto end;
    }

    if (listen(server, 20) != 0)
    {
        printf("Could not listen: %d\n", errno);
        retVal = 4;
        goto end;
    }

    while (1)
    {
        struct sockaddr_storage theirAddr = {0};
        socklen_t len = sizeof(theirAddr);
        int client = accept(server, (struct sockaddr*)&theirAddr, &len);
        if (client == -1)
        {
            printf("Accept returned %d\n", errno);
            continue;
        }

        struct ClientInfo* pCliInfo = malloc(sizeof(struct ClientInfo));
        pCliInfo->Socket = client;
        pCliInfo->LocalAddress = theirAddr;
        pthread_t t;
        if (pthread_create(&t, 0, &ThreadMain, pCliInfo) != 0)
        {
            printf("pthread_create returned %d\n", errno);
            break;
        }
    }
end:
    close(server);
    return retVal;
}
