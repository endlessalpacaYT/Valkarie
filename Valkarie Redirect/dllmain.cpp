#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <wchar.h>
#include <stdio.h>
#include <string.h>
#include "MinHook.h"

#pragma comment(lib, "Ws2_32.lib")

typedef int (WINAPI* connect_t)(SOCKET s, const struct sockaddr* name, int namelen);
typedef int (WINAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int (WINAPI* recv_t)(SOCKET s, char* buf, int len, int flags);
connect_t original_connect = NULL;
send_t original_send = NULL;
recv_t original_recv = NULL;

// Settings!
const char* redirect_ip = "127.0.0.1";
int redirect_port = 3551;
bool use_https = false;

void construct_redirect_url(char* buffer, size_t size) {
    const char* protocol = use_https ? "https" : "http";
    snprintf(buffer, size, "%s://%s:%d", protocol, redirect_ip, redirect_port);
}

int WINAPI hooked_connect(SOCKET s, const struct sockaddr* name, int namelen)
{
    if (name->sa_family == AF_INET)
    {
        const sockaddr_in* sockaddr_ipv4 = (const sockaddr_in*)name;

        char original_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(sockaddr_ipv4->sin_addr), original_ip, INET_ADDRSTRLEN);
        int original_port = ntohs(sockaddr_ipv4->sin_port);

        printf("Original connection attempt from %s:%d\n", original_ip, original_port);

        if (strcmp(original_ip, "127.0.0.1") == 0 || strcmp(original_ip, "0.0.0.0") == 0) {
            return original_connect(s, name, namelen);
        }

        sockaddr_in* mod_sockaddr_ipv4 = (sockaddr_in*)name;
        inet_pton(AF_INET, redirect_ip, &mod_sockaddr_ipv4->sin_addr);
        mod_sockaddr_ipv4->sin_port = htons(redirect_port);

        char redirect_url[256];
        construct_redirect_url(redirect_url, sizeof(redirect_url));
        printf("Redirecting connection to %s\n", redirect_url);
    }

    return original_connect(s, name, namelen);
}

int WINAPI hooked_send(SOCKET s, const char* buf, int len, int flags)
{
    printf("Sending %d bytes of data.\n", len);
    return original_send(s, buf, len, flags);
}

void log_received_data(const char* buf, int bytes_received) {
    printf("Received %d bytes of data: ", bytes_received);
    for (int i = 0; i < bytes_received; i++) {
        printf("%02X ", (unsigned char)buf[i]);
    }
    printf("\n");

    printf("Received Data (String): ");
    for (int i = 0; i < bytes_received; i++) {
        if (buf[i] >= 32 && buf[i] < 127) { 
            putchar(buf[i]);
        }
        else {
            putchar('.'); 
        }
    }
    printf("\n");
}

int WINAPI hooked_recv(SOCKET s, char* buf, int len, int flags)
{
    int bytes_received = original_recv(s, buf, len, flags);

    if (bytes_received > 0) {
        log_received_data(buf, bytes_received);
    }

    return bytes_received;
}

DWORD WINAPI MainThread(LPVOID param)
{
    AllocConsole();
    FILE* f_out;
    FILE* f_err;

    freopen_s(&f_out, "CONOUT$", "w", stdout);
    freopen_s(&f_err, "CONOUT$", "w", stderr);

    printf("Console allocated for logging...\n");

    if (MH_Initialize() != MH_OK)
    {
        printf("Failed to initialize MinHook!\n");
        return 1;
    }

    if (MH_CreateHookApi(L"ws2_32", "connect", &hooked_connect, reinterpret_cast<LPVOID*>(&original_connect)) != MH_OK)
    {
        printf("Failed to hook connect function!\n");
        return 1;
    }

    if (MH_CreateHookApi(L"ws2_32", "send", &hooked_send, reinterpret_cast<LPVOID*>(&original_send)) != MH_OK)
    {
        printf("Failed to hook send function!\n");
        return 1;
    }

    if (MH_CreateHookApi(L"ws2_32", "recv", &hooked_recv, reinterpret_cast<LPVOID*>(&original_recv)) != MH_OK)
    {
        printf("Failed to hook recv function!\n");
        return 1;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        printf("Failed to enable hook!\n");
        return 1;
    }

    printf("Valkarie Successfully Hooked!\n");

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        break;
    }
    return TRUE;
}