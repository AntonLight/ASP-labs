// SockClient.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include "../PipeToCli/lib.h"

#pragma comment(lib,"ws2_32.lib")

void read(SOCKET s) {
	DWORD len;
	char buf;
	auto h = GetStdHandle(STD_OUTPUT_HANDLE);
	while (0 != (len = recv(s, &buf, sizeof(buf), 0))) {
		WriteFile(h, &buf, len, &len, NULL);
	}
}

int main() {
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) die(L"Can't init Winsock");
	SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	sockaddr_in server = {
		AF_INET,		 //sin_family
		htons(31337),    //sin_port
		0,               //sin_addr
		{ 0 }			 //sin_zero
	};
	server.sin_addr.s_addr = inet_addr("10.0.2.15");
	
	if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0)
		die(L"connect failed");

	auto h = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)read, (LPVOID)sock, 0, 0);
	auto in = GetStdHandle(STD_INPUT_HANDLE);
	char buf;
	DWORD len;
	while (1) {
		buf = getc(stdin);
		auto res = send(sock, &buf, 1, 0);
		if (!res) break;
	}
	WaitForSingleObject(h, INFINITE);
	closesocket(sock);
	WSACleanup();
    return 0;
}

