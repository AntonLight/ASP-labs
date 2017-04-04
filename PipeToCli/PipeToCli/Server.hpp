#pragma once

#include "stdafx.h"
#include <functional>

#pragma comment(lib,"ws2_32.lib")

class Server {
public:
	Server() {
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) die(L"Can't init Winsock");
		if ((master = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) die(L"Can't create socket");
	}
	~Server() {
		closesocket(master);
		WSACleanup();
	}
	void set_up() {
		struct sockaddr_in server = {
			AF_INET,			  //sin_family
			htons(1337),          //sin_port
			inet_addr("0.0.0.0"), //sin_addr
			{ 0 }					  //sin_zero
		};

		if ((bind(master, (struct sockaddr *)&server, sizeof(server))) == SOCKET_ERROR) die(L"bind failed");
		if (listen(master, 3) != 0) die(L"listen failed");
	}
	void handle(std::function<void(SOCKET)> handler) {
		while (1) {
			struct sockaddr_in client;
			int len = sizeof(client);
			SOCKET s_client = accept(master, (struct sockaddr *)&client, &len);
			if (s_client == INVALID_SOCKET) die(L"Something wrong with the client accepting ");
			handler(s_client);
			closesocket(s_client);
		}
	}
private:
	WSADATA wsa;
	SOCKET master;
};