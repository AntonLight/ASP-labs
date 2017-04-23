#pragma once

#include "stdafx.h"
#include "Shell.hpp"

#pragma comment(lib,"ws2_32.lib")

class Server {
public:
	Server(bool should_run = true) : should_run(should_run) {
		if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) die(L"Can't init Winsock");
		if ((master = socket(AF_UNSPEC, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET) die(L"Can't create socket");
	}

	~Server() {
		closesocket(master);
		WSACleanup();
	}

	void set_up() {
		struct sockaddr_in server = {
			AF_INET,			    //sin_family
			htons(31337),           //sin_port
			inet_addr("0.0.0.0"),   //sin_addr
			{ 0 }					//sin_zero
		};

		if ((bind(master, (struct sockaddr *)&server, sizeof(server))) == SOCKET_ERROR) die(L"bind failed");
		if (listen(master, 3) != 0) die(L"listen failed");
	}

	void disable() {
		should_run = false;
	}

	void enable() {
		should_run = true;
	}

	void run() {
		while (should_run) {
			struct sockaddr_in client;
			int len = sizeof(client);
			SOCKET s_client = accept(master, (struct sockaddr *)&client, &len);
			if (s_client == INVALID_SOCKET) die(L"Something wrong with the client accepting ");
			Info info = {s_client, this->shell};
			auto reader = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Server::read, (LPVOID)&info, 0, 0);
			write(info);
			WaitForSingleObject(reader, INFINITE);
			closesocket(s_client);
		}
	}
private:
	WSADATA wsa;
	SOCKET master;
	Shell shell;
	bool should_run;

	struct Info {
		SOCKET s;
		Shell shell;
	};

	static DWORD read(Info *info) {
		while (1) {
			char buf;
			const size_t len = sizeof(buf);
			if (info->shell.read(&buf, len) != len) break;
			if (send(info->s, &buf, len, 0) != len) break;
		}
		return 0;
	}

	static DWORD write(Info &info) {
		while (1) {
			char buf;
			const size_t len = recv(info.s, &buf, sizeof(buf), 0);
			if (len == SOCKET_ERROR) die(L"recv failed");
			if (len == 0) break;
			if (len != info.shell.write(&buf, len)) break;
		}
		return 0;
	}
};