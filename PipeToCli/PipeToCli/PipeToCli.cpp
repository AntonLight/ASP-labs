// PipeToCli.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <locale>
#include <codecvt>
#include <vector>
#include <wchar.h>
#include "Piper.hpp"
#include "Shell.hpp"
#include "Server.hpp"
#include "lib.h"

constexpr auto pipe_name = L"\\\\.\\pipe\\serv";
constexpr auto buff_size = 1024L;

void init_threads() {
	TP_CALLBACK_ENVIRON env;

	InitializeThreadpoolEnvironment(&env);

	auto pool = CreateThreadpool(NULL);
	if (pool == NULL) die(L"CreateThreadpool failed");
	SetThreadpoolThreadMaximum(pool, 5);

	PTP_CLEANUP_GROUP cleanup = CreateThreadpoolCleanupGroup();
	if (cleanup == NULL) die(L"CreateThreadpoolCleanupGroup failed");

	//PTP_WORK work = CreateThreadpoolWork;
}

std::string exec(const char* cmd) {
	char buffer[128];
	std::string result;
	FILE* pipe = _popen(cmd, "r");
	if (!pipe) die(L"popen() failed!");
	SetConsoleOutputCP(65001);
	while (!feof(pipe)) {
		if (fgets(buffer, 128, pipe) != 0)
			result.append(buffer);
	}
	_pclose(pipe);
	return result;
}

void trim(char *buf, size_t len) {
	buf[len - 1] = '\0';
	int i = len - 1;
	while (i > 1 && strchr("\n\t\0", buf[i - 1])) i--;
	buf[i + 1] = '\0';
}

int main() {
	//Shell shell;
	Server s;
	s.set_up();
	s.handle([/*&shell*/](SOCKET s) {
		char buf[buff_size];
		auto len = recv(s, buf, buff_size, 0);
		trim(buf, len);
		auto res = exec(buf);
		send(s, res.c_str(), res.size(), 0);
	});
    return 0;
}

