#pragma once

#include <stdio.h>

class Shell {
public:
	Shell() {
		SECURITY_ATTRIBUTES sa;
		sa.nLength = sizeof(sa);
		sa.bInheritHandle = TRUE;
		sa.lpSecurityDescriptor = NULL;

		if (!CreatePipe(&out_r, &out_w, &sa, 0) || 
			!CreatePipe(&in_r, &in_w, &sa, 0)) die(L"Can't initialize I/O pipes");

		COMMTIMEOUTS timeout = {0,0,1000,0,1000};
		SetCommTimeouts(in_w, &timeout);
		SetCommTimeouts(out_r, &timeout);

		PROCESS_INFORMATION pi = { 0 };
		STARTUPINFO si = { 0 };

		si.cb = sizeof(si);
		si.hStdOutput = si.hStdError = out_w;
		si.hStdInput = in_r;
		si.dwFlags |= STARTF_USESTDHANDLES;

		LPTSTR cmd = _tcsdup(L"cmd"); // http://stackoverflow.com/questions/10044230/unhandled-error-with-createprocess
									  // f4k u m$
		if (!CreateProcess(NULL, cmd, NULL, 
			NULL, TRUE, NULL,
			NULL, NULL, &si, &pi)) die(L"Can't start command terminal");

		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		CloseHandle(out_w); // no need to write for child stdout
		CloseHandle(in_r);  // no need to read child stdin
		char buf[512]; unsigned long a;
		ReadFile(out_r, buf, sizeof(buf), &a, NULL); // Read unnecessary
	}
	~Shell() {
		CloseHandle(out_r);
		CloseHandle(in_w);
	}

	unsigned long read(char *buf, size_t len) {
		unsigned long read;
		if (!ReadFile(out_r, buf, len, &read, NULL)) die(L"Can't read the result from shell");
		return read;
	}

	unsigned long exec(char *buf, size_t len) {
		unsigned long written;
		if (!WriteFile(in_w, buf, len, &written, NULL)) die(L"Can't exec command at shell");
		return written;
	}
private:
	// stdin pipes
	HANDLE in_r, in_w;
	// stdout pipes
	HANDLE out_r, out_w;
};