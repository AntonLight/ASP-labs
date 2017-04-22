#pragma once
#include <windows.h>
#include <vector>
#include "../../PEHeader/PEHeader/lib.h"

extern PROCESS_INFORMATION pi;
extern STARTUPINFOW si;
extern DWORD entry_point;

std::vector<unsigned char> saved_ep;

void memdump(LPVOID mem, size_t len) {
	char *buf = (char*)malloc(len);
	SIZE_T read;
	ReadProcessMemory(pi.hProcess, mem, buf, len, &read);
	if (read == 0) die(L"Can't read child mem");
	for (size_t i = 0; i < len; ++i) wprintf_s(L"%hhx ", buf[i]);
	free(buf);
	wprintf_s(L"\n");
}

LPVOID inject_code() {
	auto shell = make_shellcode();
	const size_t len = shell.size();

	LPVOID mem = VirtualAllocEx(pi.hProcess, 0, len,
		MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!mem) die(L"Can't allocate mem in child");
	wprintf_s(L"Allocated! Mem: %p\n", mem);

	SIZE_T written;
	if (!WriteProcessMemory(pi.hProcess, mem, shell.data(), len, &written) ||
		written != len)
		die(L"Can't write in child mem");

	wprintf_s(L"Wrote shellcode! Memdump: ");

	memdump(mem, len);
	return mem;
}

void call_injected(LPVOID shellcode_addr) {
	HANDLE h = CreateRemoteThread(pi.hProcess, 0, 0,
		(LPTHREAD_START_ROUTINE)shellcode_addr, shellcode_addr, 0, 0);
	if (!h) die(L"Can't create thread in injected");
	WaitForSingleObject(h, INFINITE);
	DWORD code;
	GetExitCodeThread(h, &code);
	printf("Thread exited with code %d \n", code);
	CloseHandle(h);
}

unsigned char looper[] = {0xeb, 0xfc};

void patch_entry_point() {
}

void restore_entry_point() {

}