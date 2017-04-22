#include "stdafx.h"
#include <windows.h>
#include "shellcode.hpp"
#include "injector.hpp"
#include "../../PEHeader/PEHeader/PE_info.hpp"
#include "../../PEHeader/PEHeader/lib.h"

#ifndef _WIN64
#error "Can't work in 32-bit env"
#endif

PROCESS_INFORMATION pi;
STARTUPINFOW si;

LPWSTR dllname = L"SimpleShared.dll";
DWORD entry_point = 0;
DWORD getproc_addr = 0;

HANDLE init(LPWSTR name) {
	wprintf_s(L"Launching: %s\n", name);

	if (!CreateProcess(0, name, 0, 0, 0, CREATE_NEW_CONSOLE | CREATE_SUSPENDED, 0, 0, &si, &pi))
		die(L"Unable to create process");

	return pi.hThread;
}

void clear() {
	TerminateProcess(pi.hProcess, 0);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

void parse_pe(WCHAR *name) {
	char buffer[1024];
	SIZE_T read;
	//ReadProcessMemory(pi.hProcess, 0, buffer, sizeof(buffer), &read);
	//if (read == 0) die(L"ReadProcessMemory failed in " __FUNCTION__);
	//PIMAGE_NT_HEADERS pe_header = get_pe_header(buffer);
	//entry_point = pe_header->OptionalHeader.AddressOfEntryPoint;
}

int wmain(int argc, WCHAR *argv[]) {

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	auto name = (argc >= 2) ? argv[1] : argv[0];
	HANDLE th = init(name);
	parse_pe(name);
	patch_entry_point();

	auto shellcode_addr = inject_code();
	if (ResumeThread(th) == -1) die(L"Unable to start the main thread");
	call_injected(shellcode_addr);

	restore_entry_point();

	clear();
	return 0;
}
