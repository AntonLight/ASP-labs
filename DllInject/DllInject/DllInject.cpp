#include "stdafx.h"
#include <windows.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>
#include <cassert>
#include <Psapi.h>
#include <tlhelp32.h>

static PROCESS_INFORMATION pi;
static STARTUPINFOW si;

typedef DWORD _WORD;

LPWSTR dllname = L"imagehlp.dll";
LPVOID loadlib = NULL;
LPVOID start_addr = NULL;

void clear() {
	TerminateProcess(pi.hProcess, 0);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

__declspec(noreturn) void die(wchar_t *err) {
	_WORD err_num = GetLastError();
	LPVOID err_msg;

	MessageBox(NULL, err, TEXT("Error"), MB_OK);
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		err_num,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&err_msg,
		0, NULL);
	MessageBox(NULL, (LPCTSTR)err_msg, TEXT("Error"), MB_OK);
	LocalFree(err_msg);
	clear();
	exit(-1);
}

std::vector<char> get_shellcode(bool is_64 = false) {
	std::vector<char> res;

	// push dllname byte per byte
	for (char *a = (char*)dllname, *b = (char*)(dllname + 1);
		*a != '\0' && *b != '\0'; a++, b++) {
		if (*a == 255) {
			res.insert(res.end(), {'\x68', '\xff', '\x00', '\x00', '\x00'});
		} else {
			res.push_back('\x6a');
			res.push_back(*a);
		}
	}

	// push ebp/rbp for LoadLibrary param
	res.push_back('\x55');

	// edx/rdx <- kernel32 base
	if (is_64) {
		res.insert(res.end(), { 
			'\x64', '\x48', '\x8B', '\x14', '\x25', '\x60', '\x00', '\x00', '\x00', // mov rdx, [fs:rdx+0x60]
			'\x48', '\x8B', '\x52', '\x18', // mov rdx, [rdx+18]
			'\x48', '\x8B', '\x52', '\x20', // mov rdx, [rdx+20]
			'\x48', '\x8B', '\x12', // mov rdx, [rdx]
			'\x48', '\x8B', '\x12', // mov rdx, [rdx]
			'\x48', '\x8B', '\x52', '\x20' }); // mov rdx, [rdx+20]
	} else {
		res.insert(res.end(), {
			'\x64', '\x8B', '\x1D', '\x30', '\x00', '\x00', '\x00', // mov edx, fs:0x30
			'\x8B', '\x52', '\x0C', // mov edx, [edx+c]
			'\x8B', '\x52', '\x14', // mov edx, [edx+14]
			'\x8B', '\x12', // mov edx, [edx]
			'\x8B', '\x12', // mov edx, [edx]
			'\x8B', '\x52', '\x10'}); // mov eax, [edx+10]
	}

	//if (is_64 || 0xffffffff <= (long)loadlib) {
	//	// mov rax, imm64
	//	res.insert(res.end(), {'\x48', '\xb8'});
	//} else {
	//	// mov eax/rax, imm32
	//	if (is_64) res.insert(res.end(), {'\x48', '\xc7', '\xc0'});
	//	else res.push_back('\x68');
	//}

	//const size_t len = 0xffffffff <= (long)loadlib ? sizeof(int) : sizeof(long);
	//// address
	//for (size_t i = 0; i < len; ++i) {
	//	char *c = i + (char*)loadlib;
	//	res.push_back(*c);
	//}

	res.insert(res.end(), { '\xff', '\x10' }); // call [eax]/[rax]/LoadLibrary

	// xor eax/rax
	if (is_64) res.push_back('\x48');
	res.insert(res.end(), {'\x31', '\xc0'});

	// int3
	res.push_back('\xcc');

	// ret
	res.push_back('\xc3');

	return res;
}

std::vector<char> self_jump() {
	return {'\xe9', '\xf7', '\xff', '\xff', '\xff'};
}

void memdump(LPVOID mem, size_t len) {
	char *buf = (char*)malloc(len);
	SIZE_T read;
	ReadProcessMemory(pi.hProcess, mem, buf, len, &read);
	if (read == 0) die(L"Can't read child mem");
	for (size_t i = 0; i < len; ++i) wprintf_s(L"%hhx ", buf[i]);
	free(buf);
	wprintf_s(L"\n");
}

void inject_code() {
	auto shell = get_shellcode();
	const size_t len = shell.size();

	LPVOID mem = VirtualAllocEx(pi.hProcess, 0, len, 
		MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!mem) die(L"Can't allocate mem in child");
	wprintf_s(L"Allocated! Mem: %p\n", mem);
	start_addr = mem;

	SIZE_T written;
	if (!WriteProcessMemory(pi.hProcess, mem, shell.data(), len, &written) || 
		written != len)
		die(L"Can't write in child mem");

	wprintf_s(L"Wrote shellcode! Memdump: ");

	memdump(mem, len);
}

_WORD find_kernel32(_WORD pid) {
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	// Take a snapshot of all modules in the specified process. 
	if ((hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)) ==
		INVALID_HANDLE_VALUE) die(L"CreateToolhelp32Snapshot failed");

	// Retrieve first entry
	MODULEENTRY32 me32;
	me32.dwSize = sizeof(MODULEENTRY32);
	if (!Module32First(hModuleSnap, &me32)) die(L"Module32First failed");

	_WORD offset = -1;

	do {
		if (lstrcmpW(me32.szModule, L"kernel32.dll") == 0) {
			offset = (_WORD)me32.modBaseAddr;
			break;
		}
	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return offset;
}

void find_loadlib() {
	DWORD remote_k32;
	if ((remote_k32 = find_kernel32(pi.dwProcessId)) == -1) die(L"Can't find kernel32.dll in child");
	auto ll_offset = (_WORD)LoadLibrary - find_kernel32(GetCurrentProcessId());
	loadlib = (LPVOID)(remote_k32 + ll_offset);
}

void call_injected() {
	HANDLE h = CreateRemoteThread(pi.hProcess, 0, 0, 
		(LPTHREAD_START_ROUTINE)start_addr, start_addr, 0, 0);
	if (!h) die(L"Can't create thread in injected");
	WaitForSingleObject(h, INFINITE);
	_WORD code;
	GetExitCodeThread(h, &code);
	printf("Thread exited with code %d \n", code);
	CloseHandle(h);
}

int wmain(int argc, WCHAR *argv[]) {

	ZeroMemory(&pi, sizeof(pi));
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);

	auto name = (argc >= 2) ? argv[1] : argv[0];
	wprintf_s(L"Launching: %s\n", name);

	if (!CreateProcess(0, name, 0, 0, 0, CREATE_NEW_CONSOLE, 0, 0, &si, &pi))
		die(L"Unable to create process");

	HANDLE proc = pi.hProcess;
	HANDLE th = pi.hThread;
	find_loadlib();
	inject_code();
	call_injected();
	//if (ResumeThread(th) == (_WORD)-1) die(L"Unable to start the main thread");

	clear();
	return 0;
}

