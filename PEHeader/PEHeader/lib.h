#pragma once

#include <windows.h>

// Prints last error and exits
__declspec(noreturn) void die(wchar_t *err) {
	DWORD err_num = GetLastError();
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
	exit(-1);
}