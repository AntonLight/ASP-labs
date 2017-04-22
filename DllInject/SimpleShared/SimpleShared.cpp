// SimpleShared.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include <string>

BOOLEAN WINAPI DllMain(HINSTANCE hDllHandle, DWORD reason, LPVOID Reserved) {
	std::string msg;
	switch (reason) {
	case DLL_PROCESS_ATTACH:
		msg = "Attached!";
		break;
	case DLL_PROCESS_DETACH:
		msg = "Detached!";
		break;
	}
	MessageBoxA(NULL, msg.c_str(), "Info", MB_OK);
	return TRUE;
}