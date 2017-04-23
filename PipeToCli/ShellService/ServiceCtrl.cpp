#include "stdafx.h"
#include "..\PipeToCli\lib.h"
#include "ShellService.h"

extern const wchar_t svcname[];

enum {
	ENABLE,
	DISABLE,
	QUERY,
	REMOVE,
	START,
	INSTALL,
};

WCHAR path[] = L"C:\1\ShellService.exe";

#define usage "<enable/disable/query/remove/start/install>"

int parse(WCHAR *cmd) {
	if (!lstrcmp(L"enable", cmd)) return ENABLE;
	if (!lstrcmp(L"disable", cmd)) return DISABLE;
	if (!lstrcmp(L"query", cmd)) return QUERY;
	if (!lstrcmp(L"remove", cmd)) return REMOVE;
	if (!lstrcmp(L"start", cmd)) return START;
	if (!lstrcmp(L"install", cmd)) return INSTALL;
	return -1;
}

void modify(SC_HANDLE manager, DWORD serv_param) {
	auto svc = OpenService(manager, svcname, SERVICE_CHANGE_CONFIG);
	if (!svc) die(L"OpenService failed");

	if (!ChangeServiceConfig(svc, SERVICE_NO_CHANGE, serv_param,
		SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL))
		die(L"ChangeServiceConfig failed");
	CloseServiceHandle(svc);
}

void query(SC_HANDLE manager) {
	auto svc = OpenService(manager, svcname, SERVICE_QUERY_CONFIG);
	if (!svc) die(L"OpenService failed");

	DWORD size;

	if (!QueryServiceConfig(svc, NULL, 0, &size) &&
		GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		die(L"QueryServiceConfig failed");
	auto lpsc = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LMEM_FIXED, size);
	if (!QueryServiceConfig(svc, lpsc, size, &size))
		die(L"QueryServiceConfig failed");

	wprintf_s(L"%s config:\n"
		"\tType:       0x%x\n"
		"\tStart type: 0x%x\n"
		"\tError ctrl: 0x%x\n"
		"\tBin path:   %s\n"
		"\tAccount:    %s\n",
		svcname, lpsc->dwServiceType,
		lpsc->dwStartType, lpsc->dwErrorControl,
		lpsc->lpBinaryPathName, lpsc->lpServiceStartName);


	if (!QueryServiceConfig2(svc, SERVICE_CONFIG_DESCRIPTION, NULL, 0, &size) &&
		GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		die(L"QueryServiceConfig2 failed");
	auto lpsd = (LPSERVICE_DESCRIPTION)LocalAlloc(LMEM_FIXED, size);
	if (!QueryServiceConfig2(svc, SERVICE_CONFIG_DESCRIPTION, (LPBYTE)lpsd, size, &size))
		die(L"QueryServiceConfig2 failed");

	if (lpsd->lpDescription != NULL && lstrcmp(lpsd->lpDescription, L"") != 0)
		wprintf_s(L"\tDescription: %s\n", lpsd->lpDescription);
	if (lpsc->lpLoadOrderGroup != NULL && lstrcmp(lpsc->lpLoadOrderGroup, L"") != 0)
		wprintf_s(L"\tLoad order group: %s\n", lpsc->lpLoadOrderGroup);
	if (lpsc->dwTagId != 0)
		wprintf_s(L"\tTag ID: %d\n", lpsc->dwTagId);
	if (lpsc->lpDependencies != NULL && lstrcmp(lpsc->lpDependencies, L"") != 0)
		wprintf_s(L"\tDependencies: %s\n", lpsc->lpDependencies);

	LocalFree(lpsd);
	LocalFree(lpsc);
	CloseServiceHandle(svc);
}

void remove(SC_HANDLE manager) {
	auto svc = OpenService(manager, svcname, DELETE);
	wprintf_s(L"Are you sure you want delete service? Y/N");
	if (getc(stdin) != 'Y') return;
	if (!DeleteService(svc)) die(L"DeleteService failed");
	CloseServiceHandle(svc);
}

void install(SC_HANDLE manager) {
	if (!GetModuleFileName(NULL, path, ARRAYSIZE(path)))
		die(L"GetModuleFileName failed");
	auto svc = CreateService(manager, svcname, svcname,
		SERVICE_QUERY_STATUS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
		SERVICE_ERROR_NORMAL, L"C:\\1\\PipeToCli.exe"/*path*/, NULL, NULL, L"", L"NT AUTHORITY\\LocalService", NULL);
	if (!svc) die(L"CreateService failed");
	wprintf(L"%s have been created", svcname);
	CloseServiceHandle(svc);
}

int wmain(int argc, WCHAR *argv[]) {
	if (argc == 1) {
		wchar_t name[sizeof(svcname) / sizeof(*svcname)];
		lstrcpyW(name, svcname);
		SERVICE_TABLE_ENTRY table[] = {
			{ name, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
			NULL, NULL
		};
		if (!StartServiceCtrlDispatcher(table))
			die(L"StartServiceCtrlDispatcher failed");
	}
	if (argc > 2) {
exit:
		wprintf(L"Usage: %s " usage, argv[0]);
		return -1;
	}
	auto command = parse(argv[1]);
	if (command == -1) goto exit;
	auto manager = OpenSCManager(NULL, NULL,
		command == INSTALL ? SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE : SC_MANAGER_ALL_ACCESS);
	if (!manager) die(L"OpenSCManager failed");
	switch (command) {
	case ENABLE:
		modify(manager, SERVICE_DEMAND_START);
		break;
	case DISABLE:
		modify(manager, SERVICE_DISABLED);
		break;
	case QUERY:
		query(manager);
		break;
	case REMOVE:
		remove(manager);
		break;
	case START: {
		break;
	} case INSTALL:
		install(manager);
		break;
	default:
		die(L"Unhandled command");
	}

	CloseServiceHandle(manager);
    return 0;
}
