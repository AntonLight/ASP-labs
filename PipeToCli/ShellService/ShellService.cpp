#include "stdafx.h"
#include <Windows.h>
#include "ShellService.h"

Server s;
SERVICE_STATUS status;
SERVICE_STATUS_HANDLE status_handle;

void init() {
	set(SERVICE_START_PENDING);
	status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	status.dwCurrentState = SERVICE_START_PENDING;
	status.dwWin32ExitCode = NO_ERROR;
	status.dwControlsAccepted = SERVICE_ACCEPT_PAUSE_CONTINUE;
	status.dwServiceSpecificExitCode = 0;
	status.dwCheckPoint = 0;
	status.dwWaitHint = 0;

	status_handle = NULL;
	s.set_up();
}

void start() {
	init();
	resume();
}

void pause() {
	s.disable();
	set(SERVICE_PAUSED);
}

void resume() {
	s.enable();
	set(SERVICE_RUNNING);
	s.run();
}

void set(DWORD s) {
	status.dwCurrentState = s;
}

void WINAPI ctrl_handler(DWORD ctrl) {
	switch (ctrl) {
	case SERVICE_CONTROL_PAUSE: pause(); break;
	case SERVICE_CONTROL_CONTINUE: resume(); break;
	default:
		break;
	}
}

void WINAPI ServiceMain(DWORD argc, WCHAR *argv[]) {
	status_handle = RegisterServiceCtrlHandler(svcname, ctrl_handler);
	start();
}