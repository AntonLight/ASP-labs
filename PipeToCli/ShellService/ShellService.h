#pragma once
#include "stdafx.h"
#include "..\PipeToCli\Server.hpp"
#include <vector>

const wchar_t svcname[] = L"shellsvc";

void init();
void start();
void pause();
void resume();
void set(DWORD);

void WINAPI ServiceMain(DWORD argc, WCHAR *argv[]);