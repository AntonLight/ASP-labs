#include "stdafx.h"
#include "lib.h"
#include "Server.hpp"

int wmain(int argc, WCHAR *argv[]) {
	Server s;
	s.set_up();
	s.run();
}