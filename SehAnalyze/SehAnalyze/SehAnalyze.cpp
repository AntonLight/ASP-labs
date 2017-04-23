// SehAnalyze.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"

int a;
int* norm_ptr = &a;
int* null_ptr = 0;

void CFunc1() {
	void* p = malloc(1000);
	__try {
		*norm_ptr = 5;
		*null_ptr = 6;
	} __finally {
		if (_abnormal_termination()) {
			printf("was exception \n");
		} else {
			printf("no exception \n");
		}
		printf("in finally \n");
		free(p);
	}

}

int CFuncFilter(PEXCEPTION_POINTERS ppp) {
	printf("in filter\n");
	return EXCEPTION_EXECUTE_HANDLER;
	//null_ptr = &a;
#ifdef _X86_
	ppp->ContextRecord->Eax = a;
#else
	ppp->ContextRecord->Rax = a;
#endif
	return EXCEPTION_CONTINUE_EXECUTION;
}

void CFunc() {
	__try {
		CFunc1();
	} __except (CFuncFilter(GetExceptionInformation())) {
		printf("in handler1\n");
	}
	__try {
		CFunc1();
	}
	__except (EXCEPTION_CONTINUE_EXECUTION) {
		printf("in handler2\n");
	}
	__try {
		CFunc1();
	}
	__except (EXCEPTION_CONTINUE_SEARCH) {
		printf("in handler3\n");
	}
	__try {
		CFunc1();
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		printf("in handler4\n");
		__try {
			CFunc1();
		}
		__except (2) {
			printf("in handler5\n");
		}
	}
}

int wmain(int argc, WCHAR* argv[]) {
	CFunc();
	printf("end norm_ptr = %d \n", *norm_ptr);
	return 0;
}
