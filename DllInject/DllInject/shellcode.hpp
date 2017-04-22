#pragma once

#include <vector>
#include <array>
#include <algorithm>
#undef NDEBUG
#include <cassert>

typedef uint64_t _PTR;

extern LPWSTR dllname;
extern DWORD getproc_addr;

extern "C" void kernel32_base();
extern "C" void kernel64_base();
extern "C" void find_getproc();

std::array<unsigned char, 4> serialize(DWORD i) {
	auto c = (unsigned char*)(&i);
	return{c[0], c[1], c[2], c[3]};
}

_PTR fn_real_addr(void *fptr) {
	unsigned char *fn = (unsigned char*)fptr;
	_PTR offset = 0;
	if (*fn == 0xe9) { // follow thunk
		// call opcode 5 byte
		offset = 5 + *(DWORD*)(fn + 1);
	}
	return offset + (_PTR)fptr;
}

// Push each byte of the string to the stack
std::vector<unsigned char> str_as_code(void *str, bool is_wide = false) {
	struct push_opcode {
		unsigned char a;
		unsigned char b;
		unsigned char c;
		unsigned char d;
		explicit push_opcode(unsigned char b1, unsigned char b2)
			: a(0x66), b(0x68), c(b1), d(b2) {}
	};

	std::vector<push_opcode> res;
	//is_wide  -> while a[0] != 0 && a[1] != 0
	//!is_wide -> while a[0] != 0
	
	for (unsigned char *a = (unsigned char*)str;
		is_wide ? (a[0] != 0 || a[1] != 0) : (a[0] != 0); a += 2) {
		res.push_back(push_opcode(a[0], a[1]));
	}
	// push trailling '\0'
	res.push_back(push_opcode(0, 0));

	std::reverse(res.begin(), res.end());
	std::vector<unsigned char> t;
	std::for_each(res.begin(), res.end(), [&t](const push_opcode &psh) {
		t.push_back(psh.a);
		t.push_back(psh.b);
		t.push_back(psh.c);
		t.push_back(psh.d);
	});
	return t;
}

DWORD pushchain_len(std::vector<unsigned char> chain) {
	if (chain.size() == 0) return 0;
	return chain.size() / 2;
}

DWORD fn_size(unsigned char* fptr) {
	unsigned long len = 0;
	for (unsigned char *ptr = fptr; *(uint32_t*)(ptr + len) != 0x90909090; )
		len++;
	return len;
}

DWORD push_fn(void *fptr, std::vector<unsigned char> &bytes) {
	unsigned char *fn = (unsigned char*)fptr;
	auto size = fn_size(fn);
	bytes.reserve(bytes.size() + size);
	bytes.insert(bytes.end(), fn, fn + size);
	return size;
}

// find kernel32 base
// then find LoadLibrary address via GetProcAddress
// calls LoadLibrary(dllname)
#define _64_PREF if (is_64) {res.push_back(0x48);}
std::vector<unsigned char> make_shellcode(bool is_64 = false) {
	std::vector<unsigned char> res;

	//res.push_back(0xcc);

	//// [re]dx <- ptr to dllname
	//res.insert(res.end(), {0xe8, 0, 0, 0, 0}); // call 0
	//res.push_back(0x59); // pop [re]dx
	//_64_PREF;
	//res.insert(res.end(), {0x83, 0xc2, 0x05}); // add [re]dx, (size pop + size add = 5)
	//// mov [re]cx, [re]dx
	//_64_PREF;
	//res.insert(res.end(), {0x89, 0xd1});

	// save kernel32.dll base to [re]ax
	auto fn = (void*)fn_real_addr(is_64 ? kernel64_base : kernel32_base);
	assert(push_fn(fn, res) == (is_64 ? 27 : 21));

	_64_PREF;
	res.insert(res.end(), {0x89, 0xc3}); // mov [re]bx, [re]ax

	// find GetProcAddress
	{
		auto lib = str_as_code("GetProcAddress");
		res.insert(res.end(), lib.begin(), lib.end());
	}
	push_fn((void*)fn_real_addr(find_getproc), res);

	// mov [re]bp, [re]ax <- save this addr
	_64_PREF;
	res.insert(res.end(), {0x89, 0xc5});
	
	// push LoadLibrary
	{
		auto lib = str_as_code("LoadLibraryW");
		res.insert(res.end(), lib.begin(), lib.end());
	}
	res.push_back(0x54); // push [re]sp <- LoadLibrary str ptr
	res.push_back(0x53); // push [re]bx <- kernel32 base

	// call [re]bp <- result of find_getproc
	res.insert(res.end(), {0xff, 0xd5});

	// push dllname
	{
		auto lib = str_as_code(dllname, true);
		res.insert(res.end(), lib.begin(), lib.end());
	}
	res.push_back(0x54); // push [re]sp <- dll string ptr

	// call [re]ax <- LoadLibrary
	res.insert(res.end(), {0xff, 0xd0});

	// Return 1 if LoadLibrary failed, 0 otherwise
	_64_PREF;
	res.insert(res.end(), {0x85, 0xc0}); // test [re]ax, [re]ax
	res.push_back(0x9f); //lahf
	res.insert(res.end(), {0x0f, 0xbf, 0xc8}); // movsx ecx, ax

	// push ExitThread
	{
		auto lib = str_as_code("ExitThread");
		res.insert(res.end(), lib.begin(), lib.end());
	}
	res.push_back(0x54); // push [re]sp <- ExitThread str ptr
	res.push_back(0x53); // push [re]bx <- kernel32 base

	// call [re]bp <- GetProcAddress
	res.insert(res.end(), {0xff, 0xd5});

	res.push_back(0x51); // push [re]cx <- flags
	res.insert(res.end(), {0xff, 0xd0});
	
	return res;
}
#undef _64_PREF