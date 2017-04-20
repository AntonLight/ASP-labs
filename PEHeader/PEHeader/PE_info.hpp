#pragma once

#define RVA2VA(type, base, rva) (type)((char*)(base) + (rva))
#define RVA2RAW(type, rva, sec) (type)((rva) - (sec->VirtualAddress) + (sec->PointerToRawData));\
	assert(rva <= sec->VirtualAddress + sec->SizeOfRawData);\
	assert(rva >= sec->VirtualAddress);
#define VA2RAW(type, va, base, sec_rva, sec_raw) RVA2RAW(type, (va - base), (sec_rva), (sec_raw))

#include <windows.h>
#include <assert.h>
#include "lib.h"

PIMAGE_NT_HEADERS get_pe_header(PVOID im_base) {
	return RVA2VA(PIMAGE_NT_HEADERS, im_base, ((PIMAGE_DOS_HEADER)im_base)->e_lfanew);
}

// Perform loading of the binary and its maping
PVOID load_bin(WCHAR *filename) {
	HANDLE file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == file) die(L"Can't open file");

	HANDLE mapping = CreateFileMapping(file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (NULL == mapping) die(L"Can't create mapping");

	PVOID im_base = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
	if (NULL == im_base) die(L"Can't map");
	return im_base;
}

// Retrieve virtual address of IAT
PVOID get_data_directory(PVOID im_base, int i) {
	auto rva = get_pe_header(im_base)->OptionalHeader.DataDirectory[i].VirtualAddress;
	return RVA2VA(PVOID, (char*)im_base, rva);
}

// Finds section that corresponds to specified rva
// then calculate raw offset for it
DWORD rva_to_offset(PIMAGE_NT_HEADERS pe_header, DWORD rva) {
	PIMAGE_SECTION_HEADER section_header = RVA2VA(PIMAGE_SECTION_HEADER, pe_header,
		sizeof(pe_header) + sizeof(pe_header->FileHeader) + pe_header->FileHeader.SizeOfOptionalHeader);
	for (int i = 0; i < pe_header->FileHeader.NumberOfSections; i++, section_header++) {
		auto va = section_header->VirtualAddress;
		auto raw_size = section_header->SizeOfRawData;
		if (rva >= va && rva <= va + raw_size) {
			return rva - va + raw_size;
		}
	}
	return 0;
}

DWORD find_import(PVOID im_base, char *dllname, char *fn_name) {
	auto imports = (PIMAGE_IMPORT_DESCRIPTOR)get_data_directory(im_base, IMAGE_DIRECTORY_ENTRY_IMPORT);
	for (unsigned i = 0; imports->Name != 0; ++i, imports++) {
		const auto dll_name = RVA2VA(char*, im_base, imports->Name);
		if (strcmp(dllname, dll_name) != 0) continue;

		PIMAGE_THUNK_DATA oft = RVA2VA(PIMAGE_THUNK_DATA, im_base, imports->OriginalFirstThunk);
		PIMAGE_THUNK_DATA ft = RVA2VA(PIMAGE_THUNK_DATA, im_base, imports->FirstThunk);
		for (;; ++oft, ++ft) {
			if (oft->u1.Ordinal == 0) break;
			if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) continue;
			auto import = RVA2VA(PIMAGE_IMPORT_BY_NAME, im_base, oft->u1.AddressOfData);
			if (strcmp(import->Name, fn_name)) return ft->u1.Function;
		}
	}
	return 0;
}