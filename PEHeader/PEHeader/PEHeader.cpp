// PEHeader.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <windows.h>
#include <assert.h>

#define RVA2VA(type, base, rva) (type)((char*)(base) + (rva))
#define RVA2RAW(type, rva, sec) (type)((rva) - (sec->VirtualAddress) + (sec->PointerToRawData));\
	assert(rva <= sec->VirtualAddress + sec->SizeOfRawData);\
	assert(rva >= sec->VirtualAddress);
#define VA2RAW(type, va, base, sec_rva, sec_raw) RVA2RAW(type, (va - base), (sec_rva), (sec_raw))

// Prints last error and exits
void die(wchar_t *err) {
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

void print_dos_hdr(PIMAGE_DOS_HEADER dos_header) {
	printf("DOS HEADER:\n");
	printf("\tMagic: %c%c\n", dos_header->e_magic & 0xFF, (dos_header->e_magic >> 8) & 0xFF);
	printf("\tBytes in last block: 0x%hx\n", dos_header->e_cblp);
	printf("\tBlocks in file: 0x%hx\n", dos_header->e_cp);
	printf("\tRelocs num: 0x%hx\n", dos_header->e_crlc);
	printf("\tHeader parahraphs: 0x%hx\n", dos_header->e_cparhdr);
	printf("\tMin extra paragraps: 0x%hx\n", dos_header->e_minalloc);
	printf("\tMin extra paragraps: 0x%hx\n", dos_header->e_maxalloc);
	printf("\tss: 0x%hx\n", dos_header->e_ss);
	printf("\tsp: 0x%hx\n", dos_header->e_sp);
	printf("\tchecksum: 0x%hx\n", dos_header->e_csum);
	printf("\tip: 0x%hx\n", dos_header->e_ip);
	printf("\tcs: 0x%hx\n", dos_header->e_cs);
	printf("\tRellocation talbe offset: 0x%hx\n", dos_header->e_lfarlc);
	printf("\tOverlay number: 0x%hx\n", dos_header->e_ovno);
	//printf("\t 0x");
	//for (int i = 0; i < 4; ++i) printf("%hx", dos_header->e_res[i]); printf("\n");
	//printf("\t 0x%hx\n", dos_header->e_oemid);
	//printf("\t 0x%hx\n", dos_header->e_oeminfo);
	//printf("\t 0x");
	//for (int i = 0; i < 10; ++i) printf("%hx", dos_header->e_res2[i]); printf("\n");
	printf("\tPE header offset: 0x%hx\n", dos_header->e_lfanew);
	printf("\n\n");
}

void print_pe_hdr(PIMAGE_NT_HEADERS pe_header) {
	char *p = (char*)&pe_header->Signature;
	auto fh = pe_header->FileHeader;
	auto oh = pe_header->OptionalHeader;
	printf("PE HEADER:\n"
		"\tSignature: %c%c\\x%02x\\x%02x\n"
		"\tMachine: 0x%x %s\n"
		"\tOpt header size= %x\n"
	    "\tSection num: %x\n"
		"\tTimestamp: %x\n"
		"\tCode size: %x\n"
		"\tImage size: %x\n"
		"\tHeaders size: %x\n"
		"\tBase of code: %x\n"
		"\tBase of data: %x\n"
		"\tImage base: %x\n"
		"\tEntry point: %x\n",
		p[0], p[1], p[2], p[3],
		fh.Machine,
		oh.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? "x86" : "x86_64",
		fh.SizeOfOptionalHeader,
		fh.NumberOfSections,
		fh.TimeDateStamp,
		oh.SizeOfCode,
		oh.SizeOfImage,
		oh.SizeOfHeaders,
		oh.BaseOfCode,
		oh.BaseOfData,
		oh.ImageBase,
		oh.AddressOfEntryPoint);
}

// Retrieve virtual address of IAT
PVOID get_data_directory(PVOID im_base, PIMAGE_NT_HEADERS pe_header, int i) {
	auto rva = pe_header->OptionalHeader.DataDirectory[i].VirtualAddress;
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

void print_exported(PVOID im_base, PIMAGE_NT_HEADERS pe_header) {
	auto exported = (PIMAGE_EXPORT_DIRECTORY)get_data_directory(im_base, pe_header, IMAGE_DIRECTORY_ENTRY_EXPORT);
	printf("Exported functions:\n");
	auto dll = RVA2VA(PDWORD, im_base, exported->Name);
	auto names = RVA2VA(PDWORD, im_base, exported->AddressOfNames);
	auto addrs = RVA2VA(PDWORD, im_base, exported->AddressOfFunctions);
	auto ordin = RVA2VA(PDWORD, im_base, exported->AddressOfNameOrdinals);
	for (int i = 0; i < exported->NumberOfNames; ++i) {
		auto fn = RVA2VA(char*, im_base, names[i]);
		auto addr = RVA2VA(PVOID, im_base, addrs[ordin[i]]);
		printf("\t%s:%s @ %x\n", dll, fn, addr);
	}
}

void print_imported(PVOID im_base, PIMAGE_NT_HEADERS pe_header) {
	auto imports = (PIMAGE_IMPORT_DESCRIPTOR)get_data_directory(im_base, pe_header, IMAGE_DIRECTORY_ENTRY_IMPORT);
	printf("Imported functions:\n");
	for (unsigned i = 0; imports->Name != 0; ++i, imports++) {
		const auto dll_name = RVA2VA(char*, im_base, imports->Name);

		PIMAGE_THUNK_DATA oft = RVA2VA(PIMAGE_THUNK_DATA, im_base, imports->OriginalFirstThunk);
		PIMAGE_THUNK_DATA ft = RVA2VA(PIMAGE_THUNK_DATA, im_base, imports->FirstThunk);
		for (;; ++oft, ++ft) {
			if (oft->u1.Ordinal == 0) break;
			if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) continue;
			auto import = RVA2VA(PIMAGE_IMPORT_BY_NAME, im_base, oft->u1.AddressOfData);
			printf("\t%s:%s @ %x\n", dll_name, import->Name, ft->u1.Function);
		}
	}
}

int wmain(int argc, WCHAR *argv[]) {
	WCHAR *prog_name = argc > 1 ? argv[1] : argv[0];

	wprintf(L"Starting '%s' dissection...\n", prog_name);
	auto im_base = load_bin(prog_name);
	wprintf(L"'%s' have been loaded\nBeginning to parse...\n", prog_name);

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)im_base;
	print_dos_hdr(dos_header);
	PIMAGE_NT_HEADERS pe_header = RVA2VA(PIMAGE_NT_HEADERS, im_base, dos_header->e_lfanew);
	print_pe_hdr(pe_header);

	PIMAGE_SECTION_HEADER section_header = RVA2VA(PIMAGE_SECTION_HEADER, pe_header,
		sizeof(pe_header) + sizeof(pe_header->FileHeader) + pe_header->FileHeader.SizeOfOptionalHeader);

	for (int i = 0; i < pe_header->FileHeader.NumberOfSections; i++, section_header++) {
		auto &name = section_header->Name;
		printf("SECTION %8s \n", name);

		if (strcmp(".edata", (char*)name) == 0) {
			print_exported(im_base, pe_header);
		} else if (strcmp(".idata", (char*)name) == 0) {
			print_imported(im_base, pe_header);
		}
	}
	getc(stdin);
    return 0;
}

