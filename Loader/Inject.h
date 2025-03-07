#pragma once

#pragma once
#include <Windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <fstream>

using namespace std;

//MMAP_ERROR_FLAGS
#define FAIL_TO_READ_FILE			-1
#define FAIL_TO_OPEN_HANDLE			-2
#define NOT_A_DOS_SIGNATURE			-3
#define NOT_A_PE_SIGNATURE			-4
#define INVALID_PLATFORM			-5
#define FAIL_TO_ALLOC_MEMORY		-6
#define FAIL_TO_WRITE_MEMORY		-7
//SHELLCODE_ERROR_FLAGS
#define FAIL_TO_GET_BASE_ADDRESS	-11
#define FAIL_TO_GET_RELOC_ADDRESS	-12
#define FAIL_TO_GET_IMPORT_ADDRESS	-13
#define FAIL_TO_GET_TLS_DIRECTORY	-14


#ifdef _WIN64
#define RELOC_CHECK(pRelocInfo) ((*pRelocInfo >> 12) & IMAGE_REL_BASED_DIR64)
#elif _WIN32
#define RELOC_CHECK(pRelocInfo) ((*pRelocInfo >> 12) & IMAGE_REL_BASED_HIGHLOW)
#endif 

typedef HMODULE(WINAPI* mLoadLibraryA)			(const char*);
typedef DWORD(WINAPI* mGetProcAddress)		(HMODULE, LPCSTR);
typedef BOOL(WINAPI* mDllMain)				(HMODULE, DWORD, LPVOID);

typedef BOOL(NTAPI* mNtWriteVirtualMemory)	(HANDLE pHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumOfBytesToWrite, PULONG);
typedef BOOL(NTAPI* mNtReadVirtualMemory)	(HANDLE pHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumOfBytesToRead, PULONG);

extern mNtWriteVirtualMemory _NtWriteVirtualMemory;
extern mNtReadVirtualMemory  _NtReadVirtualMemory;

struct DATA_MAP_STRUCTURE
{
	mLoadLibraryA	 m_pLoadLibraryA;
	mGetProcAddress m_pGetProcAddress;
	PBYTE			 m_pBase;

	INT			 m_iErrorCode;
};

DWORD			GetPID(const char* pName);
INT				Inject(DWORD pId, PCHAR map);