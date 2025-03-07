#include "Inject.h"
#include "XorComp.hpp"
#include "lazy.hpp"

mNtWriteVirtualMemory	_NtWriteVirtualMemory = (mNtWriteVirtualMemory)(LI_FN(GetProcAddress)(LI_FN(GetModuleHandleA)(_("ntdll.dll")), _("NtWriteVirtualMemory")));
mNtReadVirtualMemory	_NtReadVirtualMemory = (mNtReadVirtualMemory)(LI_FN(GetProcAddress)(LI_FN(GetModuleHandleA)(_("ntdll.dll")), _("NtReadVirtualMemory")));

#define ReCa reinterpret_cast

DWORD GetPID(const char* pName)
{
	HANDLE pSnapshot = LI_FN(CreateToolhelp32Snapshot)(TH32CS_SNAPPROCESS, 0);

	if (!pSnapshot)
		return 0;

	PROCESSENTRY32 pInfo{ 0 };
	pInfo.dwSize = sizeof(PROCESSENTRY32);

	if (LI_FN(Process32First)(pSnapshot, &pInfo))
	{
		while (LI_FN(Process32Next)(pSnapshot, &pInfo))
		{
			if (strstr(pName, pInfo.szExeFile))
			{
				LI_FN(CloseHandle)(pSnapshot);

				return pInfo.th32ProcessID;
			}
		}
	}

	LI_FN(CloseHandle)(pSnapshot);

	return 0;
}

DWORD WINAPI ShellCode(DATA_MAP_STRUCTURE* pData)
{
	if (!pData || !pData->m_pLoadLibraryA)
	{
		pData->m_iErrorCode = FAIL_TO_GET_BASE_ADDRESS;
		return 1;
	}

	BYTE* pBase = pData->m_pBase;
	if (!pBase)
	{
		pData->m_iErrorCode = FAIL_TO_GET_BASE_ADDRESS;
		return 1;
	}

	auto* pOp = &ReCa<IMAGE_NT_HEADERS*>(pBase + ReCa<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;

	auto _GetProcAddress = pData->m_pGetProcAddress;;
	auto _DllMain = ReCa<mDllMain>(pBase + pOp->AddressOfEntryPoint);

	auto pRelocDt = reinterpret_cast<PIMAGE_BASE_RELOCATION>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

	if (!pRelocDt->VirtualAddress)
	{
		pData->m_iErrorCode = FAIL_TO_GET_RELOC_ADDRESS;
		return 1;
	}

	while (pRelocDt->VirtualAddress) {
		DWORD EntriesCount = (pRelocDt->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD pRelocInfo = reinterpret_cast<PWORD>(pRelocDt + 1);

		for (int i = 0; i != EntriesCount; ++i, ++pRelocInfo)
		{
			if (RELOC_CHECK(pRelocInfo))
			{
				PUINT pPath = reinterpret_cast<PUINT>(pBase + pRelocDt->VirtualAddress + (*pRelocInfo & 0xFFF));
				*pPath += reinterpret_cast<UINT>(pBase - pOp->ImageBase);
			}
		}

		pRelocDt = reinterpret_cast<PIMAGE_BASE_RELOCATION>((PBYTE)pRelocDt + pRelocDt->SizeOfBlock);
	}

	if (pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto* pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char* szMod = ReCa<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = pData->m_pLoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = ReCa<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = ReCa<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pImportDescr->OriginalFirstThunk)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = _GetProcAddress(hDll, ReCa<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto* pImport = ReCa<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = _GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto* pTLS = ReCa<IMAGE_TLS_DIRECTORY*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = ReCa<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && (*pCallback); ++pCallback)
		{
			auto Callback = *pCallback;
			Callback(pBase, DLL_PROCESS_ATTACH, nullptr);
		}
	}

	_DllMain((HMODULE)pBase, DLL_PROCESS_ATTACH, nullptr);

	DWORD Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (Size)
	{
		auto* pImportDescr = ReCa<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char* szMod = ReCa<char*>(pBase + pImportDescr->Name);
			for (; *szMod++; *szMod = 0);
			pImportDescr->Name = 0;

			ULONG_PTR* pThunkRef = ReCa<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = ReCa<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pImportDescr->OriginalFirstThunk)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (!IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					auto* pImport = ReCa<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					char* szFunc = pImport->Name;
					for (; *szFunc++; *szFunc = 0);
				}
				else
				{
					*(WORD*)pThunkRef = 0;
				}
			}

			++pImportDescr;
		}

		pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
		pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
	}

	Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	if (Size)
	{
		auto* pIDD = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress);
		BYTE* pDataa = pBase + pIDD->AddressOfRawData;
		for (UINT i = 0; i != pIDD->SizeOfData; ++i)
		{
			pDataa[i] = 0;
		}
		pIDD->AddressOfRawData = 0;
		pIDD->PointerToRawData = 0;
		pIDD->SizeOfData = 0;
		pIDD->TimeDateStamp = 0;
		pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = 0;
		pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;
	}

	Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (Size)
	{
		auto* pRelocData = ReCa<IMAGE_BASE_RELOCATION*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			pRelocData->VirtualAddress = 0;
			pRelocData = ReCa<IMAGE_BASE_RELOCATION*>(ReCa<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}

		pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
		pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
	}

	Size = pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
	if (Size)
	{
		auto* pTLS = ReCa<IMAGE_TLS_DIRECTORY*>(pBase + pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = ReCa<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && (*pCallback); ++pCallback)
		{
			*pCallback = nullptr;
		}

		pTLS->AddressOfCallBacks = 0;
		pTLS->AddressOfIndex = 0;
		pTLS->EndAddressOfRawData = 0;
		pTLS->SizeOfZeroFill = 0;
		pTLS->StartAddressOfRawData = 0;
		pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = 0;
		pOp->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size = 0;
	}

	for (UINT i = 0; i < 0x1000; i += sizeof(ULONG64))
	{
		*ReCa<ULONG64*>(pBase + i) = 0;
	}

	pData->m_iErrorCode = 1;

	return 0;
}

INT Inject(DWORD pId, PCHAR map)
{
	if (!map) return FAIL_TO_READ_FILE;

	HANDLE hProc = LI_FN(OpenProcess)(PROCESS_ALL_ACCESS, false, pId);

	if (!hProc) return FAIL_TO_OPEN_HANDLE;

	auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(map);

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		LI_FN(CloseHandle)(hProc);

		return NOT_A_DOS_SIGNATURE;
	}

	auto pe_header = reinterpret_cast<PIMAGE_NT_HEADERS>(map + dos_header->e_lfanew);

	if (pe_header->Signature != IMAGE_NT_SIGNATURE)
	{
		LI_FN(CloseHandle)(hProc);

		return NOT_A_PE_SIGNATURE;
	}

	if (pe_header->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
	{
		LI_FN(CloseHandle)(hProc);

		return INVALID_PLATFORM;
	}

	auto pOpt = &pe_header->OptionalHeader;

	LPVOID pMapBase = LI_FN(VirtualAllocEx)(hProc, nullptr, pOpt->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!pMapBase)
	{
		LI_FN(CloseHandle)(hProc);

		return FAIL_TO_ALLOC_MEMORY;
	}

	_NtWriteVirtualMemory(hProc, pMapBase, map, pOpt->SizeOfHeaders, nullptr);

	auto section_header = IMAGE_FIRST_SECTION(pe_header);

	for (int i = 0; i < pe_header->FileHeader.NumberOfSections; ++i, ++section_header)
	{
		_NtWriteVirtualMemory(hProc, reinterpret_cast<PBYTE>(pMapBase) + section_header->VirtualAddress, map + section_header->PointerToRawData,
			section_header->SizeOfRawData, nullptr);
	}

	DATA_MAP_STRUCTURE data_map{ 0 };
	data_map.m_pLoadLibraryA = LoadLibraryA;
	data_map.m_pGetProcAddress = reinterpret_cast<mGetProcAddress>(GetProcAddress);
	data_map.m_pBase = reinterpret_cast<PBYTE>(pMapBase);

	INT64 shell_size = 0x2f7; //хардкодед без приколов

	LPVOID pDataStruct = LI_FN(VirtualAllocEx)(hProc, nullptr, sizeof(DATA_MAP_STRUCTURE), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID pShellCode = LI_FN(VirtualAllocEx)(hProc, nullptr, shell_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (!pDataStruct || !pShellCode)
	{
		LI_FN(CloseHandle)(hProc);
		LI_FN(VirtualFreeEx)(hProc, pMapBase, 0, MEM_RELEASE);

		return FAIL_TO_ALLOC_MEMORY;
	}

	_NtWriteVirtualMemory(hProc, pDataStruct, &data_map, sizeof(DATA_MAP_STRUCTURE), nullptr);
	_NtWriteVirtualMemory(hProc, pShellCode, ShellCode, shell_size, nullptr);

	LI_FN(CreateRemoteThread)(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pShellCode, pDataStruct, 0, nullptr);

	while (!data_map.m_iErrorCode)
	{
		_NtReadVirtualMemory(hProc, pDataStruct, &data_map, sizeof(DATA_MAP_STRUCTURE), nullptr);

		LI_FN(Sleep).cached()(100);
	}

	LI_FN(VirtualFreeEx)(hProc, pDataStruct, 0, MEM_RELEASE);
	LI_FN(VirtualFreeEx)(hProc, pShellCode, 0, MEM_RELEASE);

	LI_FN(CloseHandle)(hProc);

	return data_map.m_iErrorCode;
}