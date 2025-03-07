#pragma once
#include <stdlib.h>
#include <windows.h>
#include <TlHelp32.h>

#define JUNK_CODE_ONE        \
    __asm{push eax}            \
    __asm{xor eax, eax}        \
    __asm{setpo al}            \
    __asm{push edx}            \
    __asm{xor edx, eax}        \
    __asm{sal edx, 2}        \
    __asm{xchg eax, edx}    \
    __asm{pop edx}            \
    __asm{or eax, ecx}   	\
    __asm{pop eax}

void DebugChecker()
{
	if (IsDebuggerPresent())
	{
		exit(1);
	}
}

bool IsProcessRun(const char* const processName)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(hSnapshot, &pe);

	while (1) {
		if (strcmp(pe.szExeFile, processName) == 0) return true;
		if (!Process32Next(hSnapshot, &pe)) return false;
	}
}

void AntiDump()
{
	JUNK_CODE_ONE
		if (IsProcessRun("ollydbg.exe") || IsProcessRun("idaq64.exe") || IsProcessRun("HxD.exe") ||
			IsProcessRun("ResourceHacker.exe") || IsProcessRun("ProcessHacker.exe") || IsProcessRun("idaq32.exe")
			|| IsProcessRun("httpdebugger.exe") || IsProcessRun("windowrenamer.exe"))
		{
			exit(-1);
		}

	JUNK_CODE_ONE
}
BOOL IsAdministrator(VOID)
{
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;

	if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup))
	{
		return FALSE;
	}

	BOOL IsInAdminGroup = FALSE;

	if (!CheckTokenMembership(NULL, AdministratorsGroup, &IsInAdminGroup))
	{
		IsInAdminGroup = FALSE;
	}

	FreeSid(AdministratorsGroup);
	return IsInAdminGroup;
}

BOOL IsVMware()
{
	BOOL bDetected = FALSE;

	__try
	{
		__asm
		{
			mov    ecx, 0Ah
			mov    eax, 'VMXh'
			mov    dx, 'VX'
			in    eax, dx
			cmp    ebx, 'VMXh'
			sete    al
			movzx   eax, al
			mov    bDetected, eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}

	return bDetected;
}
BOOL IsVM()
{
	HKEY hKey;
	int i;
	char szBuffer[64];
	const char* szProducts[] = { "*VMWARE*", "*VBOX*", "*VIRTUAL*" };

	DWORD dwSize = sizeof(szBuffer) - 1;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
	{
		if (RegQueryValueEx(hKey, "0", NULL, NULL, (unsigned char*)szBuffer, &dwSize) == ERROR_SUCCESS)
		{
			for (i = 0; i < _countof(szProducts); i++)
			{
				if (strstr(szBuffer, szProducts[i]))
				{
					RegCloseKey(hKey);
					return TRUE;
				}
			}
		}

		RegCloseKey(hKey);
	}

	return FALSE;
}
std::string wtf(AY_OBFUSCATE("XqA5RUnUN4GWKIgGIurr7q8XrpJ"));
BOOL IsSandboxie()
{
	if (GetModuleHandle("SbieDll.dll") != NULL)
		return TRUE;


	return FALSE;
}

BOOL IsVirtualBox()
{
	BOOL bDetected = FALSE;

	if (LoadLibrary("VBoxHook.dll") != NULL)
		bDetected = TRUE;

	if (CreateFile("\\\\.\\VBoxMiniRdrDN", GENERIC_READ, \
		FILE_SHARE_READ, NULL, OPEN_EXISTING, \
		FILE_ATTRIBUTE_NORMAL, NULL) \
		!= INVALID_HANDLE_VALUE)
	{
		bDetected = TRUE;
	}

	return bDetected;
}

bool MemoryBreakpointDebuggerCheck()
{
	unsigned char* pMem = NULL;
	SYSTEM_INFO sysinfo = { 0 };
	DWORD OldProtect = 0;
	void* pAllocation = NULL;

	GetSystemInfo(&sysinfo);

	pAllocation = VirtualAlloc(NULL, sysinfo.dwPageSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE);

	if (pAllocation == NULL)
		return false;

	pMem = (unsigned char*)pAllocation;
	*pMem = 0xc3;


	if (VirtualProtect(pAllocation, sysinfo.dwPageSize,
		PAGE_EXECUTE_READWRITE | PAGE_GUARD,
		&OldProtect) == 0)
	{
		return false;
	}

	__try
	{
		__asm
		{
			mov eax, pAllocation
			push MemBpBeingDebugged
			jmp eax
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		VirtualFree(pAllocation, NULL, MEM_RELEASE);
		return false;
	}

	__asm {MemBpBeingDebugged:}
	VirtualFree(pAllocation, NULL, MEM_RELEASE);
	return true;
}

inline bool Int2DCheck()
{
	__try
	{
		__asm
		{
			int 0x2d
			xor eax, eax
			add eax, 2
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return false;
	}

	return true;
}

void HideFromDebugger()
{
	JUNK_CODE_ONE
	typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
		_In_ HANDLE ThreadHandle,
		_In_ ULONG  ThreadInformationClass,
		_In_ PVOID  ThreadInformation,
		_In_ ULONG  ThreadInformationLength
		);
	const ULONG ThreadHideFromDebugger = 0x11;
	HMODULE hNtDll = LoadLibrary(TEXT("ntdll.dll"));
	pfnNtSetInformationThread NtSetInformationThread = (pfnNtSetInformationThread)
		GetProcAddress(hNtDll, "NtSetInformationThread");
	NTSTATUS status = NtSetInformationThread(GetCurrentThread(),
		ThreadHideFromDebugger, NULL, 0);
	JUNK_CODE_ONE
}
__declspec(naked) void AntiAttachs() {
	__asm {
		jmp ExitProcess
	}
}

void AntiAttach() {
	auto _GetProcAddress = LI_FN(GetProcAddress).forwarded_safe_cached();
	auto _GetModuleHandleW = LI_FN(GetModuleHandleW).forwarded_safe_cached();
	auto _GetCurrentProcess = LI_FN(GetCurrentProcess).forwarded_safe_cached();
	auto _WriteProcessMemory = LI_FN(WriteProcessMemory).forwarded_safe_cached();

	HANDLE hProcess = _GetCurrentProcess();
	HMODULE hMod = _GetModuleHandleW(L"ntdll.dll");
	FARPROC func_DbgUiRemoteBreakin = _GetProcAddress(hMod, "DbgUiRemoteBreakin");

	_WriteProcessMemory(hProcess, func_DbgUiRemoteBreakin, AntiAttachs, 6, NULL);
}