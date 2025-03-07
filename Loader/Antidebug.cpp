#include "Antidebug.h"

#include <Windows.h>
#include <Windowsx.h>
#include <Psapi.h>

#pragma comment(lib, "psapi.lib")

#include "lazy.hpp"
#include "XorComp.hpp"

void silent_crash()
{
	__asm
	{
		rdtsc
		XOR edx, eax
		add eax, edx
		mov esp, eax
		XOR ebp, edx
		mov ebx, ebp
		mov ecx, esp
		XOR esi, ebx
		XOR edi, esp
		jmp eax
	}
}

void hide()
{
	typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
		_In_ HANDLE ThreadHandle,
		_In_ ULONG  ThreadInformationClass,
		_In_ PVOID  ThreadInformation,
		_In_ ULONG  ThreadInformationLength
		);
	const ULONG ThreadHideFromDebugger = 0x11;

	if (auto lla = LI_FN(LoadLibraryA).forwarded_safe_cached()) {
		if (auto hNtDll = lla(_("ntdll.dll"))) {

			if (auto gpa = LI_FN(GetProcAddress).forwarded_safe_cached()) {
				pfnNtSetInformationThread NtSetInformationThread = (pfnNtSetInformationThread)
					gpa(hNtDll, _("NtSetInformationThread"));
				if (auto gct = LI_FN(GetCurrentThread).forwarded_safe_cached()) {
					NTSTATUS status = NtSetInformationThread(gct(),
						ThreadHideFromDebugger, NULL, 0);
				}
			}
		}
	}
}

bool httpdebugger()
{
	LPVOID drivers[2048];
	DWORD cbNeeded;
	int cDrivers, i;

	if (LI_FN(K32EnumDeviceDrivers).cached()(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
	{
		char szDriver[2048];

		cDrivers = cbNeeded / sizeof(drivers[0]);

		for (i = 0; i < cDrivers; i++)
		{
			if (LI_FN(K32GetDeviceDriverBaseNameA).cached()(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0])))
			{
				std::string strDriver = szDriver;
				if (strDriver.find((_("HttpDebug"))) != std::string::npos)
					return true;
			}
		}
	}

	return false;
}

void IsDebugPresent()
{
	if (auto is_dbg_pres = LI_FN(IsDebuggerPresent).forwarded_safe_cached()) {
		if (is_dbg_pres()) {
			silent_crash();
		}
	}
}

void CheckRemoteDbg()
{
	int is = 0;
	LI_FN(CheckRemoteDebuggerPresent).cached()(LI_FN(GetCurrentProcess).cached()(), &is);
	if (is) silent_crash();
}

DWORD WINAPI Thread(LPVOID)
{
	while (1)
	{
		if (LI_FN(FindWindowA).cached()(nullptr, _("x64dbg")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("Scylla")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("x64dbgjava"))
			|| LI_FN(FindWindowA).cached()(nullptr, _("x96dbgjava"))
			|| LI_FN(FindWindowA).cached()(nullptr, _("x32dbg"))
			|| LI_FN(FindWindowA).cached()(nullptr, _("httpdebugger"))
			|| LI_FN(FindWindowA).cached()(nullptr, _("httpdebug"))
			|| LI_FN(FindWindowA).cached()(nullptr, _("Fiddler"))
			|| LI_FN(FindWindowA).cached()(nullptr, _("fiddler"))
			|| LI_FN(FindWindowA).cached()(nullptr, _("FolderChangesViewer"))
			|| LI_FN(FindWindowA).cached()(nullptr, _("Folder Changes Viewer"))
			|| LI_FN(FindWindowA).cached()(nullptr, _("Scylla_x64")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("Process Hacker")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("HxD")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("Detect It Easy")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("ollydbg")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("x96dbg")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("ida")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("ida64")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("Wireshark")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("snowman")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("Open Server x64")) 
			|| LI_FN(FindWindowA).cached()(nullptr, _("Open Server x86")))
		{
			silent_crash();
		}

		if (httpdebugger())
			silent_crash();

		hide();
		IsDebugPresent();
		CheckRemoteDbg();

		LI_FN(Sleep).cached()(250);
	}

	return 0;
}