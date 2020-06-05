// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "SigScanIntern.h"
#include <exception>
#include <time.h>

//------------------------ for visual styles -------------------------------
#pragma comment(lib, "comctl32.lib") // for visual styles
#pragma comment(linker, "/manifestdependency:\"type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' \
language='*'\"")
//--------------------------------------------------------------------------


// Webzen
ULONG_PTR ul_PlayerBase = 0x0;
//Neuz.exe+13281 - A1 4CF39B00           - mov eax,[Neuz.exe+5BF34C] { [00000000] }

/*
8B 0D ?? ?? ?? ?? 8B 91 ?? ?? ?? ?? 8B 42 04 8B 1D ?? ?? ?? ?? A8 01

Neuz.exe+125731 - 8B 0D 4CF39B00        - mov ecx,[Neuz.exe+5BF34C] { [14D312F8] }
Neuz.exe+125737 - 8B 91 3C030000        - mov edx,[ecx+0000033C]
Neuz.exe+12573D - 8B 42 04              - mov eax,[edx+04]
Neuz.exe+125740 - 8B 1D A4FA9B00        - mov ebx,[Neuz.exe+5BFAA4] { [107037E0] }
Neuz.exe+125746 - A8 01                 - test al,01 { 1 }

*/

ULONG_PTR ul_ActionMoverOffset = 0x0; //=> 0000033C
#define MODULE_NAME L"Neuz.exe"


// Setup shellcode
unsigned char Shellcode[] =
{
	0x50,				// push eax
	0x8B, 0x45, 0xDC,	// mov eax, [ebp-0x24] | eax now holds dwItemId
	0x83, 0xF8, 0x00,	// cmp eax, 0
	0x75, 0x11,			// jne $JMPBACK

	0xA1, 0xAA, 0xAA, 0xAA, 0xAA, // mov eax, [StrongBowEnabled]
	0x83, 0xF8, 0x01,   // cmp eax, 1

	0x75, 0x07,			// jne $JMPBACK
	0xC7, 0x45, 0xDC, 0x04, 0x00, 0x00, 0x00, // mov [ebp-0x24], 4

	// $JMPBACK
	0x58,  // pop eax
	0xE9, 0xBB, 0xBB, 0xBB, 0xBB, // jmp [gSendActMsgOrig]
};

ULONG_PTR* shadowSendActMessage = nullptr;


ULONG_PTR WINAPI MainWin(HMODULE hModule);
BOOL CALLBACK DlgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
ULONG_PTR WINAPI thBowHack();
void UnloadSelf();
void LogMessageA(const char* pszFormat, ...);


BOOLEAN bHackRunning = TRUE;

void MySleep(double d_delay);
DWORD dwMainWinThread, dwBowHackThread;
HANDLE hBowHack, hMainWin;
HMODULE g_hModule;
HWND g_hWnd;
BOOLEAN bowAlwaysStrongAttack;

bool AlreadyHooked = false;
ULONG_PTR gRWXBuf = NULL;
ULONG_PTR gSendActMsgOrig = NULL;
ULONG_PTR gStrongBowEnabled = NULL;


#define PAGE_SIZE 4096
typedef __success(return >= 0) LONG NTSTATUS;
#define STATUS_SUCCESS 0x00000000
typedef NTSTATUS(NTAPI*PNtAllocateVirtualMemory)(HANDLE ProcessHandle,
	PVOID *BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T RegionSize,
	ULONG AllocationType,
	ULONG Protect);


// Entry point of our DLL module
INT APIENTRY DllMain(HMODULE hDLL, DWORD Reason, LPVOID Reserved)
{
	switch (Reason)
	{
	case DLL_PROCESS_ATTACH:
	{
		g_hModule = hDLL;
		DisableThreadLibraryCalls(hDLL);

		// Main dialog thread
		hMainWin = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&MainWin, g_hModule, NULL, &dwMainWinThread);

		// Bow hack thread
		hBowHack = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&thBowHack, NULL, NULL, &dwBowHackThread);

		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return TRUE;
}

void UnloadSelf()
{
	MySleep(1000);

	// close all the already created threads before to unload the main MODULE
	WaitForSingleObject(hBowHack, INFINITE);
	CloseHandle(hBowHack);

	// unload and exit
	FreeLibraryAndExitThread(g_hModule,0);
}


void LogErrorMessageA(const char* pszFormat, ...) {
	static char s_acBuf[2048]; // this here is a caveat!
	va_list args;
	va_start(args, pszFormat);
	vsprintf(s_acBuf, pszFormat, args);
	OutputDebugStringA(s_acBuf);
	va_end(args);
	MessageBoxA(g_hWnd, s_acBuf, "Error", MB_ICONERROR);
}

void LogMessageA(const char* pszFormat, ...) {
	static char s_acBuf[2048]; // this here is a caveat!
	va_list args;
	va_start(args, pszFormat);
	vsprintf(s_acBuf, pszFormat, args);
	OutputDebugStringA(s_acBuf);
	va_end(args);
}

struct MyError : std::exception
{
	char text[2048];
	MyError(char const* fmt, ...) {
		va_list ap;
		va_start(ap, fmt);
		vsnprintf(text, sizeof text, fmt, ap);
		va_end(ap);
		MessageBoxA(g_hWnd, text, "Exception", MB_ICONERROR);
	}

	char const* what() const throw() { return text; }
};


// Main callback procedure
BOOL CALLBACK DlgProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
	{
		g_hWnd = hWnd;
		break;
	}
	case WM_COMMAND:
	{
		if (wParam == IDC_HACK_TOGGLE)
		{
			bowAlwaysStrongAttack = IsDlgButtonChecked(hWnd, IDC_HACK_TOGGLE);

			if (!bowAlwaysStrongAttack)
			{
				SetDlgItemText(hWnd, IDC_HACK_STATUS, L"Bow Hack [OFF]");
			}
			else {
				SetDlgItemText(hWnd, IDC_HACK_STATUS, L"Bow Hack [ON]");
			}
		}
		else if (wParam == IDC_LINK)
		{
			ShellExecute(0, 0, L"https://www.elitepvpers.com/forum/flyff-hacks-bots-cheats-exploits-macros/4622307-release-source-flyff-webzen-bow-hack.html", 0, 0, SW_SHOW);
			break;
		}
		break;
	}
	case WM_CLOSE:
	{

		// reset original function
		if (shadowSendActMessage)
		{
			*shadowSendActMessage = gSendActMsgOrig;
		}

		// delete the allocated buffer
		if (gRWXBuf)
		{
			VirtualFree(
				&gRWXBuf,       // Base address of block
				0,             // Bytes of committed pages
				MEM_RELEASE);  // Decommit the pages
		}


		// send end signal for the running thread
		bHackRunning = FALSE;

		// first kill the thread showing the dialog window
		DestroyWindow(hWnd);

		// second, start a new thread to unload the module itself
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&UnloadSelf, g_hModule, NULL, 0);
		break;
	}
	case WM_DESTROY:
	{
		break;
	}
	default:
		break;
	}
	return 0;
}


// Show Main Dialog
ULONG_PTR WINAPI MainWin(HMODULE hModule)
{
	Sleep(1000);
	DialogBox(hModule, MAKEINTRESOURCE(IDD_DIALOG1), NULL, (DLGPROC)DlgProc);
	ExitThread(0);
}



bool FindGlobalPlayer() {
	// Signature scan for the g_pPLayer
	//"5E 85 C0 74 17 50 A1 ?? ?? ?? ?? 8B 88 ?? 03 00 00 51 B9"; //+7
	char sig[] = "\x5E\x85\xC0\x74\x17\x50\xA1\x00\x00\x00\x00\x8B\x88\x00\x03\x00\x00\x51\xB9";
	char mask[] = "xxxxxxx????xx?xxxxx";
	auto shared_area = FindPattern((WCHAR*)MODULE_NAME, sig, mask);

	LogMessageA("[DEBUG] shared_area: %08x\n", shared_area);
	if (shared_area == 0) {
		return false;
	}
	ul_PlayerBase = shared_area + 7;
	LogMessageA("[DEBUG] ul_PlayerBase: %08x\n", ul_PlayerBase);
	return true;
}

bool FindActionMoverOffset()
{
	//"8B 0D ?? ?? ?? ?? 8B 91 ?? ?? ?? ?? 8B 42 04 8B 1D ?? ?? ?? ?? A8 01"; //+8
	char sig[] = "\x8B\x0D\x00\x00\x00\x00\x8B\x91\x00\x00\x00\x00\x8B\x42\x04\x8B\x1D\x00\x00\x00\x00\xA8\x01";
	char mask[] = "xx????xx????xxxxx????xx";
	auto shared_area = FindPattern((WCHAR*)MODULE_NAME, sig, mask);

	LogMessageA("[DEBUG] shared_area: %08x\n", shared_area);
	if (shared_area == 0) {
		return false;
	}
	DWORD * addyPtr = (DWORD*)(shared_area + 8);

	if (addyPtr)
	{
		ul_ActionMoverOffset = *addyPtr;
		LogMessageA("[DEBUG] ul_ActionMoverOffset: %08x\n", ul_ActionMoverOffset);
	}
	else {
		LogErrorMessageA("[ERROR] Failed to fetch ul_ActionMoverOffset!\n");
		return false;
	}

	return true;
}


/*
	Replace Sleep(ms) function
*/
void MySleep(double d_delay)
{
	DWORD start = GetTickCount();
	DWORD control = GetTickCount();
	while (control < (start + d_delay)) {
		control = GetTickCount();
	}
}



// main hack thread
ULONG_PTR WINAPI thBowHack()
{
	// find player base addy
	if (!FindGlobalPlayer())
	{
		LogErrorMessageA("[ERROR] Failed to sig scan for Global Player!\n");
		SendMessage(g_hWnd, WM_CLOSE, 0, 0);
		return -1;
	}
	
	while (bHackRunning)
	{
		MySleep(200);

		// SendActMsg: Neuz.exe + 19B410 | 55 8B EC F6 41 08 08 74 ??
		// Inject shellcode if not already done
		if (!AlreadyHooked)
		{
			// Get CActionMover Object	
			ULONG_PTR** LocalPlayer = (ULONG_PTR**)ul_PlayerBase;		

			if (!LocalPlayer)
			{
				LogErrorMessageA("[ERROR] LocalPlayer is NULL!\n");
				break;
				//throw MyError("LocalPlayer is NULL!");
			}

			ULONG_PTR g_pPlayer = **LocalPlayer;
			if (g_pPlayer)
			{
				LogMessageA("[DEBUG] g_pPlayer @ 0x%08x\n", g_pPlayer);

				if (!FindActionMoverOffset())
				{
					LogErrorMessageA("[ERROR] Failed to sig scan for Action Mover Offset!\n");
					SendMessage(g_hWnd, WM_CLOSE, 0, 0);
					return -1;
				}


				ULONG_PTR* LocalActionMover = (ULONG_PTR*)(g_pPlayer + ul_ActionMoverOffset);
				if (!LocalActionMover)
				{
					LogErrorMessageA("[ERROR] LocalActionMover is NULL!\n");
					break;
					//throw MyError("LocalActionMover is NULL!");
				}

				ULONG_PTR CActionMoverObj = *LocalActionMover;

				if (!CActionMoverObj)
				{
					LogErrorMessageA("[ERROR] CActionMoverObj is NULL!\n");
					break;
					//throw MyError("CActionMoverObj is NULL!");
				}

				LogMessageA("[DEBUG] CActionMoverObj @ 0x%08x\n", CActionMoverObj);

				// First 16 Bytes used for Shadow VMT
				ULONG_PTR CActionMoverObjVtable = *(ULONG_PTR*)CActionMoverObj;

					if (!CActionMoverObjVtable)
					{
						LogErrorMessageA("[ERROR] CActionMoverObjVtable is NULL!\n");
						break;
						//throw MyError("CActionMoverObjVtable is NULL!");
					}

						LogMessageA("[DEBUG] CActionMoverObjVtable @ 0x%08x\n", CActionMoverObjVtable);

						// Allocate space for vmt & shellcode
						/*
						16 bytes - ShadowVMT
						4  bytes - Used for Settings
						?  bytes - Shellcode
						*/
						if (gRWXBuf == NULL)
						{
							SIZE_T RWXBufSize = PAGE_SIZE;
							FARPROC NAVM = GetProcAddress(LoadLibrary(L"NTDLL.DLL"), "NtAllocateVirtualMemory");
							if (!NAVM)
							{
								LogErrorMessageA("[ERROR] Can not find NtAllocateVirtualMemory!\n");
								break;
								//throw MyError("Can not find NtAllocateVirtualMemory!");
							}
							PNtAllocateVirtualMemory NtAllocateVirtualMemory = (PNtAllocateVirtualMemory)NAVM;
							NTSTATUS ret = NtAllocateVirtualMemory(GetCurrentProcess(), (PVOID*)&gRWXBuf, 0, &RWXBufSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

							if (ret != STATUS_SUCCESS) {
								LogErrorMessageA("[ERROR] NtAllocateVirtualMemory failed with error code: 0x%08x!\n", ret);
								break;
								//throw MyError("NtAllocateVirtualMemory failed with error code: 0x%08x!\n", ret);
							}
							LogMessageA("[DEBUG] gRWXBuf @ 0x%08x\n", gRWXBuf);
						}

						memcpy((void*)gRWXBuf, (void*)CActionMoverObjVtable, 16);

						// Save SendActMsg
						// SendActMsg is at (vTable + 4) position
						gSendActMsgOrig = *(ULONG_PTR*)(CActionMoverObjVtable + 4);

						LogMessageA("[DEBUG] gSendActMsgOrig @ 0x%08x\n", gSendActMsgOrig);

						// Save gStrongBowEnabled Ptr
						gStrongBowEnabled = (ULONG_PTR)(gRWXBuf + 16);


						*(ULONG_PTR*)(Shellcode + 10) = (ULONG_PTR)gStrongBowEnabled; // StrongBowEnabled

						*(ULONG_PTR*)(Shellcode + 28) = (ULONG_PTR)(gSendActMsgOrig - (gRWXBuf + 47) - 5); // jmp back

						// Copy Shellcode
						memcpy((void*)(gRWXBuf + 20), Shellcode, sizeof(Shellcode));

						// Patch VMT Ptr
						shadowSendActMessage = (ULONG_PTR*)(CActionMoverObjVtable + 4);

						if (shadowSendActMessage)
						{
							LogMessageA("[DEBUG] shadowSendActMessage @ 0x%08x \n", shadowSendActMessage);

							// patch it!
							*shadowSendActMessage = (gRWXBuf + 20);
							LogMessageA("[DEBUG] VMT Hook placed :)\n");
							AlreadyHooked = true;
						}
			}
			else {
				LogErrorMessageA("[ERROR] g_pPlayer was not found, are you logged in the game?\n");
				break;
				//throw MyError("g_pPlayer was not found, are you logged in the game?");
			}
		}

		if (AlreadyHooked)
		{
			if (bowAlwaysStrongAttack)
			{
				*(ULONG_PTR*)gStrongBowEnabled = 1;
			}			
			else {
				*(ULONG_PTR*)gStrongBowEnabled = 0;
			}
				
		}
	}


	SendMessage(g_hWnd, WM_CLOSE, 0, 0);
	LogMessageA("### END ###\n");

	return 0;

}

