

//---------------------------------------------------------------------------------------------------------------
//
//       MyRemoteThread2012.cpp: 
//
//       History:
//
//       04/08/2014      Version 1.0
//
//---------------------------------------------------------------------------------------------------------------

//---------------------------------------------------------------------------------------------------------------
//
// Author: Anatoli Kazun 
// This code is one example of injection code into the system  process explorer.exe   
//
// Email: akasun@rambler.ru
//
//---------------------------------------------------------------------------------------------------------------

#include "stdafx.h"
#include "Windows.h"
#include "Winsvc.h"
#include "time.h"
#include <Aclapi.h>
#include <WtsApi32.h>
#include <UserEnv.h>
#include <tlhelp32.h>
#include <process.h>
#include <conio.h>
#include <wininet.h>
#include <shlobj.h>
//#include "atlwin.h"

#pragma comment(lib,"WtsApi32.lib")
#pragma comment(lib,"UserEnv.lib")
#define cbInjectFunc	100000






BOOL LaunchAppIntoDifferentSession(); 
void DebugOut(const TCHAR* szFormat, ...);
BOOL ObtainSeDebugPrivilege(HANDLE hProcess);

typedef     int 		(WINAPI *SETWINDOWINT)	           (HWND,LPCTSTR,LPCTSTR,UINT) ;
typedef     int 		(WINAPI *GETSYSTEMMETRICS_M)       (int) ;
typedef     HWND		(WINAPI *GETDESKTOPWINDOW_M)       ();
typedef     HDC		    (WINAPI *GETDC_M)	               (HWND);
typedef     HDC         (WINAPI *CREATECOMATIBLEDC_M)      (HDC);
typedef     HBITMAP     (WINAPI *CREATECOMPATIBLEBITMAP_M) (HDC,int,int);
typedef     HGDIOBJ     (WINAPI *SELECTOBJ_M)              (HDC,HGDIOBJ);
typedef     BOOL        (WINAPI *BITBLT_M)                 (HDC,int,int,int,int,HDC,int,int,DWORD);
typedef     int         (WINAPI *RELEASEDC_M)              (HWND,HDC);
typedef     BOOL        (WINAPI *DELETEDC_M)               (HDC);
typedef     BOOL        (WINAPI *DELETEOBJECT_M)           (HGDIOBJ);
typedef     LPVOID      (WINAPI *VIRTUALALLOC_M)           (LPVOID,SIZE_T,DWORD,DWORD);
typedef     int         (WINAPI *GETDIBITS_M)              (HDC,HBITMAP,UINT,UINT,LPVOID,LPBITMAPINFO,UINT);
typedef     void        (WINAPI *FILLMEMORY_M)             (PVOID,SIZE_T,BYTE);
typedef     BOOL        (WINAPI *VIRTUALFREE_M)            (LPVOID,SIZE_T,DWORD);
typedef     HGLOBAL     (WINAPI *GLOBALALLOC_M)            (UINT,SIZE_T);
typedef     LPVOID      (WINAPI *GLOBALLOCK_M)             (HGLOBAL);
typedef     HGLOBAL     (WINAPI *GLOBALFREE_M)             (HGLOBAL);
typedef     BOOL        (WINAPI *GLOBALUNLOCK_M)           (HGLOBAL);
typedef     HANDLE      (WINAPI *CREATEFILE_M)             (LPCTSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef     BOOL        (WINAPI *CLOSEHANDL_M)             (HANDLE);
typedef     BOOL        (WINAPI *WRITEFILE_M)              (HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef     BOOL        (WINAPI *SYSTEMPARAMETERSINFO_M)   (UINT,UINT,PVOID,UINT);

//This code assigned to Windows 7
typedef NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx)
(
OUT PHANDLE hThread,
IN ACCESS_MASK DesiredAccess,
IN LPVOID ObjectAttributes,
IN HANDLE ProcessHandle,
IN LPTHREAD_START_ROUTINE lpStartAddress,
IN LPVOID lpParameter,
IN BOOL CreateSuspended,
IN ULONG StackZeroBits,
IN ULONG SizeOfStackCommit,
IN ULONG SizeOfStackReserve,
OUT LPVOID lpBytesBuffer
);
struct NtCreateThreadExBuffer
{
ULONG Size;
ULONG Unknown1;
ULONG Unknown2;
PULONG Unknown3;
ULONG Unknown4;
ULONG Unknown5;
ULONG Unknown6;
PULONG Unknown7;
ULONG Unknown8;
};
//end code for Windows 7


typedef struct {
	// data initialized by our "SaveBitmapFunc.exe" before 
	// injecting the structure into "explorer.exe"
	SETWINDOWINT func;
	GETSYSTEMMETRICS_M funcGetSystemMetrics;
	GETDESKTOPWINDOW_M funcGetDesktopWindow;
	GETDC_M funcGetDC;
	CREATECOMATIBLEDC_M funcCreateCompatibleDC;
	CREATECOMPATIBLEBITMAP_M funcCreateCompatibleBitmap;
	SELECTOBJ_M funcSelectObject;
	BITBLT_M funcBitBlt;
	RELEASEDC_M funcReleaseDC;
	DELETEDC_M funcDeleteDC;
	DELETEOBJECT_M funcDeleteObject;
	VIRTUALALLOC_M funcVirtualAlloc;
	GETDIBITS_M funcGetDIBits;
	FILLMEMORY_M funcFillMemory;
	VIRTUALFREE_M funcVirtualFree;
	GLOBALALLOC_M funcGlobalAlloc;
	GLOBALLOCK_M funcGlobalLock;
	GLOBALUNLOCK_M funcGlobalUnlock;
	GLOBALFREE_M funcGlobalFree;
	CREATEFILE_M funcCreateFile;
	CLOSEHANDL_M funcCloseHandle;
	WRITEFILE_M funcWriteFile;
	SYSTEMPARAMETERSINFO_M funcSystemParametersInfo;
	char psText[25];
	char psPath[255];
	char psErrorAllocateMemory[255];
	char psErrorCreateFile[255];
	char psError[25];
	char fname[255];
	HDC					hdc;
	HANDLE 				fp;
	LPVOID				pBuf;
	BITMAPINFO			bmpInfo;
	BITMAPFILEHEADER	bmpFileHeader;
    BITMAP bmpScreen;
	int nScreenWidth;
	int nScreenHeight;
	HWND hDesktopWnd;
	HDC hDesktopDC;
	HDC hCaptureDC;
	HBITMAP hCaptureBitmap;
	HANDLE hDIB;
	DWORD dwBytesWritten;
 
		
} INJDATA;



BYTE	*pDataRemote;
DWORD	*pProcRemote;

//----------------------------------------------------------------------------------------------------------------
//	The code injected into the expolore.exe
//  This programm SaveBitmapFunc make the action of capture a screen in the  user session.
//----------------------------------------------------------------------------------------------------------------
//Entry in the code injected in explorer.exe
static DWORD WINAPI SaveBitmapFunc( INJDATA* pArguments )
{
	pArguments->nScreenWidth=pArguments->funcGetSystemMetrics(SM_CXSCREEN);
	pArguments->nScreenHeight=pArguments->funcGetSystemMetrics(SM_CYSCREEN);
	pArguments->hDesktopWnd = pArguments->funcGetDesktopWindow();
	pArguments->hDesktopDC = pArguments->funcGetDC(pArguments->hDesktopWnd);
	pArguments->hCaptureDC = pArguments->funcCreateCompatibleDC(pArguments->hDesktopDC);
	pArguments->hCaptureBitmap =pArguments->funcCreateCompatibleBitmap(pArguments->hDesktopDC,pArguments->nScreenWidth,pArguments->nScreenHeight);

	pArguments->funcSelectObject(pArguments->hCaptureDC,pArguments->hCaptureBitmap);
    pArguments->funcBitBlt(pArguments->hCaptureDC,0,0,pArguments->nScreenWidth,pArguments->nScreenHeight,pArguments->hDesktopDC,0,0,SRCCOPY);//|CAPTUREBLT
	pArguments->hdc=pArguments->funcGetDC(NULL);

	pArguments->bmpInfo.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
	pArguments->funcGetDIBits(pArguments->hdc,pArguments->hCaptureBitmap,0,0,NULL,&pArguments->bmpInfo,DIB_RGB_COLORS);
	if(pArguments->bmpInfo.bmiHeader.biSizeImage<=0)
			pArguments->bmpInfo.bmiHeader.biSizeImage=pArguments->bmpInfo.bmiHeader.biWidth*abs(pArguments->bmpInfo.bmiHeader.biHeight)*(pArguments->bmpInfo.bmiHeader.biBitCount+7)/8;
	pArguments->hDIB = pArguments->funcGlobalAlloc(GHND,pArguments->bmpInfo.bmiHeader.biSizeImage); 
	 pArguments->pBuf = (char *)pArguments->funcGlobalLock( pArguments->hDIB);    
	 pArguments->bmpInfo.bmiHeader.biCompression=BI_RGB;
	 pArguments->funcGetDIBits(pArguments->hdc,pArguments->hCaptureBitmap,0,pArguments->bmpInfo.bmiHeader.biHeight,pArguments->pBuf,&pArguments->bmpInfo,DIB_RGB_COLORS);	
	 // A file is created, this is where we will save the screen capture.
	 //::CreateFile
	 pArguments->fp = pArguments->funcCreateFile((LPCTSTR)pArguments->psPath,
		                                          GENERIC_WRITE,
                                                  0,
                                                  NULL,
                                                  CREATE_ALWAYS,
                                                  FILE_ATTRIBUTE_NORMAL, NULL);   
		pArguments->bmpFileHeader.bfReserved1=0;
		pArguments->bmpFileHeader.bfReserved2=0;
		pArguments->bmpFileHeader.bfSize=sizeof(BITMAPFILEHEADER)+sizeof(BITMAPINFOHEADER)+pArguments->bmpInfo.bmiHeader.biSizeImage;
		pArguments->bmpFileHeader.bfType=0x4D42;//'MB';
		pArguments->bmpFileHeader.bfOffBits=sizeof(BITMAPFILEHEADER)+sizeof(BITMAPINFOHEADER);
		pArguments->dwBytesWritten = 0;
		pArguments->funcWriteFile(pArguments->fp, (LPSTR)&pArguments->bmpFileHeader, sizeof(BITMAPFILEHEADER), &pArguments->dwBytesWritten, NULL);
		pArguments->funcWriteFile(pArguments->fp, (LPSTR)&pArguments->bmpInfo, sizeof(BITMAPINFOHEADER), &pArguments->dwBytesWritten, NULL);
        pArguments->funcWriteFile(pArguments->fp, (LPSTR)pArguments->pBuf, pArguments->bmpInfo.bmiHeader.biSizeImage, &pArguments->dwBytesWritten, NULL);
		
	//Unlock and Free the DIB from the heap
    pArguments->funcGlobalUnlock(pArguments->hDIB);    
    pArguments->funcGlobalFree(pArguments->hDIB);
	//Close the handle for the file that was created
    pArguments->funcCloseHandle(pArguments->fp);

	pArguments->funcReleaseDC(NULL,pArguments->hdc);
	pArguments->funcReleaseDC(pArguments->hDesktopWnd,pArguments->hDesktopDC);
	pArguments->funcDeleteDC(pArguments->hCaptureDC);
	pArguments->funcDeleteObject(pArguments->hCaptureBitmap);

return 1;
}
//End of code injected in explorer.exe


static void __stdcall t() //This defined the end of code injected in explorer.exe 
 { 
 ; 
 }


int _tmain(int argc, _TCHAR* argv[])
{
	BOOL ifSuccess = ObtainSeDebugPrivilege( GetCurrentProcess());
	if(ifSuccess) 	LaunchAppIntoDifferentSession();
	return 0;
}
////////////////////////////////////////////////////////////////////////////////////
//Added By A.Kazun on 23/06/2011 to Launch the process into a different session
////////////////////////////////////////////////////////////////////////////////////  
//---------------------------------------------------------------------------------------------------------------
//                             LaunchAppIntoDifferentSession()
//---------------------------------------------------------------------------------------------------------------
BOOL LaunchAppIntoDifferentSession()
{
	BOOL bResult = FALSE;
	DWORD dwSessionId, explorePid;
	HANDLE hProcess;
	HMODULE		hKernel32 = 0;
	HMODULE		hUser32 = 0;
	HMODULE		hGdi32 = 0;


	// Log the client on to the local computer.

	dwSessionId =  WTSGetActiveConsoleSessionId();

	//////////////////////////////////////////
	// Find the explorer process
	////////////////////////////////////////

	PROCESSENTRY32 procEntry;

	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE)
	{
		return 1;
	}

	procEntry.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hSnap, &procEntry))
	{
		return 1;
	}

	do
	{
		if (_wcsicmp(procEntry.szExeFile, _T("explorer.exe")) == 0)
		{
			//  Found a explore process.Make sure it's running in the console session
			DWORD winlogonSessId = 0;
			if (ProcessIdToSessionId(procEntry.th32ProcessID, &winlogonSessId) && winlogonSessId == dwSessionId)
			{
				//The explorer process IS running in the console session
				explorePid = procEntry.th32ProcessID;
				break;
			}
			else
			{
				//The explorer process IS NOT running in the console session
				break;
			}
		}

	} while (Process32Next(hSnap, &procEntry));

	////////////////////////////////////////////////////////////////////////

	hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, explorePid);
	hKernel32 = GetModuleHandle(__TEXT("kernel32"));
	hGdi32 = GetModuleHandle(__TEXT("gdi32"));
	hUser32 = GetModuleHandle(__TEXT("user32"));

	// It is need  for Windows 7
	HMODULE modNtDll = GetModuleHandle(__TEXT("ntdll.dll"));



	DWORD dwThreadID;// 
	int			nSuccess = 0; // Subclassing succeded?
	DWORD dwNumBytesXferred = 0; // Number of bytes written to the remote process.
	////////////////////////////////////////////////////////////////////////
	//                           Initialize the INJDATA structure
	////////////////////////////////////////////////////////////////////////

	INJDATA DataLocal = {
		(SETWINDOWINT)GetProcAddress(hUser32, "MessageBoxA"),
		(GETSYSTEMMETRICS_M)GetProcAddress(hUser32, "GetSystemMetrics"),
		(GETDESKTOPWINDOW_M)GetProcAddress(hUser32, "GetDesktopWindow"),
		(GETDC_M)GetProcAddress(hUser32, "GetDC"),
		(CREATECOMATIBLEDC_M)GetProcAddress(hGdi32, "CreateCompatibleDC"),
		(CREATECOMPATIBLEBITMAP_M)GetProcAddress(hGdi32, "CreateCompatibleBitmap"),
		(SELECTOBJ_M)GetProcAddress(hGdi32, "SelectObject"),
		(BITBLT_M)GetProcAddress(hGdi32, "BitBlt"),
		(RELEASEDC_M)GetProcAddress(hUser32, "ReleaseDC"),
		(DELETEDC_M)GetProcAddress(hGdi32, "DeleteDC"),
		(DELETEOBJECT_M)GetProcAddress(hGdi32, "DeleteObject"),
		(VIRTUALALLOC_M)GetProcAddress(hKernel32, "VirtualAlloc"),
		(GETDIBITS_M)GetProcAddress(hGdi32, "GetDIBits"),
		(FILLMEMORY_M)GetProcAddress(hKernel32, "FillMemory"),
		(VIRTUALFREE_M)GetProcAddress(hKernel32, "VirtualFree"),
		(GLOBALALLOC_M)GetProcAddress(hKernel32, "GlobalAlloc"),
		(GLOBALLOCK_M)GetProcAddress(hKernel32, "GlobalLock"),
		(GLOBALUNLOCK_M)GetProcAddress(hKernel32, "GlobalUnlock"),
		(GLOBALFREE_M)GetProcAddress(hKernel32, "GlobalFree"),
		(CREATEFILE_M)GetProcAddress(hKernel32, "CreateFileA"),
		(CLOSEHANDL_M)GetProcAddress(hKernel32, "CloseHandle"),
		(WRITEFILE_M)GetProcAddress(hKernel32, "WriteFile"),
		(SYSTEMPARAMETERSINFO_M)GetProcAddress(hUser32, "SystemParametersInfoA"),
		"Debug",
		"c:\\Temp\\screen.bmp\0",
		"Unable to Allocate Bitmap Memory\0",
		"Unable to Create Bitmap File\0",
		"Error\0",
		"C:\\Temp\\1.bmp\0",
		NULL,
		NULL,
		NULL
	};
		pDataRemote = (BYTE*)VirtualAllocEx(hProcess, 0, sizeof(INJDATA), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		bResult = WriteProcessMemory(hProcess, pDataRemote, &DataLocal, sizeof(INJDATA), &dwNumBytesXferred);
	////////////////////////////////////////////////////////////////////////
	//                             ProcRemote
	////////////////////////////////////////////////////////////////////////

	pProcRemote = (PDWORD)VirtualAllocEx(hProcess, 0, ((SIZE_T)((unsigned int)t - (unsigned int)SaveBitmapFunc)), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	bResult = WriteProcessMemory(hProcess, pProcRemote, SaveBitmapFunc, ((SIZE_T)((unsigned int)t - (unsigned int)SaveBitmapFunc)), &dwNumBytesXferred);
	////////////////////////////////////////////////////////////////////////
	//                             CreateRemoteThread
	////////////////////////////////////////////////////////////////////////

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pProcRemote, pDataRemote, 0/*CREATE_SUSPENDED*/, &dwThreadID);
	if (!hThread)
	{
		// Probably it is Windows 7. Attempt to create a thread for Windows 7
		LPFUN_NtCreateThreadEx funNtCreateThreadEx = (LPFUN_NtCreateThreadEx)GetProcAddress(modNtDll, "NtCreateThreadEx");
		if (funNtCreateThreadEx)
		{
			//Successful to get funtion address from ntdll.dll;
			NtCreateThreadExBuffer ntbuffer;
			memset(&ntbuffer, 0, sizeof(NtCreateThreadExBuffer));
			DWORD temp1 = 0;
			DWORD temp2 = 0;
			ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
			ntbuffer.Unknown1 = 0x10003;
			ntbuffer.Unknown2 = 0x8;
			ntbuffer.Unknown3 = &temp2;
			ntbuffer.Unknown4 = 0;
			ntbuffer.Unknown5 = 0x10004;
			ntbuffer.Unknown6 = 4;
			ntbuffer.Unknown7 = &temp1;
			ntbuffer.Unknown8 = 0;
			NTSTATUS status = funNtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)pProcRemote, pDataRemote,
				FALSE, //start instantly//
				NULL,
				NULL,
				NULL,
				&ntbuffer
				);
		}
	}
		WaitForSingleObject(hThread, INFINITE);
		GetExitCodeThread(hThread, (PDWORD)&nSuccess);
		CloseHandle(hThread);
		VirtualFreeEx(hProcess, pDataRemote, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pProcRemote, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 0;
	}






	//---------------------------------------------------------------------------------------------------------------
	//                             ObtainSeDebugPrivilege(HANDLE hProcess)
	//---------------------------------------------------------------------------------------------------------------
	BOOL ObtainSeDebugPrivilege(HANDLE hProcess)
	{
		BOOL Result;
		//  TOKEN_PRIVILEGES TokenPrivileges;
		TOKEN_PRIVILEGES PreviousTokenPrivileges;
		LUID luid;
		HANDLE hToken;
		DWORD dwPreviousTokenPrivilegesSize = sizeof(TOKEN_PRIVILEGES);
		Result = OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
		if (Result == FALSE) return false;
		Result = LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);
		if (Result == FALSE) return false;
		PreviousTokenPrivileges.PrivilegeCount = 1;
		PreviousTokenPrivileges.Privileges[0].Luid = luid;
		PreviousTokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, FALSE, &PreviousTokenPrivileges,
			dwPreviousTokenPrivilegesSize, NULL, NULL);
		if (GetLastError() != ERROR_SUCCESS) 		return false;
    	else     DebugOut(_T("Adjust Token Privileges SE_PRIVILEGE_ENABLED  is OK! \n"));
		CloseHandle(hToken);
		return true;
	}
	

	//---------------------------------------------------------------------------------------------------------------
	//                             DebugOut()
	//---------------------------------------------------------------------------------------------------------------

	// Helper for writing information to the debugger.
	void DebugOut(const TCHAR* szFormat, ...)
	{
		TCHAR szBuffer[2000];
		va_list vaMarker;
		va_start(vaMarker, szFormat);
		wvsprintf(szBuffer, szFormat, vaMarker);
		va_end(vaMarker);
		FILE *debugfile = fopen("c:\\Temp\\vc32plg", "a");
		fwprintf(debugfile, szBuffer);
		fwprintf(debugfile, TEXT("\r\n"));
		fclose(debugfile);

	}