#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <vector>
#include <string>

#define MAX_CLASSNAME 255
#define MAX_WNDNAME MAX_CLASSNAME

struct OverlayFinderParams {
	DWORD PidOwner = NULL; // overlay process id
	std::wstring wndClassName = L"";
	std::wstring wndName = L"";
	RECT pos = { 0, 0, 0, 0 }; // GetSystemMetrics with SM_CXSCREEN and SM_CYSCREEN can be useful here
	POINT res = { 0, 0 };
	float percentAllScreens = 0.0f;
	float percentMainScreen = 0.0f;
	DWORD style = NULL;
	DWORD styleEx = NULL;
	bool satisfyAllCriteria = false;
	std::vector<HWND> hwnds;
};

struct HandleData
{
	DWORD pid;
	HWND hWnd;
};

inline BOOL CALLBACK EnumGameWindowsCallback(HWND hWnd, LPARAM lParam) {
	HandleData& data = *(HandleData*)lParam;
	DWORD pid = 0;
	GetWindowThreadProcessId(hWnd, &pid);
	if (pid == data.pid && GetWindow(hWnd, GW_OWNER) == HWND(0) && IsWindowVisible(hWnd))
	{
		data.hWnd = hWnd;
		return FALSE;
	}

	return TRUE;
}

inline HWND FindGameindow(DWORD dwPID) {
	HandleData handleData{ 0 };
	handleData.pid = dwPID;
	EnumWindows(EnumGameWindowsCallback, (LPARAM)&handleData);
	return handleData.hWnd;
}

DWORD GetGameProcessId(const wchar_t* Target);
BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam);
std::vector<HWND> OverlayFinder(OverlayFinderParams params);

int main() {
	printf("Searching for suspicious windows...\n\n\n");

	DWORD gamePid = GetGameProcessId(L"cs2.exe");
	HWND gameHwnd = FindGameindow(gamePid);

	// get game (client) window size
	RECT game_window;
	RECT client_game_window;
	GetWindowRect(gameHwnd, &game_window); // The window rect includes the non-client area, i.e. the window borders, caption bar etc.
	GetClientRect(gameHwnd, &client_game_window); // Retrieves the coordinates of a window's client area

	int window_width = game_window.right - game_window.left; // width of the window (including borders)
	int window_heigth = game_window.bottom - game_window.top; // height of the window (including borders)

	OverlayFinderParams params;
	//params.pos = game_window;
	//params.style = WS_VISIBLE;
	params.styleEx = WS_EX_LAYERED | WS_EX_TRANSPARENT /*| WS_EX_TOPMOST*/;
	params.percentMainScreen = 90.0f;
	params.satisfyAllCriteria = true;
	
	std::vector<HWND> hwnds = OverlayFinder(params);
	for (int i = 0; i < hwnds.size(); i++) {
		DWORD pid = 0;
		GetWindowThreadProcessId(hwnds[i], &pid);
		printf("Window #%d found: HWND %p | PID: %d\n\t", i + 1, hwnds[i], pid);
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (hProcess) {
			char cheatPath[MAX_PATH] = "";
			K32GetProcessImageFileNameA(hProcess, (LPSTR)&cheatPath, MAX_PATH);
			CloseHandle(hProcess);
			printf("%s\n", cheatPath);
		}
		printf("----------------------------------------------------------------\n");
	}

	printf("\n");
	system("pause");

	return EXIT_SUCCESS;
}

DWORD GetGameProcessId(const wchar_t* Target) {
	HANDLE snapshotHandle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshotHandle == INVALID_HANDLE_VALUE) {
		return NULL;
	}

	PROCESSENTRY32W processEntry = { };
	processEntry.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(snapshotHandle, &processEntry)) {
		do {
			if (_wcsicmp(processEntry.szExeFile, Target) == 0) {
				CloseHandle(snapshotHandle);
				return processEntry.th32ProcessID;
			}
		} while (Process32NextW(snapshotHandle, &processEntry));
	}
	CloseHandle(snapshotHandle);
	return NULL;
}

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
	OverlayFinderParams& params = *(OverlayFinderParams*)lParam;

	int SatisfiedCriteria = 0, UnsatisfiedCriteria = 0;

	// Looking for windows of a specific PID...
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	if (params.PidOwner != NULL)
		if (params.PidOwner == pid)
			SatisfiedCriteria++;
		else
			UnsatisfiedCriteria++;

	// Looking for windows of a specific class...
	wchar_t className[MAX_CLASSNAME] = L"";
	GetClassName(hwnd, className, MAX_CLASSNAME);
	std::wstring classNameWstr = className;
	if (params.wndClassName != L"")
		if (params.wndClassName == classNameWstr)
			SatisfiedCriteria++;
		else
			UnsatisfiedCriteria++;

	// Looking for windows with a specific name...
	wchar_t windowName[MAX_WNDNAME] = L"";
	GetWindowText(hwnd, windowName, MAX_CLASSNAME);
	std::wstring windowNameWstr = windowName;
	if (params.wndName != L"")
		if (params.wndName == windowNameWstr)
			SatisfiedCriteria++;
		else
			UnsatisfiedCriteria++;

	// Looking for window at a specific position
	RECT pos;
	GetWindowRect(hwnd, &pos);
	if (params.pos.left || params.pos.top || params.pos.right || params.pos.bottom)
		if (params.pos.left == pos.left && params.pos.top == pos.top && params.pos.right == pos.right && params.pos.bottom == pos.bottom)
			SatisfiedCriteria++;
		else
			UnsatisfiedCriteria++;

	// Looking for window of a specific size
	POINT res = { pos.right - pos.left, pos.bottom - pos.top };
	if (params.res.x || params.res.y)
		if (res.x == params.res.x && res.y == params.res.y)
			SatisfiedCriteria++;
		else
			UnsatisfiedCriteria++;

	// Looking for windows taking more than a specific percentage of all the screens
	float ratioAllScreensX = res.x / GetSystemMetrics(SM_CXSCREEN);
	float ratioAllScreensY = res.y / GetSystemMetrics(SM_CYSCREEN);
	float percentAllScreens = ratioAllScreensX * ratioAllScreensY * 100;
	if (params.percentAllScreens != 0.0f)
		if (percentAllScreens >= params.percentAllScreens)
			SatisfiedCriteria++;
		else
			UnsatisfiedCriteria++;

	// Looking for windows taking more than a specific percentage or the main screen
	RECT desktopRect;
	GetWindowRect(GetDesktopWindow(), &desktopRect);
	POINT desktopRes = { desktopRect.right - desktopRect.left, desktopRect.bottom - desktopRect.top };
	float ratioMainScreenX = res.x / desktopRes.x;
	float ratioMainScreenY = res.y / desktopRes.y;
	float percentMainScreen = ratioMainScreenX * ratioMainScreenY * 100;
	if (params.percentMainScreen != 0.0f)
		if (percentAllScreens >= params.percentMainScreen)
			SatisfiedCriteria++;
		else
			UnsatisfiedCriteria++;

	// Looking for windows with specific styles
	LONG_PTR style = GetWindowLongPtr(hwnd, GWL_STYLE);
	if (params.style)
		if (params.style & style)
			SatisfiedCriteria++;
		else
			UnsatisfiedCriteria++;

	// Looking for windows with specific extended styles
	LONG_PTR styleEx = GetWindowLongPtr(hwnd, GWL_EXSTYLE);
	if (params.styleEx)
		if (params.styleEx & styleEx)
			SatisfiedCriteria++;
		else
			UnsatisfiedCriteria++;

	if (!SatisfiedCriteria)
		return TRUE;

	if (params.satisfyAllCriteria && UnsatisfiedCriteria)
		return TRUE;

	params.hwnds.push_back(hwnd);
	return TRUE;
}

std::vector<HWND> OverlayFinder(OverlayFinderParams params) {
	EnumWindows(EnumWindowsCallback, (LPARAM)&params);
	return params.hwnds;
}
