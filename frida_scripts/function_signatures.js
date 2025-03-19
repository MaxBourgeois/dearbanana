var functionSignatures = {
    "CreateFileW": {
        args: [
            { name: "lpFileName", type: "wstring" },
            { name: "dwDesiredAccess", type: "uint32" },
            { name: "dwShareMode", type: "uint32" },
            { name: "lpSecurityAttributes", type: "pointer" },
            { name: "dwCreationDisposition", type: "uint32" },
            { name: "dwFlagsAndAttributes", type: "uint32" },
            { name: "hTemplateFile", type: "pointer" }
        ],
        retType: "pointer"
    },
    "ReadFile": {
        args: [
            { name: "hFile", type: "pointer" },
            { name: "lpBuffer", type: "pointer" },
            { name: "nNumberOfBytesToRead", type: "uint32" },
            { name: "lpNumberOfBytesRead", type: "pointer" },
            { name: "lpOverlapped", type: "pointer" }
        ],
        retType: "bool"
    },
    "WriteFile": {
        args: [
            { name: "hFile", type: "pointer" },
            { name: "lpBuffer", type: "pointer" },
            { name: "nNumberOfBytesToWrite", type: "uint32" },
            { name: "lpNumberOfBytesWritten", type: "pointer" },
            { name: "lpOverlapped", type: "pointer" }
        ],
        retType: "bool"
    },
    "Sleep": {
        args: [
            { name: "dwMilliseconds", type: "uint32" }
        ],
        retType: "void"
    },

    "CreateFileA": {
        args: [
            { name: "lpFileName", type: "string" },
            { name: "dwDesiredAccess", type: "uint32" },
            { name: "dwShareMode", type: "uint32" },
            { name: "lpSecurityAttributes", type: "pointer" },
            { name: "dwCreationDisposition", type: "uint32" },
            { name: "dwFlagsAndAttributes", type: "uint32" },
            { name: "hTemplateFile", type: "pointer" }
        ],
        retType: "pointer"
    },
    "CloseHandle": {
        args: [
            { name: "hObject", type: "pointer" }
        ],
        retType: "bool"
    },
    "VirtualAlloc": {
        args: [
            { name: "lpAddress", type: "pointer" },
            { name: "dwSize", type: "uint32" },
            { name: "flAllocationType", type: "uint32" },
            { name: "flProtect", type: "uint32" }
        ],
        retType: "pointer"
    },
    "VirtualFree": {
        args: [
            { name: "lpAddress", type: "pointer" },
            { name: "dwSize", type: "uint32" },
            { name: "dwFreeType", type: "uint32" }
        ],
        retType: "bool"
    },
    "VirtualProtect": {
        args: [
            { name: "lpAddress", type: "pointer" },
            { name: "dwSize", type: "uint32" },
            { name: "flNewProtect", type: "uint32" },
            { name: "lpflOldProtect", type: "pointer" }
        ],
        retType: "bool"
    },
    "LoadLibraryA": {
        args: [
            { name: "lpLibFileName", type: "string" }
        ],
        retType: "pointer"
    },
    "LoadLibraryW": {
        args: [
            { name: "lpLibFileName", type: "wstring" }
        ],
        retType: "pointer"
    },
    "GetProcAddress": {
        args: [
            { name: "hModule", type: "pointer" },
            { name: "lpProcName", type: "string" }
        ],
        retType: "pointer"
    },
    "FreeLibrary": {
        args: [
            { name: "hLibModule", type: "pointer" }
        ],
        retType: "bool"
    },
    "GetModuleHandleA": {
        args: [
            { name: "lpModuleName", type: "string" }
        ],
        retType: "pointer"
    },
    "GetModuleHandleW": {
        args: [
            { name: "lpModuleName", type: "wstring" }
        ],
        retType: "pointer"
    },
    "GetLastError": {
        args: [],
        retType: "uint32"
    },
    "SetLastError": {
        args: [
            { name: "dwErrCode", type: "uint32" }
        ],
        retType: "void"
    },
    "VirtualAllocEx": {
        args: [
            { name: "hProcess", type: "pointer" },
            { name: "lpAddress", type: "pointer" },
            { name: "dwSize", type: "uint32" },
            { name: "flAllocationType", type: "uint32" },
            { name: "flProtect", type: "uint32" }
        ],
        retType: "pointer"
    },
    "VirtualFreeEx": {
        args: [
            { name: "hProcess", type: "pointer" },
            { name: "lpAddress", type: "pointer" },
            { name: "dwSize", type: "uint32" },
            { name: "dwFreeType", type: "uint32" }
        ],
        retType: "bool"
    },
    "VirtualProtectEx": {
        args: [
            { name: "hProcess", type: "pointer" },
            { name: "lpAddress", type: "pointer" },
            { name: "dwSize", type: "uint32" },
            { name: "flNewProtect", type: "uint32" },
            { name: "lpflOldProtect", type: "pointer" }
        ],
        retType: "bool"
    },
    "CreateRemoteThread": {
        args: [
            { name: "hProcess", type: "pointer" },
            { name: "lpThreadAttributes", type: "pointer" },
            { name: "dwStackSize", type: "uint32" },
            { name: "lpStartAddress", type: "pointer" },
            { name: "lpParameter", type: "pointer" },
            { name: "dwCreationFlags", type: "uint32" },
            { name: "lpThreadId", type: "pointer" }
        ],
        retType: "pointer"
    },
    "GetThreadId": {
        args: [
            { name: "Thread", type: "pointer" }
        ],
        retType: "uint32"
    },
    "WaitForSingleObject": {
        args: [
            { name: "hHandle", type: "pointer" },
            { name: "dwMilliseconds", type: "uint32" }
        ],
        retType: "uint32"
    },
    "WaitForMultipleObjects": {
        args: [
            { name: "nCount", type: "uint32" },
            { name: "lpHandles", type: "pointer" },
            { name: "bWaitAll", type: "bool" },
            { name: "dwMilliseconds", type: "uint32" }
        ],
        retType: "uint32"
    },
    "ExitThread": {
        args: [
            { name: "dwExitCode", type: "uint32" }
        ],
        retType: "void"
    },
    "TerminateThread": {
        args: [
            { name: "hThread", type: "pointer" },
            { name: "dwExitCode", type: "uint32" }
        ],
        retType: "bool"
    },
    "CreateProcessA": {
        args: [
            { name: "lpApplicationName", type: "string" },
            { name: "lpCommandLine", type: "string" },
            { name: "lpProcessAttributes", type: "pointer" },
            { name: "lpThreadAttributes", type: "pointer" },
            { name: "bInheritHandles", type: "bool" },
            { name: "dwCreationFlags", type: "uint32" },
            { name: "lpEnvironment", type: "pointer" },
            { name: "lpCurrentDirectory", type: "string" },
            { name: "lpStartupInfo", type: "pointer" },
            { name: "lpProcessInformation", type: "pointer" }
        ],
        retType: "bool"
    },
    "CreateProcessW": {
        args: [
            { name: "lpApplicationName", type: "wstring" },
            { name: "lpCommandLine", type: "wstring" },
            { name: "lpProcessAttributes", type: "pointer" },
            { name: "lpThreadAttributes", type: "pointer" },
            { name: "bInheritHandles", type: "bool" },
            { name: "dwCreationFlags", type: "uint32" },
            { name: "lpEnvironment", type: "pointer" },
            { name: "lpCurrentDirectory", type: "wstring" },
            { name: "lpStartupInfo", type: "pointer" },
            { name: "lpProcessInformation", type: "pointer" }
        ],
        retType: "bool"
    },
    "OpenProcess": {
        args: [
            { name: "dwDesiredAccess", type: "uint32" },
            { name: "bInheritHandle", type: "bool" },
            { name: "dwProcessId", type: "uint32" }
        ],
        retType: "pointer"
    },
    "GetCurrentProcess": {
        args: [],
        retType: "pointer"
    },
    "GetCurrentThread": {
        args: [],
        retType: "pointer"
    },
    "GetCurrentProcessId": {
        args: [],
        retType: "uint32"
    },
    "GetCurrentThreadId": {
        args: [],
        retType: "uint32"
    }
};
