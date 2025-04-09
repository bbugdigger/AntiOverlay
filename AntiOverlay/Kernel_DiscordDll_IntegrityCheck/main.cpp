#include "Undefined.h"

#define MAX_PATH 256

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);

ULONG Murmur3(const void* data, SIZE_T len);

NTSTATUS GetProcessId(const wchar_t* ProcessName, PULONG Pid);
NTSTATUS GetProcessBase(PEPROCESS Process, PVOID* BaseAddress);
NTSTATUS GetDllBase(PEPROCESS* Process, PPEB* PpPeb, PVOID* DllBaseAddress);
NTSTATUS ReadFile(PCWSTR  FilePath, PVOID* OutBuffer, PSIZE_T Outsize);
NTSTATUS IntegrityCheck(PVOID* dll, ULONG* sectionHash);

NTSTATUS DriverEntry() {
    KdPrintEx((0, 0, "[+] Did we enter kernel?\n"));

    ULONG pid = 0;
    NTSTATUS status = GetProcessId(L"cs2.exe", &pid);

    if (!NT_SUCCESS(status))
        return STATUS_UNSUCCESSFUL;

    PEPROCESS process = nullptr;
    status = PsLookupProcessByProcessId(HANDLE(pid), &process);

    if (!NT_SUCCESS(status))
        return STATUS_UNSUCCESSFUL;

    //PVOID gameBase = 0;
    //GetProcessBase(process, &gameBase);

    PPEB pPEB = PsGetProcessPeb(process);
    PVOID discordHookDll = 0;
    status = GetDllBase(&process, &pPEB, &discordHookDll);

    if (!NT_SUCCESS(status))
        return STATUS_UNSUCCESSFUL;

    ULONG loadedDllHash;
    IntegrityCheck(&discordHookDll, &loadedDllHash);
    if (!NT_SUCCESS(status))
        return STATUS_UNSUCCESSFUL;

    PVOID diskDllBuffer;
    SIZE_T readData;
    status = ReadFile(L"DiscordHook64.dll FilePath", &diskDllBuffer, &readData);
    if (!NT_SUCCESS(status))
        return STATUS_UNSUCCESSFUL;

    ObDereferenceObject(process);

    KdPrintEx((0, 0, "[+] Did we find anything?\n"));
}

NTSTATUS IntegrityCheck(PVOID* dll, ULONG* sectionHash) {
    PVOID dllBase = *dll;
    size_t SectionSize = 0;
    PVOID Data = 0;

    IMAGE_NT_HEADERS* pNtHeader = (IMAGE_NT_HEADERS*)((UINT_PTR)dllBase + ((IMAGE_DOS_HEADER*)dllBase)->e_lfanew);
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        KdPrintEx((0, 0, "[!] PE signature invalid !!!\n"));
        return STATUS_UNSUCCESSFUL;
    }

    IMAGE_SECTION_HEADER* pSectionHeader = (IMAGE_SECTION_HEADER*)((UINT_PTR)&pNtHeader->OptionalHeader + pNtHeader->FileHeader.SizeOfOptionalHeader);
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        if (_stricmp(reinterpret_cast<const char*>(pSectionHeader[i].Name), ".text") == 0) {
            UINT_PTR TextStart = (UINT_PTR)dllBase + pSectionHeader[i].VirtualAddress;
            Data = (PVOID)TextStart;

            auto extraSpace = (0x1000 - (static_cast<uintptr_t>(pSectionHeader->Misc.VirtualSize) % 0x1000)) % 0x1000;
            if (pSectionHeader->Misc.VirtualSize && pSectionHeader->Misc.VirtualSize > pSectionHeader->SizeOfRawData)
                SectionSize = pSectionHeader->Misc.VirtualSize + extraSpace;
            else
                SectionSize = pSectionHeader->SizeOfRawData + extraSpace;

            break;
        }
    }
    // hash dll .text section
    Murmur3(Data, SectionSize);

    return STATUS_SUCCESS;
}

NTSTATUS ReadFile(PCWSTR  FilePath, PVOID* OutBuffer, PSIZE_T Outsize) {
    //https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-files-in-a-driver

    if (!FilePath || !OutBuffer || !Outsize) {
        KdPrint(("Invalid parameter(s)\n"));
        return STATUS_INVALID_PARAMETER;
    }

    WCHAR ntPath[MAX_PATH + 10];
    RtlZeroMemory(ntPath, sizeof(ntPath));

    // Construct the NT path; /??/ is same thing as /DosDevices/
    NTSTATUS status = RtlStringCchCopyW(ntPath, ARRAYSIZE(ntPath), L"\\??\\");
    if (!NT_SUCCESS(status)) {
        KdPrint(("RtlStringCchCopyW Failed With Status: 0x%08X\n", status));
        return status;
    }

    // Append the provided file path to the /DosDevices/
    status = RtlStringCchCatW(ntPath, ARRAYSIZE(ntPath), FilePath);
    if (!NT_SUCCESS(status)) {
        KdPrint(("RtlStringCchCatW Failed With Status: 0x%08X\n", status));
        return status;
    }

    KdPrint(("File NT: %ws\n", ntPath));

    UNICODE_STRING path = { 0 };
    RtlInitUnicodeString(&path, ntPath);
    OBJECT_ATTRIBUTES objAttr = { 0 };
    InitializeObjectAttributes(&objAttr, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK IoStatus = { 0 }; // final completion status and other information about the requested operation
    status = ZwCreateFile(
        &hFile,
        GENERIC_READ | SYNCHRONIZE,
        &objAttr,
        &IoStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("ZwCreateFile Failed With Status: 0x%08X\n", status));
        return status;
    }

    // get file size
    FILE_STANDARD_INFORMATION FileInfo = { 0 };
    status = ZwQueryInformationFile(
        hFile,
        &IoStatus,
        &FileInfo,
        sizeof(FILE_STANDARD_INFORMATION),
        FileStandardInformation
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("ZwQueryInformationFile Failed With Status: 0x%08X\n", status));
        ZwClose(hFile);
        return status;
    }

    SIZE_T Size = FileInfo.EndOfFile.QuadPart;
    if (Size == 0) {
        KdPrint(("File is empty.\n"));
        ZwClose(hFile);
        return STATUS_END_OF_FILE;
    }

    *OutBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, Size, 'what');
    if (*OutBuffer == NULL) {
        KdPrint(("ExAllocatePool2 Failed - Not enough memory.\n"));
        ZwClose(hFile);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    *Outsize = Size;

    LARGE_INTEGER byteOffset;
    byteOffset.LowPart = byteOffset.HighPart = 0;

    // Read the file into the allocated buffer
    status = ZwReadFile(
        hFile,
        NULL,
        NULL,
        NULL,
        &IoStatus,
        *OutBuffer,
        (ULONG)Size,
        &byteOffset,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("ZwReadFile Failed With Status: 0x%08X\n", status));
        ExFreePoolWithTag(*OutBuffer, 'what');
        ZwClose(hFile);
        return status;
    }

    ZwClose(hFile);

    return status;
}

NTSTATUS GetProcessBase(PEPROCESS Process, PVOID* BaseAddress) {
    if (!Process || !BaseAddress) {
        KdPrint(("Invalid parameters.\n"));
        return STATUS_INVALID_PARAMETER;
    }

    *BaseAddress = PsGetProcessSectionBaseAddress(Process);
    if (*BaseAddress == NULL) {
        KdPrint(("PsGetSectionBaseAddress returned NULL.\n"));
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}

NTSTATUS GetProcessId(const wchar_t* ProcessName, PULONG Pid) {
    NTSTATUS Status = STATUS_NOT_FOUND;
    ULONG    BufferSize = 1 << 12;
    PVOID    Buffer = nullptr;

    // Checks if the 'Pid' or 'ProcessName' pointer is null
    if (!Pid || !ProcessName) {
        KdPrint(("GetProcessId: Output parameter 'Pid' or 'ProcessName' is NULL\n"));
        return STATUS_INVALID_PARAMETER;
    }

    do {
        // Free previously allocated memory, if any, before a new allocation.
        if (Buffer) ExFreePoolWithTag(Buffer, 'Proc');

        // Allocate memory for process information.
        Buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, BufferSize, 'Proc');
        if (!Buffer) {
            KdPrint(("Failed to allocate memory for process information\n"));
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = ZwQuerySystemInformation(SystemProcessInformation, Buffer, BufferSize, &BufferSize);
    } while (Status == STATUS_INFO_LENGTH_MISMATCH);

    // Iterate through the list of processes to find the specified process name.
    PSYSTEM_PROCESS_INFORMATION ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)Buffer;
    while (ProcessInfo->NextEntryOffset != 0) {
        // Compare the process name with the target name (case-insensitive).
        if (ProcessInfo->ImageName.Buffer != NULL && _wcsicmp(ProcessInfo->ImageName.Buffer, ProcessName) == 0) {
            *Pid = HandleToUlong(ProcessInfo->UniqueProcessId);
            Status = STATUS_SUCCESS;
            break;
        }

        // Move to the next process entry in the list.
        ProcessInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)ProcessInfo + ProcessInfo->NextEntryOffset);
    }

    // If the loop completes without finding the process, return not found.
    ExFreePoolWithTag(Buffer, 'Proc');
    return Status;
}

NTSTATUS GetDllBase(PEPROCESS* Process, PPEB* PpPeb, PVOID* DllBaseAddress) {
    PPEB Ppeb = *PpPeb;

    PEPROCESS process = *Process;
    KAPC_STATE KAPC = { 0 };
    KeStackAttachProcess(process, &KAPC);

    if (Ppeb && Ppeb->LoaderData) {
        for (PLIST_ENTRY pListEntry = Ppeb->LoaderData->InLoadOrderModuleList.Flink; 
            pListEntry != &Ppeb->LoaderData->InLoadOrderModuleList; pListEntry = pListEntry->Flink) {
            
            PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            KdPrint(("Checking out: %ls\n", pEntry->BaseDllName.Buffer));
            if (_wcsicmp((PWCH)pEntry->BaseDllName.Buffer, L"DiscordHook64.dll") == 0)
            {
                *DllBaseAddress = pEntry->DllBase;
                break;
            }
        }
    }
    else {
        KdPrint(("PEB invalid\n"));
        return STATUS_INVALID_PARAMETER;
    }

    KeUnstackDetachProcess(&KAPC);

    return STATUS_SUCCESS;
}

/**
 * @brief Computes the MurmurHash3 (32-bit) for a given binary buffer.
 *
 * @param data Pointer to the buffer (e.g., .text section start).
 * @param len Size of the buffer in bytes (e.g., .text section size).
 * @return ULONG The computed hash value.
 */
ULONG Murmur3(const void* data, SIZE_T len) {
    const ULONG SEED = 0x9747B28C;
    const ULONG C1 = 0xCC9E2D51;
    const ULONG C2 = 0x1B873593;

    const BYTE* bytes = (const BYTE*)data;
    ULONG hash = SEED;
    SIZE_T i = 0;

    while (i + 4 <= len) {
        ULONG k = *(ULONG*)(bytes + i);
        k *= C1;
        k = _rotl(k, 15);
        k *= C2;

        hash ^= k;
        hash = _rotl(hash, 13);
        hash = hash * 5 + 0xE6546B64;

        i += 4;
    }

    ULONG k = 0;
    SIZE_T remainder = len & 3;

    if (remainder == 3) k ^= bytes[i + 2] << 16;
    if (remainder >= 2) k ^= bytes[i + 1] << 8;
    if (remainder >= 1) {
        k ^= bytes[i];
        k *= C1;
        k = _rotl(k, 15);
        k *= C2;
        hash ^= k;
    }

    hash ^= (ULONG)len;
    hash ^= hash >> 16;
    hash *= 0x85EBCA6B;
    hash ^= hash >> 13;
    hash *= 0xC2B2AE35;
    hash ^= hash >> 16;

    return hash;
}