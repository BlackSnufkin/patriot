/*
 * Patriot memory scanner
 * Copyright 2022 Joe Desimone. All rights reserved.
 * Contact: @dez_
 */

#include "patriot.h"

#include "nt.h"

char PATRIOT_VERSION[] = "v0.3";
std::vector<UPFinding> Findings;
LOG_LEVEL logLevel = info;

void Log(LOG_LEVEL level, const char* fmt, ...)
{
    if (level < logLevel)
    {
        return;
    }
    int result;
    va_list va;
    va_start(va, fmt);
    result = vprintf(fmt, va);
    va_end(va);
}

// bool FindTimerCallback(void* pBuf, SIZE_T szBuf, const wchar_t* dllName, const char*
// functionName)
//{
//    if (szBuf < 24)
//    {
//        return false;
//    }
//
//    void* pFunction    = GetProcAddress(GetModuleHandle(dllName), functionName);
//    char search[3 * 8] = {0};
//    DWORD i            = 0;
//
//    memcpy(&search[i], "\x00\x00\x00\x00\x00\x00\x00\x00", 8);
//    i += 8;
//    memcpy(&search[i], "\x20\x00\x00\x00\x00\x00\x00\x00", 8);
//    i += 8;
//    memcpy(&search[i], &pFunction, 8);
//    i += 8;
//    if (memmem(pBuf, szBuf, search, i))
//    {
//        return true;
//    }
//
//    return false;
//}

bool FindSuspiciousContext(Process& process, void* pBuf, SIZE_T szBuf)
{
    if (szBuf < sizeof(CONTEXT))
    {
        return false;
    }

    CONTEXT* pCtx;

    void* functions[10];
    functions[0] = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtProtectVirtualMemory");
    functions[1] = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualProtect");
    functions[2] = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "VirtualProtectEx");
    functions[3] = GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "VirtualProtect");
    functions[4] = GetProcAddress(GetModuleHandle(L"kernelbase.dll"), "VirtualProtectEx");
    int count = 5;

    for (int i = 0; i < szBuf - sizeof(CONTEXT); i += 8)
    {
        char* pcBuf = (char*)pBuf;
        pCtx = (CONTEXT*)&pcBuf[i];
        if ((pCtx->ContextFlags & CONTEXT_CONTROL) &&
            VirtualProtectFunction(functions, count, pCtx->Rip) &&
            (IsExecuteSet((DWORD)pCtx->R8) || IsExecuteSet((DWORD)pCtx->R9)))
        {
            DWORD64 target = 0;
            if (pCtx->Rcx == (DWORD64)-1)
                target = pCtx->Rdx;
            else
                target = pCtx->Rcx;

            auto finding = std::make_unique<Finding>();

            finding->pid = process.pid;
            finding->processName = process.processName;
            finding->level = "suspect";
            finding->type = "CONTEXT";

            char details[256];
            sprintf_s(details, sizeof(details),
                "Suspicious CONTEXT structure pointing to VirtualProtect class function. Target: %016llx",
                target);
            finding->details = details;

            Findings.push_back(std::move(finding));
        }
    }
    return false;
}

bool EnumerateMemory(Process& process, ModuleList& moduleList)
{
    bool status = true;

    auto spModuleInfo = std::make_shared<Module>();
    Module* pModuleInfo = spModuleInfo.get();

    DWORD_PTR pMem = 0;
    bool inModule = false;
    DWORD modulePathSz = 0;
    bool bModuleHasExec = false;

    while (true)
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        if (0 == VirtualQueryEx(process.hProcess, (void*)pMem, &mbi, sizeof(mbi)))
        {
            if (ERROR_INVALID_PARAMETER == GetLastError())
            {
                break;
            }
            else
            {
                return false;
            }
        }

        pMem += mbi.RegionSize;

        if (inModule && (pModuleInfo->moduleBase != (DWORD_PTR)mbi.AllocationBase))
        {
            if (bModuleHasExec)
            {
                moduleList.push_back(spModuleInfo);
                spModuleInfo = std::make_shared<Module>();
                pModuleInfo = spModuleInfo.get();
            }

            inModule = false;
        }

        if (process.bElevated && mbi.Type != MEM_IMAGE && IsExecuteSet(mbi.Protect) &&
            mbi.State == MEM_COMMIT)
        {
            auto finding = std::make_unique<Finding>();
            finding->pid = process.pid;
            finding->processName = process.processName;
            finding->level = "suspect";
            finding->type = "elevatedUnbackedExecute";

            char details[256];
            sprintf_s(details, sizeof(details),
                "Elevated unbacked execute at Base: %016llx, Protection: %08x, Size: %016llx",
                (DWORD64)mbi.BaseAddress, mbi.Protect, mbi.RegionSize);
            finding->details = details;

            Findings.push_back(std::move(finding));
        }

        // Rest of the function remains the same...
        if (mbi.State == MEM_COMMIT)
        {
            auto pMbi = std::make_unique<MEMORY_BASIC_INFORMATION>();
            memcpy(pMbi.get(), &mbi, sizeof(mbi));
            process.memoryMap.push_back(std::move(pMbi));
        }

        if (mbi.Type != MEM_IMAGE)
        {
            continue;
        }

        if (IsExecuteSet(mbi.Protect))
        {
            bModuleHasExec = true;
        }

        if (mbi.Protect & PAGE_GUARD)
        {
            printf("[!] Guard page found on module\n");
        }
        pModuleInfo->moduleSize += mbi.RegionSize;

        if (inModule)
        {
            continue;
        }

        pModuleInfo->moduleBase = (DWORD_PTR)mbi.BaseAddress;

        while (true)
        {
            SetLastError(0);
            modulePathSz = GetMappedFileName(process.hProcess, (void*)mbi.BaseAddress,
                &pModuleInfo->modulePathNt[0],
                (DWORD)pModuleInfo->modulePathNt.size());
            if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
            {
                pModuleInfo->modulePathNt.resize(pModuleInfo->modulePathNt.size() * 2);
                continue;
            }
            break;
        }

        if (modulePathSz == 0)
        {
            pModuleInfo->getPathError = GetLastError();
            printf("[!] GetMappedFileName error, %p, %d\n", mbi.BaseAddress, GetLastError());
            continue;
        }

        pModuleInfo->modulePathNt.resize(modulePathSz);
        inModule = true;
    }

Cleanup:
    return status;
}

bool UnsharedSize(HANDLE hProcess, void* regionBase, SIZE_T regionSize, SIZE_T& unsharedSized)
{
    bool status = true;

    unsharedSized = 0;
    SIZE_T pages  = regionSize / 0x1000;
    PSAPI_WORKING_SET_EX_INFORMATION* pInfo =
        (PSAPI_WORKING_SET_EX_INFORMATION*)malloc(pages * sizeof(PSAPI_WORKING_SET_EX_INFORMATION));

    for (SIZE_T i = 0; i < pages; i++)
    {
        pInfo[i].VirtualAddress = (void*)((DWORD_PTR)regionBase + (i * 0x1000));
    }

    if (!QueryWorkingSetEx(hProcess, pInfo,
                           (DWORD)(pages * sizeof(PSAPI_WORKING_SET_EX_INFORMATION))))
    {
        printf("[!] QueryWorkingSet failed: %d\n", GetLastError());
        CleanupError();
    }

    for (SIZE_T i = 0; i < pages; i++)
    {
        if (0 == pInfo[i].VirtualAttributes.Shared)
        {
            unsharedSized += 0x1000;
        }
    }

Cleanup:
    if (pInfo)
    {
        free(pInfo);
    }
    return status;
}

bool IsProcessElevated(HANDLE hProcess, BOOL& bElevated)
{
    bool status = true;

    HANDLE hToken = 0;
    bElevated     = FALSE;
    DWORD dwRet   = 0;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
    {
        printf("Error opening process token, err %d\n", GetLastError());
        CleanupError();
    }

    if (!GetTokenInformation(hToken, TokenElevation, &bElevated, sizeof(bElevated), &dwRet))
    {
        printf("Error getting token elevation status err %d\n", GetLastError());
        CleanupError();
    }

Cleanup:
    DeleteHandle(hToken);
    return status;
}

void* ScanProc(Process& process)
{
    process.hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process.pid);
    if (0 == process.hProcess)
    {
        return 0;
    }

    Log(debug, "[+] Scanning Pid: %d, Process: %ws\n", process.pid, process.processName.c_str());

    (void)IsProcessElevated(process.hProcess, process.bElevated);

    ModuleList moduleList;
    EnumerateMemory(process, moduleList);
    for (auto it = moduleList.begin(); it != moduleList.end(); ++it)
    {
        auto moduleInfo = it->get();
        // printf("Module: [%llx-%llx] %ws\n", moduleInfo->moduleBase,
        //        moduleInfo->moduleBase + moduleInfo->moduleSize,
        //        moduleInfo->modulePathNt.c_str());

        PEFile peDisk;
        PEFile peMem;
        peMem.pid         = process.pid;
        peMem.processName = process.processName;
        peMem.moduleInfo  = *it;
        if (peDisk.LoadHeaderFromDisk(moduleInfo->modulePathNt) &&
            peMem.LoadHeaderFromMemory(process.hProcess, moduleInfo->moduleBase))
        {
            PEFile::ValidateIntegrity(peDisk, peMem, process);
        }
    }

    DWORD_PTR pMem = 0;
    for (auto it = process.memoryMap.begin(); it != process.memoryMap.end(); ++it)
    {
        auto pMbi     = it->get();
        void* pBuf    = 0;
        SIZE_T stRead = 0;

        if (pMbi->State != MEM_COMMIT || pMbi->Protect != PAGE_READWRITE ||
            pMbi->RegionSize > 1024 * 1024 * 50 || pMbi->Type != MEM_PRIVATE)
        {
            continue;
        }

        pBuf = malloc(pMbi->RegionSize);

        if (!ReadProcessMemory(process.hProcess, pMbi->BaseAddress, pBuf, pMbi->RegionSize,
                               &stRead))
        {
            free(pBuf);
            continue;
        }

        FindSuspiciousContext(process, pBuf, pMbi->RegionSize);

        /*
        Disabling this one for now. Decent enough coverage with the CONTEXT check.
        if (FindTimerCallback(pBuf, mbi.RegionSize, L"ntdll.dll", "NtContinue") ||
            FindTimerCallback(pBuf, mbi.RegionSize, L"ntdll.dll", "RtlRestoreContext"))
        {
            free(pBuf);
            return mbi.BaseAddress;
        }
        */

        free(pBuf);
    }

    // ToDo check for guard pages and hardware breakpoints on image sections.
    // ToDo Enumerate vectored handlers
    // https://dimitrifourny.github.io/2020/06/11/dumping-veh-win10.html.

    DeleteHandle(process.hProcess);

    return 0;
}

void EnumProcess(ProcessList& processList)
{
    HANDLE hSnap = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 proc32;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        goto Cleanup;
    }

    proc32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnap, &proc32))
    {
        goto Cleanup;
    }

    do
    {
        if (GetCurrentProcessId() == proc32.th32ProcessID)
        {
            continue;
        }
        processList.push_back(Process(proc32.th32ProcessID, proc32.szExeFile));

    } while ((Process32Next(hSnap, &proc32)) == TRUE);

Cleanup:

    DeleteHandle(hSnap);

    return;
}

BOOL GetPriv(const wchar_t* privName)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tkpPrev;
    LUID luid;
    TOKEN_PRIVILEGES tkp;
    BOOL bRet;
    ULONG ulRet;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    bRet = LookupPrivilegeValue(NULL, privName, &luid);
    if (!bRet)
    {
        CloseHandle(hToken);
        return bRet;
    }

    tkp.PrivilegeCount           = 1;
    tkp.Privileges[0].Luid       = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    bRet = AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), &tkpPrev, &ulRet);

    CloseHandle(hToken);

    return bRet;
}



void PrintProcessInfo(const Process& process) {
    printf("\n=== Process Information ===\n");
    printf("PID: %d\n", process.pid);
    printf("Process Name: %ws\n", process.processName.c_str());
    printf("Elevation Status: %s\n", process.bElevated ? "Elevated" : "Not Elevated");

    // Print memory statistics
    SIZE_T totalPrivateMemory = 0;
    SIZE_T totalExecutableMemory = 0;
    int regionCount = 0;

    for (const auto& mbi : process.memoryMap) {
        regionCount++;
        if (mbi->Type == MEM_PRIVATE) {
            totalPrivateMemory += mbi->RegionSize;
        }
        if (IsExecuteSet(mbi->Protect)) {
            totalExecutableMemory += mbi->RegionSize;
        }
    }

    printf("\n=== Memory Statistics ===\n");
    printf("Total Memory Regions: %d\n", regionCount);
    printf("Total Private Memory: %.2f MB\n", totalPrivateMemory / (1024.0 * 1024.0));
    printf("Total Executable Memory: %.2f MB\n", totalExecutableMemory / (1024.0 * 1024.0));
    printf("\n");
}

void PrintDetailedFindings(const std::vector<UPFinding>& findings) {
    if (findings.empty()) {
        printf("[+] No suspicious findings detected\n");
        return;
    }

    printf("\n=== Detailed Findings ===\n");

    // Count findings by type using a simpler approach
    std::vector<std::pair<std::string, int>> findingCounts;
    for (const auto& finding : findings) {
        bool typeFound = false;
        for (auto& count : findingCounts) {
            if (count.first == finding->type) {
                count.second++;
                typeFound = true;
                break;
            }
        }
        if (!typeFound) {
            findingCounts.push_back(std::make_pair(finding->type, 1));
        }
    }

    // Print summary
    printf("Total Findings: %zu\n", findings.size());
    printf("\nFindings by Type:\n");
    for (const auto& count : findingCounts) {
        printf("- %s: %d\n", count.first.c_str(), count.second);
    }

    // Print detailed findings
    printf("\nDetailed Findings:\n");
    int findingIndex = 1;
    for (const auto& finding : findings) {
        printf("\n--- Finding #%d ---\n", findingIndex++);
        printf("Level: %s\n", finding->level.c_str());
        printf("Type: %s\n", finding->type.c_str());
        printf("Process: %ws (PID: %d)\n", finding->processName.c_str(), finding->pid);
        printf("Details: %s\n", finding->details.c_str());

        if (finding->moduleInfo) {
            printf("Module Information:\n");
            printf("  Path: %ws\n", finding->moduleInfo->modulePathNt.c_str());
            printf("  Base Address: 0x%llx\n", finding->moduleInfo->moduleBase);
            printf("  Size: %.2f MB\n", finding->moduleInfo->moduleSize / (1024.0 * 1024.0));
        }

        SYSTEMTIME st;
        GetLocalTime(&st);
        printf("Timestamp: %04d-%02d-%02d %02d:%02d:%02d\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    }
}

int main(int argc, char** argv)
{
    printf("== Patriot Memory Scanner ==\n");
    printf("Copyright 2022 Joe Desimone. All rights reserved.\n");
    printf("Contact: @dez_\n");
    printf("Version: %s\n\n", PATRIOT_VERSION);

    DWORD targetPid = 0;
    bool verbose = false;
    bool fullScan = false;

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        const char* pArg = argv[i];
        if (0 == _stricmp(pArg, "-v")) {
            verbose = true;
            logLevel = debug;
        }
        else if (0 == _stricmp(pArg, "-p") && i + 1 < argc) {
            targetPid = atoi(argv[++i]);
        }
        else if (0 == _stricmp(pArg, "-f")) {
            fullScan = true;
        }
    }

    // Check arguments validity
    if (!fullScan && targetPid == 0) {
        printf("Usage: %s [options]\n", argv[0]);
        printf("Options:\n");
        printf("  -p <pid>    Scan specific Process ID\n");
        printf("  -f          Scan all processes\n");
        printf("  -v          Enable verbose output\n");
        return 1;
    }

    if (!GetPriv(SE_DEBUG_NAME)) {
        printf("Error getting debug privilege, err: %d\n", GetLastError());
    }

    ULONGLONG startTime = GetTickCount64();

    if (fullScan) {
        // Full system scan
        printf("[+] Starting full system scan...\n");

        ProcessList processList;
        EnumProcess(processList);

        int totalProcesses = processList.size();
        int scannedProcesses = 0;

        printf("[+] Found %d processes to scan\n", totalProcesses);

        for (auto& process : processList) {
            scannedProcesses++;
            printf("\n[%d/%d] Scanning PID: %d (%ws)\n",
                scannedProcesses, totalProcesses,
                process.pid, process.processName.c_str());

            ScanProc(process);

            if (verbose) {
                PrintProcessInfo(process);
            }
        }
    }
    else {
        // Single process scan
        printf("[+] Initiating scan of PID: %d\n", targetPid);

        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap == INVALID_HANDLE_VALUE) {
            printf("Error creating process snapshot, err: %d\n", GetLastError());
            return 1;
        }

        PROCESSENTRY32 proc32;
        proc32.dwSize = sizeof(PROCESSENTRY32);
        bool processFound = false;
        Process targetProcess(targetPid, L"");

        if (Process32First(hSnap, &proc32)) {
            do {
                if (proc32.th32ProcessID == targetPid) {
                    targetProcess = Process(targetPid, proc32.szExeFile);
                    processFound = true;
                    break;
                }
            } while (Process32Next(hSnap, &proc32));
        }

        CloseHandle(hSnap);

        if (!processFound) {
            printf("[-] Process with PID %d not found\n", targetPid);
            return 1;
        }

        printf("[+] Scanning process memory...\n");
        ScanProc(targetProcess);
        PrintProcessInfo(targetProcess);
    }

    // Print scan summary
    ULONGLONG endTime = GetTickCount64();
    double duration = (endTime - startTime) / 1000.0;

    printf("\n=== Scan Summary ===\n");
    printf("Scan Duration: %.2f seconds\n", duration);

    // Print findings
    if (Findings.empty()) {
        printf("[+] No suspicious findings detected\n");
    }
    else {
        PrintDetailedFindings(Findings);
    }

    return 0;
}
