#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <map>
#include <string>
#include <fstream>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <psapi.h>

// Windows API için gerekli tanımlamalar
typedef LONG NTSTATUS;
typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    ThreadTimes,
    ThreadPriority,
    ThreadBasePriority,
    ThreadAffinityMask,
    ThreadImpersonationToken,
    ThreadDescriptorTableEntry,
    ThreadEnableAlignmentFaultFixup,
    ThreadEventPair_Reusable,
    ThreadQuerySetWin32StartAddress,
    ThreadZeroTlsCell,
    ThreadPerformanceCount,
    ThreadAmILastThread,
    ThreadIdealProcessor,
    ThreadPriorityBoost,
    ThreadSetTlsArrayAddress,
    ThreadIsIoPending,
    ThreadHideFromDebugger,
    ThreadBreakOnTermination,
    ThreadSwitchLegacyState,
    ThreadIsTerminated,
    ThreadLastSystemCall,
    ThreadIoPriority,
    ThreadCycleTime,
    ThreadPagePriority,
    ThreadActualBasePriority,
    ThreadTebInformation,
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context,
    ThreadGroupInformation,
    ThreadUmsInformation,
    ThreadCounterProfiling,
    ThreadIdealProcessorEx,
    MaxThreadInfoClass
} THREADINFOCLASS;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

extern "C" NTSTATUS NTAPI NtQueryInformationThread(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

// Global değişkenler
const DWORD THREAD_QUERY_INFO = THREAD_QUERY_INFORMATION;
const DWORD THREAD_SUSPEND = THREAD_SUSPEND_RESUME;

// Güvenli thread işlemleri için wrapper sınıf
class ThreadHandle {
private:
    HANDLE handle;
public:
    ThreadHandle(HANDLE h) : handle(h) {}
    ThreadHandle(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId) {
        handle = OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    }
    ~ThreadHandle() {
        if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    }
    operator HANDLE() const { return handle; }
    bool isValid() const { return handle != NULL && handle != INVALID_HANDLE_VALUE; }
};

// Thread cycle time alma fonksiyonu
ULONGLONG GetThreadCycleTime(DWORD threadID) {
    ThreadHandle hThread(THREAD_QUERY_INFO, FALSE, threadID);
    if (!hThread.isValid()) return 0;

    FILETIME creation, exit, kernel, user;
    if (!GetThreadTimes(hThread, &creation, &exit, &kernel, &user)) {
        return 0;
    }

    ULONGLONG kernelTime = (((ULONGLONG)kernel.dwHighDateTime) << 32) | kernel.dwLowDateTime;
    ULONGLONG userTime = (((ULONGLONG)user.dwHighDateTime) << 32) | user.dwLowDateTime;
    
    return kernelTime + userTime;
}

// Thread askıya alma fonksiyonu
bool SuspendThreadByID(DWORD threadID) {
    ThreadHandle hThread(THREAD_SUSPEND, FALSE, threadID);
    if (!hThread.isValid()) return false;

    return SuspendThread(hThread) != (DWORD)-1;
}

// Aktif threadleri bulma fonksiyonu
std::map<DWORD, ULONGLONG> FindActiveThreads(const std::string& processName = "vgc.exe") {
    std::map<DWORD, ULONGLONG> activeThreads;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
    
    if (snapshot == INVALID_HANDLE_VALUE) return activeThreads;
    ThreadHandle hSnapshot(snapshot);

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snapshot, &pe)) {
        do {
            std::wstring wProcessName(pe.szExeFile);
            std::string currentProcessName(wProcessName.begin(), wProcessName.end());
            
            if (_stricmp(currentProcessName.c_str(), processName.c_str()) == 0) {
                THREADENTRY32 te = { sizeof(te) };
                if (Thread32First(snapshot, &te)) {
                    do {
                        if (te.th32OwnerProcessID == pe.th32ProcessID) {
                            ULONGLONG cycles = GetThreadCycleTime(te.th32ThreadID);
                            if (cycles > 10000) {
                                activeThreads[te.th32ThreadID] = cycles;
                            }
                        }
                    } while (Thread32Next(snapshot, &te));
                }
            }
        } while (Process32NextW(snapshot, &pe));
    }

    return activeThreads;
}

// VGC servisini başlatma fonksiyonu
bool EnsureVGCRunning() {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    char cmdLine[] = "sc start vgc";
    
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cout << "[ERROR] VGC servisi başlatılamadı.\n";
        return false;
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    return true;
}

// Güzel bir menü arayüzü
void DisplayMenu() {
    system("cls");
    std::cout << R"(
 ██████╗██╗ █████╗ ███████╗██╗   ██╗
██╔════╝██║██╔══██╗██╔════╝╚██╗ ██╔╝
██║     ██║███████║█████╗   ╚████╔╝ 
██║     ██║██╔══██║██╔══╝    ╚██╔╝  
╚██████╗██║██║  ██║███████╗   ██║   
 ╚═════╝╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   
discord.gg/ciaey
)" << std::endl;
    std::cout << "\n1. Bypass\n2. Çıkış\nSeçenek: ";
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    while (true) {
        DisplayMenu();
        int option;
        std::cin >> option;

        if (option == 1) {
            if (!EnsureVGCRunning()) {
                std::cout << "[ERROR] VGC servisi başlatılamadı.\n";
                continue;
            }

            std::cout << "[INFO] İşlem başlatılıyor...\n";
            std::this_thread::sleep_for(std::chrono::seconds(3));

            auto threads = FindActiveThreads();
            if (threads.size() < 4) {
                std::cout << "[ERROR] Yeterli aktif thread bulunamadı.\n";
                continue;
            }

            std::cout << "[BİLGİ] League of Legends veya Valorant'ı açın: 01:00\n";
            for (int i = 60; i > 0; --i) {
                std::cout << "\r[BİLGİ] League of Legends veya Valorant'ı açın: 00:" 
                         << std::setw(2) << std::setfill('0') << i << std::flush;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            for (const auto& thread : threads) {
                SuspendThreadByID(thread.first);
            }

            std::cout << "\n[BİLGİ] 3 dakika bekleyin, sonra inject edin...\n";
            for (int i = 180; i > 0; --i) {
                int minutes = i / 60;
                int seconds = i % 60;
                std::cout << "\r[BİLGİ] Kalan süre: " 
                         << std::setw(2) << std::setfill('0') << minutes << ":"
                         << std::setw(2) << std::setfill('0') << seconds << std::flush;
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            std::cout << "\n[BİLGİ] Artık hile kullanabilirsiniz!\n";
        } else if (option == 2) {
            std::cout << "Çıkış yapılıyor...\n";
            break;
        } else {
            std::cout << "[ERROR] Geçersiz seçenek.\n";
        }
    }

    return 0;
}
