// winject.c

#define MAX_CMDLINE_LEN 4096 // max command line length
#define MAX_PROCNAME_LEN 256 // max process name length

#define STDOUT ((DWORD)-11)
#define STDERR ((DWORD)-12)

#define F_SUSPEND  1
#define F_WAIT     2
#define F_PID      4
#define F_NAME     8
#define F_FILE     16

#include <windows.h>
#include <tlhelp32.h>

#pragma comment (lib, "ntdll.lib")

extern __declspec(dllimport) long __stdcall NtSuspendProcess(void* hProcess);
extern __declspec(dllimport) long __stdcall NtResumeProcess(void* hProcess);
extern __declspec(dllimport) long __stdcall RtlAdjustPrivilege(DWORD dwPrivilege, BOOL bEnablePrivilege, BOOL bIsThreadPrivilege, PBOOL pbPreviosValue);

char argv[MAX_CMDLINE_LEN];

#pragma function(memset)
void* __cdecl memset(void* dst, int val, size_t count) {
  void* start = dst;
  while (count--) {
    *(char*)dst = (char)val;
    dst = (char*)dst + 1;
  }
  return(start);
}

static __forceinline BOOL FileExistsA(const char* fileName) {
  DWORD fileAttr;
  fileAttr = GetFileAttributesA(fileName);
  if (INVALID_FILE_ATTRIBUTES == fileAttr) { // 0xFFFFFFFF (-1) 
    switch (GetLastError())
    {
      case ERROR_FILE_NOT_FOUND:
      case ERROR_PATH_NOT_FOUND:
      case ERROR_INVALID_NAME:
      case ERROR_INVALID_DRIVE:
      case ERROR_NOT_READY:
      case ERROR_INVALID_PARAMETER:
      case ERROR_BAD_PATHNAME:
      case ERROR_BAD_NETPATH:
        return FALSE;
      default:
        break;
    }
  }
  return TRUE;
}

static __forceinline char* _strrchr(char* s, char c) {
  while(*s != 0) {
    if(*s == c)
      return s;
    s++;
  }
  return 0;
}

static __forceinline int _atoi(char* s) {
  int a = 0, b = 0, x = 0, i = 0, len = 0;
  len = lstrlenA(s);
  for (x = 0; x < len; x++) {
    if (s[x] == 48) continue;
    if (s[x] > 48 && s[x] < 58) {
      a = 1;
      if (x < len-1)
        for (b = 0; b < len-x-1; ++b)
          a *= 10;
      a *= (s[x]-48);
      i += a;
    }
    else
      return 0;
  }
  return i;
}

static BOOL GetProcInfo(char* process, DWORD* pid) {
  PROCESSENTRY32 lppe = {0};
  char* pname;

  HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot) {
    lppe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot,&lppe)) {
      do {
        pname = _strrchr(lppe.szExeFile, '\\');
        if (pname) {
          pname++;
        } else {
          pname = lppe.szExeFile;
        }
        if (*process == 0) {
          if(*pid == lppe.th32ProcessID) {
            lstrcpyA(process, pname);
            break;
          }
        } else if(!lstrcmpiA(process, pname)) {
          *pid=lppe.th32ProcessID;
          break;
        }
      } while (Process32Next(hSnapshot,&lppe));
    }
    CloseHandle(hSnapshot);
  }
  return (*pid != 0 && *process != 0);
}

static __forceinline void chrreplace(char* s, char a, char b) {
  while (*s != 0) {
    if(*s == a)
      *s = b;
    s++;
  }
}

static char* get_next_arg(char* s, BOOL write) {
  while(*s != 0 && (*s == ' ' || *s == '\t')) {
    s++;
  }
  if (*s == '"') {
    s++;
    while(*s != 0 && *s != '"') {
      s++;
    }
  }
  while(*s != 0 && *s != ' ' && *s != '\t') {
    s++;
  }
  while(*s != 0 && (*s == ' ' || *s == '\t')) {
    if (write)
      *s = 0;
    s++;
  }
  return s;
}

static char* strip_quotes(char* s) {
  while (*s != 0 && *s == '\"') {
    s++;
  }
  chrreplace(s, '\"', 0);
  return s;
}

static void _ioprint(DWORD std_handle, const char* cbuf) {
  DWORD u = 0;
  WriteFile(GetStdHandle(std_handle), cbuf, lstrlenA(cbuf), &u, 0);
}

static __forceinline void print(const char* cbuf) {
  _ioprint(STDOUT, cbuf);
}

static __forceinline int error(const char* cbuf) {
  _ioprint(STDERR, cbuf);
  return 1;
}

static void _fmt_ioprint(DWORD std_handle, const char *fmt, DWORD_PTR arg1, DWORD_PTR arg2, DWORD_PTR arg3) {
  char* fmt_str = 0;
  DWORD_PTR pArgs[] = { (DWORD_PTR)arg1, (DWORD_PTR)arg2, (DWORD_PTR)arg3 };
  if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, fmt, 0, 0, (LPSTR)&fmt_str, 0, (va_list*)pArgs)) {
    _ioprint(std_handle, fmt_str);
    LocalFree(fmt_str);
  }
}

static __forceinline void fmt_print(const char *fmt, DWORD_PTR arg1, DWORD_PTR arg2, DWORD_PTR arg3) {
  _fmt_ioprint(STDOUT, fmt, arg1, arg2, arg3);
}

static __forceinline int fmt_error(const char *fmt, DWORD_PTR arg1, DWORD_PTR arg2, DWORD_PTR arg3) {
  _fmt_ioprint(STDERR, fmt, arg1, arg2, arg3);
  return 1;
}

static int usage() {
  return error("Usage: winject <dll...> <[-x] [-w] -p procname | [-x] -u pid | -s exe [args...]>\r\n");
}

int main() {
  char *cmdline, *parg, *pnext;
  DWORD flags=0, pid=0;
  int args_len=0, libcount=0, i=0;
  char procname[MAX_PROCNAME_LEN];
  void *page;
  HANDLE hThread = NULL;
  HANDLE hProc = NULL;
  STARTUPINFO si = {0};
  PROCESS_INFORMATION pi = {0};
  DWORD dwErr = 0;
  //TOKEN_PRIVILEGES tkp;
  //HANDLE hToken;

  cmdline = GetCommandLineA();
  if(!cmdline) return fmt_error("kernel32:GetCommandLineA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");

  parg = get_next_arg(cmdline, FALSE);
  args_len = lstrlenA(parg);
  if (!args_len) return usage();
  if (args_len > MAX_CMDLINE_LEN) return error("Command line is too long > 4096\r\n");

  //print(cmdline);
  //print("\r\n");

  lstrcpyA(argv, parg);

  parg = argv;

  while (*parg != 0) {
    pnext = get_next_arg(parg, TRUE);

    parg = strip_quotes(parg);
    //fmt_print("arg: '%1'\r\n", (DWORD_PTR)parg, (DWORD_PTR)"", (DWORD_PTR)"", (DWORD_PTR)"");

    if (parg[0] == '-' || parg[0] == '/' && parg[1] != 0 && parg[2] == 0) {
      if (parg[1] == '?' || parg[1] == 'h' || parg[1] == 'H') return usage();
      if (parg[1] == 'u' || parg[1] == 'U') {
        flags = F_PID;
        break;
      }
      if (parg[1] == 's' || parg[1] == 'S') {
        flags = F_FILE;
        break;
      }
      if (parg[1] == 'p' || parg[1] == 'P') {
        flags = F_NAME;
        break;
      }
      if (parg[1] == 'x' || parg[1] == 'X') {
        flags |= F_SUSPEND;
        parg = pnext;
        continue;
      }
      if (parg[1] == 'w' || parg[1] == 'W') {
        flags |= F_WAIT;
        parg = pnext;
        continue;
      }
    }

    if (lstrlenA(parg) > MAX_PATH-1) return fmt_error("Path length exceeds MAX_PATH (%1!u!): '%2'\r\n", (DWORD_PTR)MAX_PATH, (DWORD_PTR)parg, (DWORD_PTR)"");
    if (!FileExistsA(parg)) return fmt_error("File does not exist: '%1'\r\n", (DWORD_PTR)parg, (DWORD_PTR)"", (DWORD_PTR)"");
    libcount++;
 
    parg = pnext;
  }

  if (libcount == 0 || flags < 4) return usage();
  parg = pnext;

  //print(parg);

  if (flags & F_FILE) {
    si.cb = sizeof(STARTUPINFO);
    if (!CreateProcess(NULL, parg, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
      return fmt_error("kernel32:CreateProcess() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
    }
    hProc = pi.hProcess;
    pid = pi.dwProcessId;
  }
  else if (flags & F_NAME) {
    parg = strip_quotes(parg);
    if (!GetProcInfo(parg, &pid)) {
      if (flags & F_WAIT) {
        fmt_print("Waiting for process '%1' ...\r\n", (DWORD_PTR)parg, (DWORD_PTR)"", (DWORD_PTR)"");
        while (!GetProcInfo(parg, &pid)) Sleep(500);
      } else {
        return fmt_error("Could not find process with name '%1'\r\n", (DWORD_PTR)parg, (DWORD_PTR)"", (DWORD_PTR)"");
      }
    }
  }
  else if (flags & F_PID) {
    parg = strip_quotes(parg);
    pid = _atoi(parg);
    *procname = 0;
    if (!GetProcInfo(procname, &pid)) {
      return fmt_error("Could not find process with PID '%1!u!'\r\n", (DWORD_PTR)pid, (DWORD_PTR)"", (DWORD_PTR)"");
    }
  }
  //else return error("wtf");

  if (flags & (F_NAME | F_PID)) {
    /*if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
      return fmt_error("kernel32:OpenProcessToken() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
      if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
        fmt_error("kernel32:LookupPrivilegeValueA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
        CloseHandle(hToken);
        return 1;
      }

    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
    dwErr = GetLastError();
    CloseHandle(hToken);

    if (dwErr != ERROR_SUCCESS) {
      fmt_error("kernel32:AdjustTokenPrivileges() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"", (DWORD_PTR)"");
      return 1;
    }*/

    BOOL bPrev = FALSE;
    dwErr = RtlAdjustPrivilege(/* SE_DEBUG_PRIVILEGE */ 20, TRUE, FALSE, &bPrev);
    if (dwErr != ERROR_SUCCESS) {
      fmt_error("ntdll:RtlAdjustPrivilege() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"", (DWORD_PTR)"");
      return 1;
    }

    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) {
      return fmt_error("kernel32:OpenProcess() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
    }

    if (flags & F_SUSPEND) {
      dwErr = NtSuspendProcess(hProc);
      if(dwErr != ERROR_SUCCESS) {
        return fmt_error("ntdll:NtSuspendProcess() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"", (DWORD_PTR)"");
      }
    }
  }

  fmt_print("Opened process PID:'%1!u!'\r\n", (DWORD_PTR)pid, (DWORD_PTR)"", (DWORD_PTR)"");

  page = VirtualAllocEx(hProc, NULL, MAX_PATH, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
  if (!page) {
    fmt_error("kernel32:VirtualAllocEx() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
    if (flags & F_FILE) CloseHandle(pi.hThread);
    CloseHandle(hProc);
    return 1;
  }

  parg = argv;
  for (i = 1; i <= libcount; i++) {
    while (*parg == 0 || *parg == ' ' || *parg == '\t') {
      parg++;
    }
    fmt_print("Loading module (%1!d!/%2!d!): '%3'\r\n", (DWORD_PTR)i, (DWORD_PTR)libcount, (DWORD_PTR)parg);

    if (!WriteProcessMemory(hProc, page, parg, lstrlenA(parg)+1, NULL)) {
      fmt_error("kernel32:WriteProcessMemory() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
      VirtualFreeEx(hProc, page, 0, MEM_RELEASE);
      if (flags & F_FILE) CloseHandle(pi.hThread);
      CloseHandle(hProc);
      return 1;
    }

    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, page, 0, NULL);
    if (!hThread) {
      fmt_error("kernel32:CreateRemoteThread() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
      VirtualFreeEx(hProc, page, 0, MEM_RELEASE);
      if (flags & F_FILE) CloseHandle(pi.hThread);
      CloseHandle(hProc);
      return 1;
    }

    if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
      fmt_error("kernel32:WaitForSingleObject() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
      CloseHandle(hThread);
      VirtualFreeEx(hProc, page, 0, MEM_RELEASE);
      if (flags & F_FILE) CloseHandle(pi.hThread);
      CloseHandle(hProc);
      return 1;
    }
    CloseHandle(hThread);
    parg++;
  }
  if (!VirtualFreeEx(hProc, page, 0, MEM_RELEASE)) {
    fmt_error("kernel32:VirtualFreeEx() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
  }

  if (flags & F_FILE) {
    if (ResumeThread(pi.hThread) == (DWORD)-1) {
      fmt_error("kernel32:ResumeThread() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
    }
    CloseHandle(pi.hThread);
  }
  else if (flags & F_SUSPEND) {
    dwErr = NtResumeProcess(hProc);
    if(dwErr != ERROR_SUCCESS) {
      fmt_error("ntdll:NtResumeProcess() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)dwErr, (DWORD_PTR)"", (DWORD_PTR)"");
    }
  }

  CloseHandle(hProc);
  print("Done\r\n");
  return 0;
}
