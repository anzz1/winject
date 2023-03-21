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

__forceinline static void* __memset(void* dst, int val, size_t count) {
  void* start = dst;
  while (count--) {
    *(char*)dst = (char)val;
    dst = (char*)dst + 1;
  }
  return start;
}

__forceinline static BOOL FileExistsA(const char* fileName) {
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

__forceinline static int __stricmp(const char* s1, const char* s2) {
  char c1, c2;
  do {
    if (*s1 == 0 && *s2 == 0) return 0;
    c1 = (*s1>64 && *s1<91) ? (*s1+32):*s1; // A-Z -> a-z
    c2 = (*s2>64 && *s2<91) ? (*s2+32):*s2; // A-Z -> a-z
    s1++; s2++;
  } while (c1 == c2);
  return (*s1 > *s2) ? 1 : -1;
}
__forceinline static char* __strrchr(const char* s, char c) {
  char *p = 0;
  while (*s != 0) {
    if (*s == c)
      p = (char*)s;
    s++;
  }
  return p;
}
__forceinline static unsigned int __strlen(const char* s) {
  unsigned int i = 0;
  while (s[i] != 0) i++;
  return i;
}
__forceinline static char* __strcpy(char* dst, const char* src) {
  char *p = dst;
  while (*src != 0) *p++ = *src++;
  *p = 0;
  return dst;
}
__forceinline static char* __strreplacechr(char* s, char a, char b) {
  char *p = s;
  while (*p != 0) {
    if(*p == a)
      *p = b;
    p++;
  }
  return s;
}
__forceinline static int __atoi(char* a)
{
  int i,x;
  for (i = 0, x = 0; a[i] != 0; i++)
    x = x * 10 + a[i] - 48;
  return x;
}

static BOOL GetProcInfo(char* process, DWORD* pid) {
  PROCESSENTRY32 lppe;
  char* pname;
  HANDLE hSnapshot;

  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot) {
    __memset(&lppe, 0, sizeof(PROCESSENTRY32));
    lppe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot,&lppe)) {
      do {
        pname = __strrchr(lppe.szExeFile, '\\');
        if (pname) {
          pname++;
        } else {
          pname = lppe.szExeFile;
        }
        if (*process == 0) {
          if(*pid == lppe.th32ProcessID) {
            __strcpy(process, pname);
            break;
          }
        } else if(!__stricmp(process, pname)) {
          *pid=lppe.th32ProcessID;
          break;
        }
      } while (Process32Next(hSnapshot,&lppe));
    }
    CloseHandle(hSnapshot);
  }
  return (*pid != 0 && *process != 0);
}

__forceinline static char* get_next_arg(char* s, BOOL write) {
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

__forceinline static char* strip_quotes(char* s) {
  return __strreplacechr(s, '\"', 0);;
}

__forceinline static void _ioprint(DWORD std_handle, const char* cbuf) {
  DWORD u = 0;
  WriteFile(GetStdHandle(std_handle), cbuf, __strlen(cbuf), &u, 0);
}

__forceinline static void print(const char* cbuf) {
  _ioprint(STDOUT, cbuf);
}

__forceinline static int error(const char* cbuf) {
  _ioprint(STDERR, cbuf);
  return 1;
}

__forceinline static void _fmt_ioprint(DWORD std_handle, const char *fmt, DWORD_PTR arg1, DWORD_PTR arg2, DWORD_PTR arg3) {
  char* fmt_str = 0;
  DWORD_PTR pArgs[] = { (DWORD_PTR)arg1, (DWORD_PTR)arg2, (DWORD_PTR)arg3 };
  if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_STRING | FORMAT_MESSAGE_ARGUMENT_ARRAY, fmt, 0, 0, (LPSTR)&fmt_str, 0, (va_list*)pArgs)) {
    _ioprint(std_handle, fmt_str);
    LocalFree(fmt_str);
  }
}

__forceinline static void fmt_print(const char *fmt, DWORD_PTR arg1, DWORD_PTR arg2, DWORD_PTR arg3) {
  _fmt_ioprint(STDOUT, fmt, arg1, arg2, arg3);
}

__forceinline static int fmt_error(const char *fmt, DWORD_PTR arg1, DWORD_PTR arg2, DWORD_PTR arg3) {
  _fmt_ioprint(STDERR, fmt, arg1, arg2, arg3);
  return 1;
}

__forceinline static int usage() {
  return error("Usage: winject <dll...> <[-x] [-w] -p procname | [-x] -u pid | -s exe [args...]>\r\n");
}

int main() {
  char *cmdline, *parg, *pnext;
  DWORD flags=0, pid=0;
  int args_len=0, libcount=0, i=0;
  unsigned int libpath_len = 0;
  char procname[MAX_PROCNAME_LEN];
  char libpath[MAX_PATH+1];
  void *page;
  HANDLE hThread = NULL;
  HANDLE hProc = NULL;
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  DWORD dwErr = 0;
  //TOKEN_PRIVILEGES tkp;
  //HANDLE hToken;

  __memset(&si, 0, sizeof(STARTUPINFO));
  __memset(&pi, 0, sizeof(PROCESS_INFORMATION));

  cmdline = GetCommandLineA();
  if(!cmdline) return fmt_error("kernel32:GetCommandLineA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");

  parg = get_next_arg(cmdline, FALSE);
  args_len = __strlen(parg);
  if (!args_len) return usage();
  if (args_len > MAX_CMDLINE_LEN) return error("Command line is too long > 4096\r\n");

  //print(cmdline);
  //print("\r\n");

  __strcpy(argv, parg);

  parg = argv;

  while (*parg != 0) {
    pnext = get_next_arg(parg, TRUE);

    parg = strip_quotes(parg);
    //fmt_print("arg: '%1'\r\n", (DWORD_PTR)parg, (DWORD_PTR)"", (DWORD_PTR)"", (DWORD_PTR)"");

    if (parg[0] == '-' || parg[0] == '/' && parg[1] != 0 && parg[2] == 0) {
      if (parg[1] == '?' || parg[1] == 'h' || parg[1] == 'H') return usage();
      if (parg[1] == 'u' || parg[1] == 'U') {
        flags |= F_PID;
        break;
      }
      if (parg[1] == 's' || parg[1] == 'S') {
        flags = F_FILE;
        break;
      }
      if (parg[1] == 'p' || parg[1] == 'P') {
        flags |= F_NAME;
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

    if (__strlen(parg) > MAX_PATH) return fmt_error("Path length exceeds MAX_PATH (%1!u!): '%2'\r\n", (DWORD_PTR)MAX_PATH, (DWORD_PTR)parg, (DWORD_PTR)"");
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
    pid = __atoi(parg);
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

  page = VirtualAllocEx(hProc, NULL, MAX_PATH+1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
  if (!page) {
    fmt_error("kernel32:VirtualAllocEx() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
    if (flags & F_FILE) {
      ResumeThread(pi.hThread);
      CloseHandle(pi.hThread);
    }
    else if (flags & F_SUSPEND) NtResumeProcess(hProc);
    CloseHandle(hProc);
    return 1;
  }

  parg = argv;
  for (i = 1; i <= libcount; i++) {
    while (*parg == 0 || *parg == ' ' || *parg == '\t') {
      parg++;
    }
    libpath_len = GetFullPathNameA(parg, MAX_PATH+1, libpath, NULL);

    if (!libpath_len) {
      fmt_error("kernel32:GetFullPathNameA() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
      VirtualFreeEx(hProc, page, 0, MEM_RELEASE);
      if (flags & F_FILE) {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
      }
      else if (flags & F_SUSPEND) NtResumeProcess(hProc);
      CloseHandle(hProc);
      return 1;
    }

    if (libpath_len > MAX_PATH) {
      fmt_error("Path length exceeds MAX_PATH (%1!u!): '%2'\r\n", (DWORD_PTR)MAX_PATH, (DWORD_PTR)libpath, (DWORD_PTR)"");
      VirtualFreeEx(hProc, page, 0, MEM_RELEASE);
      if (flags & F_FILE) {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
      }
      else if (flags & F_SUSPEND) NtResumeProcess(hProc);
      CloseHandle(hProc);
      return 1;
    }

    fmt_print("Loading module (%1!d!/%2!d!): '%3'\r\n", (DWORD_PTR)i, (DWORD_PTR)libcount, (DWORD_PTR)libpath);

    if (!WriteProcessMemory(hProc, page, libpath, libpath_len+1, NULL)) {
      fmt_error("kernel32:WriteProcessMemory() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
      VirtualFreeEx(hProc, page, 0, MEM_RELEASE);
      if (flags & F_FILE) {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
      }
      else if (flags & F_SUSPEND) NtResumeProcess(hProc);
      CloseHandle(hProc);
      return 1;
    }

    hThread = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, page, 0, NULL);
    if (!hThread) {
      fmt_error("kernel32:CreateRemoteThread() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
      VirtualFreeEx(hProc, page, 0, MEM_RELEASE);
      if (flags & F_FILE) {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
      }
      else if (flags & F_SUSPEND) NtResumeProcess(hProc);
      CloseHandle(hProc);
      return 1;
    }

    if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
      fmt_error("kernel32:WaitForSingleObject() failed; error code = 0x%1!08X!\r\n", (DWORD_PTR)GetLastError(), (DWORD_PTR)"", (DWORD_PTR)"");
      CloseHandle(hThread);
      VirtualFreeEx(hProc, page, 0, MEM_RELEASE);
      if (flags & F_FILE) {
        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
      }
      else if (flags & F_SUSPEND) NtResumeProcess(hProc);
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
