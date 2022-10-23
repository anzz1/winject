### winject (yet another windows injector)


features:
- tiny
- no CRT (imports only kernel32.dll and ntdll.dll)
- 64-bit / 32-bit
- WinXP+ compatible
- can inject multiple dlls at once

usage:  

winject <dll...> <[-x] [-w] -p procname | [-x] -u pid | -s exe [args...]>

| Option | Description |
| --- | --- |
| -s exe [args...]   | start new process (with optional args) |
| -u pid     | inject to existing process by pid |
| -p procname     | inject to existing process by name |
| -w     | wait for process to be found instead of exiting |
| -x     | suspend process -> inject -> unsuspend |

