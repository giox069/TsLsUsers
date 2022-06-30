// LogoffRDPUsers.c
//

#include "pch.h"
#include <stdio.h>
#include <tchar.h>
#include <windows.h>
#include <strsafe.h>
#include <WtsApi32.h>
#include <time.h>

void ErrorPrintAndExit(LPTSTR lpszFunction)
{

	LPVOID lpMsgBuf;
	LPVOID lpDisplayBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);


	lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT,
		(lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
	StringCchPrintf((LPTSTR)lpDisplayBuf,
		LocalSize(lpDisplayBuf) / sizeof(TCHAR),
		TEXT("%s failed with error %d: %s"),
		lpszFunction, dw, lpMsgBuf);
	_putts((LPCTSTR)lpDisplayBuf);

	LocalFree(lpMsgBuf);
	LocalFree(lpDisplayBuf);
	ExitProcess(dw);
}

void usage(TCHAR *exepath)
{
	_tprintf(_T("Use %s [/logoff] [/outfile:filename] [/csv|/json]\n"), exepath);
	ExitProcess(1);
}

static struct {
	TCHAR in;
	TCHAR out;
} jesc[] = {
	{ '"', '"' },
	{ '\\', '\\' },
	{ '/', '/' },
	{ '\b', 'b' },
	{ '\f', 'f' },
	{ '\n', 'n' },
	{ '\r', 'r' },
	{ '\t', 't' }
};

TCHAR *json_escape(TCHAR *in)
{
	TCHAR c;
	int bufUsed = 0;
#define JBUFLEN 128
	int ec;
	BOOL escaped;

	TCHAR *obuf = malloc(sizeof(TCHAR) * JBUFLEN);

	while ((c = *in++) != 0) {
		escaped = FALSE;
		for (ec = 0; ec < (sizeof(jesc) / sizeof(jesc[0])); ec++) {
			if (jesc[ec].in == c) {
				if (bufUsed >= JBUFLEN - 3)
					break;
				obuf[bufUsed++] = '\\';
				obuf[bufUsed++] = jesc[ec].out;
				escaped = TRUE;
				break;
			}
		}
		if (!escaped) {
			if (bufUsed >= JBUFLEN - 2)
				break;
			obuf[bufUsed++] = c;
		}
	}
	obuf[bufUsed] = 0;
	return obuf;
}


int _tmain(int argc, TCHAR *argv[])
{
	HANDLE hServer;
	DWORD level;

	PWTS_SESSION_INFO_1W s;
	DWORD sCount, i, locount;
	int n;

	ULONG *mySessionId;
	DWORD lenMySessionId;

	hServer = WTS_CURRENT_SERVER_HANDLE;
	TCHAR username[128];
	TCHAR *outFileName = NULL;

	BOOL doLogoff = FALSE;
	enum {
		FORMAT_DEFAULT,
		FORMAT_CSV,
		FORMAT_JSON
	} outputFormat = FORMAT_DEFAULT;
	FILE *fout;
	TCHAR *actionStatus;

	time_t rawtime;
	struct tm timeinfo;


	if (argc > 1) {
		for (n = 1; n < argc; n++) {
			if (_tcsicmp(argv[n], _T("/logoff")) == 0)
				doLogoff = TRUE;
			else if (_tcsnicmp(argv[n], _T("/outfile:"), 9) == 0)
				outFileName = argv[n] + 9;
			else if (_tcsicmp(argv[n], _T("/csv")) == 0)
				outputFormat = FORMAT_CSV;
			else if (_tcsicmp(argv[n], _T("/json")) == 0)
				outputFormat = FORMAT_JSON;
			else
				usage(argv[0]);
		}
	}

	if (outFileName != NULL) {
		errno_t err;
		err = _tfopen_s(&fout, outFileName, _T("wt"));
		if (err) {
			TCHAR errBuf[200];
			fout = stdout;
			_tcserror_s(errBuf, sizeof(errBuf) / sizeof(WORD), err);
			_tprintf(_T("Unable to create outfile %s: %s\n"), outFileName, errBuf);
		}
	}
	else
		fout = stdout;


	// https://docs.microsoft.com/en-us/windows/win32/api/wtsapi32/ns-wtsapi32-wts_session_info_1w/


	/* Get current session ID to avoid disconnect ourselves */
	if (!WTSQuerySessionInformationW(hServer, WTS_CURRENT_SESSION, WTSSessionId, (LPWSTR *)&mySessionId, &lenMySessionId))
		ErrorPrintAndExit(_T("WTSQuerySessionInformationW returned an error: "));

	level = 1;
	if (!WTSEnumerateSessionsExW(hServer, &level, 0, &s, &sCount))
		ErrorPrintAndExit(_T("WTSEnumerateSessionsExW returned an error: "));


	/* Start with output */
	time(&rawtime);
	localtime_s(&timeinfo, &rawtime);
	if (outputFormat == FORMAT_DEFAULT) {
		if (outFileName != NULL) {
			_ftprintf(fout, _T("[%04d-%02d-%02d %02d:%02d:%02d]\n"),
				timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
				timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
		}
		_ftprintf(fout, _T("%-6s %-18.18s %-30.30s %-4.4s %s\n"), _T("SesID"), _T("SessionName"),
			_T("UserName"), _T("This"), _T("actionStatus"));
	}
	else if (outputFormat == FORMAT_CSV) {
		_fputts(_T("\"SessionID\",\"SessionName\",\"UserName\",\"isThisSession\",\"actionStatus\"\n"), fout);
	}
	else if (outputFormat == FORMAT_JSON) {
		_ftprintf(fout, _T("{\n"
			"\"datetime\": \"[%04d-%02d-%02d %02d:%02d:%02d]\",\n"
			"\"sessions\": [\n"),
			timeinfo.tm_year + 1900, timeinfo.tm_mon + 1, timeinfo.tm_mday,
			timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
	}


	for (i = 0, locount = 0; i < sCount; i++) {
		if (s[i].pUserName != NULL) {
			if (s[i].pDomainName != NULL)
				_sntprintf_s(username, sizeof(username) / sizeof(TCHAR), _TRUNCATE, _T("%s\\%s"), s[i].pDomainName, s[i].pUserName);
			else
				_sntprintf_s(username, sizeof(username) / sizeof(TCHAR), _TRUNCATE, _T("%s"), s[i].pUserName);
		}
		else
			_sntprintf_s(username, sizeof(username) / sizeof(TCHAR), _TRUNCATE, _T("%s"), _T(""));

		if (outputFormat == FORMAT_DEFAULT) {
			_ftprintf(fout, _T("%-6u %-18.18s %-30.30s %-4.4s"), (unsigned)s[i].SessionId,
				s[i].pSessionName == NULL ? _T("?") : s[i].pSessionName,
				_tcslen(username) == 0 ? _T("-") : username,
				*mySessionId == s[i].SessionId ? _T("Yes"): _T("-"));
		}
		else if (outputFormat == FORMAT_CSV) {
			_ftprintf(fout, _T("\"%u\",\"%s\",\"%s\",\"%s\","), (unsigned)s[i].SessionId,
				s[i].pSessionName == NULL ? _T("") : s[i].pSessionName,
				username,
				*mySessionId == s[i].SessionId ? _T("Yes"): _T("-"));
		}
		else if (outputFormat == FORMAT_JSON) {
			TCHAR *sname, *uname;
			sname = json_escape(s[i].pSessionName == NULL ? _T("?") : s[i].pSessionName);
			uname = json_escape(username);
			_ftprintf(fout, _T("\t{ "
					"\"sessionid\": %u,"
					"\"sessionname\": \"%s\","
					"\"username\": \"%s\", "
					"\"isThisSession\": %s, "
					), (unsigned)s[i].SessionId,
				sname,
				uname,
				*mySessionId == s[i].SessionId ? _T("true"): _T("false"));
			free(uname);
			free(sname);
		}

		/* Execute logoff */
		actionStatus = _T("");
		if (s[i].SessionId != 0) { // skip session 0 "Services"
			if (s[i].SessionId != *mySessionId) { // skip current session
				if (doLogoff) {
					actionStatus = _T("LOGOFF REQUESTED");
					locount++;
					WTSLogoffSession(hServer, s[i].SessionId, TRUE);
				}
			}
		}

		/* Close the line output */
		if (outputFormat == FORMAT_DEFAULT)
			_ftprintf(fout, _T(" %s\n"), actionStatus);
		else if (outputFormat == FORMAT_CSV)
			_ftprintf(fout, _T("\"%s\"\n"), actionStatus);
		else if (outputFormat == FORMAT_JSON) {
			TCHAR *astatus;
			astatus = json_escape(actionStatus);
			_ftprintf(fout, _T("\"actionstatus\":\"%s\" }"), actionStatus);
			free(astatus);
			if (i < sCount - 1)
				_ftprintf(fout, _T(","));
			_ftprintf(fout, _T("\n"));
		}
	}

	/* Close the output */
	if (outputFormat == FORMAT_JSON) {
		_ftprintf(fout, _T("]}\n"));
	}

	WTSFreeMemory(mySessionId);
	WTSFreeMemoryExW(WTSTypeSessionInfoLevel1, (PVOID)s, sCount);
	if (fout != stdout) {
		fclose(fout);
		fout = NULL;
	}

	return 0;


}

