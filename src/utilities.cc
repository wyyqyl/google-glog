// Copyright (c) 2008, Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Author: Shinichiro Hamaji

#include "utilities.h"

#include <stdio.h>
#include <stdlib.h>

#include <signal.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#include <time.h>
#if defined(HAVE_SYSCALL_H)
#include <syscall.h>                 // for syscall()
#elif defined(HAVE_SYS_SYSCALL_H)
#include <sys/syscall.h>                 // for syscall()
#endif
#ifdef HAVE_SYSLOG_H
# include <syslog.h>
#endif

#include "base/googleinit.h"

using std::string;

_START_GOOGLE_NAMESPACE_

static const char* g_program_invocation_short_name = NULL;
static pthread_t g_main_thread_id;

_END_GOOGLE_NAMESPACE_

// The following APIs are all internal.
#ifdef HAVE_STACKTRACE

#include "stacktrace.h"
#include "symbolize.h"
#include "base/commandlineflags.h"

GLOG_DEFINE_bool(symbolize_stacktrace, true,
                 "Symbolize the stack trace in the tombstone");

_START_GOOGLE_NAMESPACE_

typedef void DebugWriter(const char*, void*);

// The %p field width for printf() functions is two characters per byte.
// For some environments, add two extra bytes for the leading "0x".
static const int kPrintfPointerFieldWidth = 2 + 2 * sizeof(void*);

static void DebugWriteToStderr(const char* data, void *) {
  // This one is signal-safe.
  if (write(STDERR_FILENO, data, strlen(data)) < 0) {
    // Ignore errors.
  }
}

void DebugWriteToString(const char* data, void *arg) {
  reinterpret_cast<string*>(arg)->append(data);
}

#ifdef HAVE_SYMBOLIZE
// Print a program counter and its symbol name.
static void DumpPCAndSymbol(DebugWriter *writerfn, void *arg, void *pc,
                            const char * const prefix) {
  char tmp[1024];
  const char *symbol = "(unknown)";
  // Symbolizes the previous address of pc because pc may be in the
  // next function.  The overrun happens when the function ends with
  // a call to a function annotated noreturn (e.g. CHECK).
  if (Symbolize(reinterpret_cast<char *>(pc) - 1, tmp, sizeof(tmp))) {
      symbol = tmp;
  }
  char buf[1024];
  snprintf(buf, sizeof(buf), "%s@ %*p  %s\n",
           prefix, kPrintfPointerFieldWidth, pc, symbol);
  writerfn(buf, arg);
}
#endif

static void DumpPC(DebugWriter *writerfn, void *arg, void *pc,
                   const char * const prefix) {
  char buf[100];
  snprintf(buf, sizeof(buf), "%s@ %*p\n",
           prefix, kPrintfPointerFieldWidth, pc);
  writerfn(buf, arg);
}

// Dump current stack trace as directed by writerfn
static void DumpStackTrace(int skip_count, DebugWriter *writerfn, void *arg) {
  // Print stack trace
  void* stack[32];
  int depth = GetStackTrace(stack, ARRAYSIZE(stack), skip_count+1);
  for (int i = 0; i < depth; i++) {
#if defined(HAVE_SYMBOLIZE)
    if (FLAGS_symbolize_stacktrace) {
      DumpPCAndSymbol(writerfn, arg, stack[i], "    ");
    } else {
      DumpPC(writerfn, arg, stack[i], "    ");
    }
#else
    DumpPC(writerfn, arg, stack[i], "    ");
#endif
  }
}

static void DumpStackTraceAndExit() {
  DumpStackTrace(1, DebugWriteToStderr, NULL);

  // Set the default signal handler for SIGABRT, to avoid invoking our
  // own signal handler installed by InstallFailedSignalHandler().
  struct sigaction sig_action;
  memset(&sig_action, 0, sizeof(sig_action));
  sigemptyset(&sig_action.sa_mask);
  sig_action.sa_handler = SIG_DFL;
  sigaction(SIGABRT, &sig_action, NULL);

  abort();
}

_END_GOOGLE_NAMESPACE_

#endif  // HAVE_STACKTRACE

_START_GOOGLE_NAMESPACE_

namespace glog_internal_namespace_ {

const char* ProgramInvocationShortName() {
  if (g_program_invocation_short_name != NULL) {
    return g_program_invocation_short_name;
  } else {
    // TODO(hamaji): Use /proc/self/cmdline and so?
    return "UNKNOWN";
  }
}

bool IsGoogleLoggingInitialized() {
  return g_program_invocation_short_name != NULL;
}

bool is_default_thread() {
  if (g_program_invocation_short_name == NULL) {
    // InitGoogleLogging() not yet called, so unlikely to be in a different
    // thread
    return true;
  } else {
    return pthread_equal(pthread_self(), g_main_thread_id);
  }
}

#ifdef OS_WINDOWS
struct timeval {
  long tv_sec, tv_usec;
};

// Based on: http://www.google.com/codesearch/p?hl=en#dR3YEbitojA/os_win32.c&q=GetSystemTimeAsFileTime%20license:bsd
// See COPYING for copyright information.
static int gettimeofday(struct timeval *tv, void* tz) {
#define EPOCHFILETIME (116444736000000000ULL)
  FILETIME ft;
  LARGE_INTEGER li;
  uint64 tt;

  GetSystemTimeAsFileTime(&ft);
  li.LowPart = ft.dwLowDateTime;
  li.HighPart = ft.dwHighDateTime;
  tt = (li.QuadPart - EPOCHFILETIME) / 10;
  tv->tv_sec = tt / 1000000;
  tv->tv_usec = tt % 1000000;

  return 0;
}
#endif

int64 CycleClock_Now() {
  // TODO(hamaji): temporary impementation - it might be too slow.
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return static_cast<int64>(tv.tv_sec) * 1000000 + tv.tv_usec;
}

int64 UsecToCycles(int64 usec) {
  return usec;
}

WallTime WallTime_Now() {
  // Now, cycle clock is retuning microseconds since the epoch.
  return CycleClock_Now() * 0.000001;
}

static int32 g_main_thread_pid = getpid();
int32 GetMainThreadPid() {
  return g_main_thread_pid;
}

bool PidHasChanged() {
  int32 pid = getpid();
  if (g_main_thread_pid == pid) {
    return false;
  }
  g_main_thread_pid = pid;
  return true;
}

pid_t GetTID() {
  // On Linux and MacOSX, we try to use gettid().
#if defined OS_LINUX || defined OS_MACOSX
#ifndef __NR_gettid
#ifdef OS_MACOSX
#define __NR_gettid SYS_gettid
#elif ! defined __i386__
#error "Must define __NR_gettid for non-x86 platforms"
#else
#define __NR_gettid 224
#endif
#endif
  static bool lacks_gettid = false;
  if (!lacks_gettid) {
    pid_t tid = syscall(__NR_gettid);
    if (tid != -1) {
      return tid;
    }
    // Technically, this variable has to be volatile, but there is a small
    // performance penalty in accessing volatile variables and there should
    // not be any serious adverse effect if a thread does not immediately see
    // the value change to "true".
    lacks_gettid = true;
  }
#endif  // OS_LINUX || OS_MACOSX

  // If gettid() could not be used, we use one of the following.
#if defined OS_LINUX
  return getpid();  // Linux:  getpid returns thread ID when gettid is absent
#elif defined OS_WINDOWS || defined OS_CYGWIN
  return GetCurrentThreadId();
#else
  // If none of the techniques above worked, we use pthread_self().
  return (pid_t)(uintptr_t)pthread_self();
#endif
}

#if defined OS_WINDOWS

typedef void (WINAPI *PGNSI)(LPSYSTEM_INFO);
typedef BOOL (WINAPI *PGPI)(DWORD, DWORD, DWORD, DWORD, PDWORD);

static std::string g_main_os_version;
const std::string &OSVersion() {
  if (g_main_os_version.length() > 0) {
    return g_main_os_version;
  }

  OSVERSIONINFOEX osvi;
  SYSTEM_INFO si;
  PGNSI pGNSI;
  PGPI pGPI;
  BOOL bOsVersionInfoEx;
  DWORD dwType;

  g_main_os_version = "Microsoft ";
  ZeroMemory(&si, sizeof(SYSTEM_INFO));
  ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));

  osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
  bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO*) &osvi);

  if (bOsVersionInfoEx == NULL ) return g_main_os_version;

  // Call GetNativeSystemInfo if supported or GetSystemInfo otherwise.
  pGNSI = (PGNSI) GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetNativeSystemInfo");
  if(NULL != pGNSI)
      pGNSI(&si);
  else
      GetSystemInfo(&si);

  if (VER_PLATFORM_WIN32_NT != osvi.dwPlatformId || osvi.dwMajorVersion <= 4) {
      return g_main_os_version;
  }

  // Test for the specific product.
  if (osvi.dwMajorVersion == 6) {
    if(osvi.dwMinorVersion == 0) {
      if(osvi.wProductType == VER_NT_WORKSTATION) {
        g_main_os_version += "Windows Vista ";
      } else {
        g_main_os_version += "Windows Server 2008 ";
      }
    } else if (osvi.dwMinorVersion == 1) {
      if (osvi.wProductType == VER_NT_WORKSTATION) {
        g_main_os_version += "Windows 7 ";
      } else {
        g_main_os_version += "Windows Server 2008 R2 ";
      }
    } else if (osvi.dwMinorVersion == 2) {
        if (osvi.wProductType == VER_NT_WORKSTATION) {
            g_main_os_version += "Windows 8 ";
        } else {
            g_main_os_version += "Windows Server 2012 ";
        }
    }
    pGPI = (PGPI) GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "GetProductInfo");
    pGPI(osvi.dwMajorVersion, osvi.dwMinorVersion, 0, 0, &dwType);
    
    switch(dwType) {
    case PRODUCT_ULTIMATE:
      g_main_os_version += "Ultimate Edition";
      break;
    case PRODUCT_PROFESSIONAL:
      g_main_os_version += "Professional";
      break;
    case PRODUCT_HOME_PREMIUM:
      g_main_os_version += "Home Premium Edition";
      break;
    case PRODUCT_HOME_BASIC:
      g_main_os_version += "Home Basic Edition";
      break;
    case PRODUCT_ENTERPRISE:
      g_main_os_version += "Enterprise Edition";
      break;
    case PRODUCT_BUSINESS:
      g_main_os_version += "Business Edition";
      break;
    case PRODUCT_STARTER:
      g_main_os_version += "Starter Edition";
      break;
    case PRODUCT_CLUSTER_SERVER:
      g_main_os_version += "Cluster Server Edition";
      break;
    case PRODUCT_DATACENTER_SERVER:
      g_main_os_version += "Datacenter Edition";
      break;
    case PRODUCT_DATACENTER_SERVER_CORE:
      g_main_os_version += "Datacenter Edition (core installation)";
      break;
    case PRODUCT_ENTERPRISE_SERVER:
      g_main_os_version += "Enterprise Edition";
      break;
    case PRODUCT_ENTERPRISE_SERVER_CORE:
      g_main_os_version += "Enterprise Edition (core installation)";
      break;
    case PRODUCT_ENTERPRISE_SERVER_IA64:
      g_main_os_version += "Enterprise Edition for Itanium-based Systems";
      break;
    case PRODUCT_SMALLBUSINESS_SERVER:
      g_main_os_version += "Small Business Server";
      break;
    case PRODUCT_SMALLBUSINESS_SERVER_PREMIUM:
      g_main_os_version += "Small Business Server Premium Edition";
      break;
    case PRODUCT_STANDARD_SERVER:
      g_main_os_version += "Standard Edition";
      break;
    case PRODUCT_STANDARD_SERVER_CORE:
      g_main_os_version += "Standard Edition (core installation)";
      break;
    case PRODUCT_WEB_SERVER:
      g_main_os_version += "Web Server Edition";
      break;
    }
  } else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2) {
    if(GetSystemMetrics(SM_SERVERR2))
      g_main_os_version += "Windows Server 2003 R2, ";
    else if (osvi.wSuiteMask & VER_SUITE_STORAGE_SERVER)
      g_main_os_version += "Windows Storage Server 2003";
    else if (osvi.wSuiteMask & VER_SUITE_WH_SERVER)
      g_main_os_version += "Windows Home Server";
    else if (osvi.wProductType == VER_NT_WORKSTATION && si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
      g_main_os_version += "Windows XP Professional x64 Edition";
    else
      g_main_os_version += "Windows Server 2003, ";

    // Test for the server type.
    if (osvi.wProductType != VER_NT_WORKSTATION) {
      if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64) {
        if (osvi.wSuiteMask & VER_SUITE_DATACENTER)
          g_main_os_version += "Datacenter Edition for Itanium-based Systems";
        else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
          g_main_os_version += "Enterprise Edition for Itanium-based Systems";
      } else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
        if (osvi.wSuiteMask & VER_SUITE_DATACENTER)
          g_main_os_version += "Datacenter x64 Edition";
        else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE)
          g_main_os_version += "Enterprise x64 Edition";
        else
          g_main_os_version += "Standard x64 Edition";
      } else {
        if (osvi.wSuiteMask & VER_SUITE_COMPUTE_SERVER)
          g_main_os_version += "Compute Cluster Edition";
        else if( osvi.wSuiteMask & VER_SUITE_DATACENTER )
          g_main_os_version += "Datacenter Edition";
        else if( osvi.wSuiteMask & VER_SUITE_ENTERPRISE )
          g_main_os_version += "Enterprise Edition";
        else if ( osvi.wSuiteMask & VER_SUITE_BLADE )
          g_main_os_version += "Web Edition";
        else
          g_main_os_version += "Standard Edition";
      }
    }
  } else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1) {
    g_main_os_version += "Windows XP ";
    if (osvi.wSuiteMask & VER_SUITE_PERSONAL)
      g_main_os_version += "Home Edition";
    else
      g_main_os_version += "Professional";
  } else if (osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0) {
    g_main_os_version += "Windows 2000 ";
    if (osvi.wProductType == VER_NT_WORKSTATION) {
      g_main_os_version += "Professional";
    } else {
      if (osvi.wSuiteMask & VER_SUITE_DATACENTER) {
        g_main_os_version += "Datacenter Server";
      } else if (osvi.wSuiteMask & VER_SUITE_ENTERPRISE) {
        g_main_os_version += "Advanced Server";
      } else {
        g_main_os_version += "Server";
      }
    }
  }

  // Include service pack (if any) and build number.
  if(osvi.szCSDVersion[0] != '\0') {
    g_main_os_version += " ";
#ifdef UNICODE
    std::wstring wstr = osvi.szCSDVersion;
    g_main_os_version.append(wstr.begin(), wstr.end());
#else
    g_main_os_version += osvi.szCSDVersion;
#endif
  }

  char buf[80] = { 0 };
  snprintf(buf, 80, " (build %d)", osvi.dwBuildNumber);
  g_main_os_version += buf;

  if (osvi.dwMajorVersion >= 6) {
    if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
      g_main_os_version += ", 64-bit";
    else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
      g_main_os_version += ", 32-bit";
  }
}
#endif

const char* const_basename(const char* filepath) {
  const char* base = strrchr(filepath, '/');
#ifdef OS_WINDOWS  // Look for either path separator in Windows
  if (!base)
    base = strrchr(filepath, '\\');
#endif
  return base ? (base+1) : filepath;
}

static string g_my_user_name;
const string& MyUserName() {
  return g_my_user_name;
}
static void MyUserNameInitializer() {
  // TODO(hamaji): Probably this is not portable.
#if defined(OS_WINDOWS)
  const char* user = getenv("USERNAME");
#else
  const char* user = getenv("USER");
#endif
  if (user != NULL) {
    g_my_user_name = user;
  } else {
    g_my_user_name = "invalid-user";
  }
}
REGISTER_MODULE_INITIALIZER(utilities, MyUserNameInitializer());

#ifdef HAVE_STACKTRACE
void DumpStackTraceToString(string* stacktrace) {
  DumpStackTrace(1, DebugWriteToString, stacktrace);
}
#endif

// We use an atomic operation to prevent problems with calling CrashReason
// from inside the Mutex implementation (potentially through RAW_CHECK).
static const CrashReason* g_reason = 0;

void SetCrashReason(const CrashReason* r) {
  sync_val_compare_and_swap(&g_reason,
                            reinterpret_cast<const CrashReason*>(0),
                            r);
}

void InitGoogleLoggingUtilities(const char* argv0) {
  CHECK(!IsGoogleLoggingInitialized())
      << "You called InitGoogleLogging() twice!";
  const char* slash = strrchr(argv0, '/');
#ifdef OS_WINDOWS
  if (!slash)  slash = strrchr(argv0, '\\');
#endif
  g_program_invocation_short_name = slash ? slash + 1 : argv0;
  g_main_thread_id = pthread_self();

#ifdef HAVE_STACKTRACE
  InstallFailureFunction(&DumpStackTraceAndExit);
#endif
}

void ShutdownGoogleLoggingUtilities() {
  CHECK(IsGoogleLoggingInitialized())
      << "You called ShutdownGoogleLogging() without calling InitGoogleLogging() first!";
  g_program_invocation_short_name = NULL;
#ifdef HAVE_SYSLOG_H
  closelog();
#endif
}

}  // namespace glog_internal_namespace_

_END_GOOGLE_NAMESPACE_

// Make an implementation of stacktrace compiled.
#ifdef STACKTRACE_H
# include STACKTRACE_H
#endif
