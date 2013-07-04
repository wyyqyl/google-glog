#ifndef WCHAR_LOGGING_H_
#define WCHAR_LOGGING_H_

#include <wchar.h>

#include <iostream>
#include <string>

__pragma(warning(push))
__pragma(warning(disable:4996))
inline std::ostream& operator<<(std::ostream& out, const wchar_t* str) {
  size_t len = std::wcsrtombs(NULL, &str, 0, NULL);
  char* buf = (char*)malloc(len + 1);
  buf[len] = 0;
  wcsrtombs(buf, &str, len, NULL);
  out << buf;
  free(buf);
  return out;
}
__pragma(warning(pop))

inline std::ostream& operator<<(std::ostream& out, const std::wstring& str) {
  return operator<<(out, str.c_str());
}

#endif  // WCHAR_LOGGING_H_
