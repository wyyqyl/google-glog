#ifndef WCHAR_LOGGING_H_
#define WCHAR_LOGGING_H_

#include <wchar.h>

#include <iostream>
#include <string>

inline std::ostream& operator<<(std::ostream& out, const wchar_t* str) {
  size_t len = wcsrtombs(NULL, &str, 0, NULL);
  char* buf = (char*)malloc(len + 1);
  buf[len] = 0;
  wcsrtombs(buf, &str, len, NULL);
  out << buf;
  free(buf);
  return out;
}

inline std::ostream& operator<<(std::ostream& out, const std::wstring& str) {
  return operator<<(out, str.c_str());
}

#endif  // WCHAR_LOGGING_H_
