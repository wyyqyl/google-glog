#ifndef WCHAR_LOGGING_H_
#define WCHAR_LOGGING_H_

#include <wchar.h>

#include <iostream>
#include <string>

inline std::ostream& operator<<(std::ostream& out, const wchar_t* str) {
  size_t len = 0;
# if defined(_WIN32)
  if (wcsrtombs_s(&len, NULL, 0, &str, 0, NULL)) {
      return out;
  }
# else
  len = wcsrtombs(NULL, &str, 0, NULL) + 1;
# endif
  char* buf = (char*)malloc(len);
  buf[len - 1] = 0;
# if defined(_WIN32)
  if (wcsrtombs_s(&len, buf, len, &str, len, NULL)) {
      return out;
  }
# else
  wcsrtombs(buf, &str, len, NULL);
# endif
  out << buf;
  free(buf);
  return out;
}

inline std::ostream& operator<<(std::ostream& out, const std::wstring& str) {
  return operator<<(out, str.c_str());
}

#endif  // WCHAR_LOGGING_H_
