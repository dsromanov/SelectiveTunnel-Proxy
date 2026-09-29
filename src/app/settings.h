#pragma once

#include "core/profile.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
st::Result<st::Profile> ShowProxySettings(HWND parent, const st::Profile* current);
#endif
