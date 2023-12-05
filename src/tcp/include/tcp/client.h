#pragma once

#if PLATFORM == 1 // Windows
#include "windows_tcp.h"
#elif PLATFORM == 2 // Linux
#include "tcp/lwip_tcp.h"
#else
#include "tcp/base_client.h"
#endif
