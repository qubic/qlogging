#pragma once

#include <cstdarg>
#include <cstdio>

static void LOG(const char *fmt, ...)
{
	va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

static void printDebug(const char *fmt, ...)
{
#if DEBUG
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
#endif
}