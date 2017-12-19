#pragma once

#ifdef LINUX
#include <sys/types.h>
#include <stdint.h>
#include <memory.h>
#include <assert.h>
#include <limits.h>

typedef uint32_t 		DWORD;
typedef uint16_t  		WORD;
typedef unsigned char   	BYTE;
typedef unsigned long long  	QWORD;
#define CALLBACK_CONVENTION 
#define W64LIT(x) 		x##ULL
typedef long long	    	__int64;
typedef unsigned long long  	qword;
typedef unsigned long long  	word64;
typedef uint32_t       		word32;

typedef void			VOID;
typedef bool			BOOL	;
typedef char			CHAR;
typedef BYTE*			PBYTE;
typedef DWORD*			PDWORD;
typedef VOID*			PVOID;
typedef CHAR*			PCHAR;
typedef QWORD*			PQWORD;

typedef void*           LPVOID;
typedef wchar_t*        LPWSTR;

#ifndef TRUE
#define TRUE  true
#endif
#ifndef FALSE
#define FALSE false
#endif

#include  <sys/stat.h>
inline int _mkdir( const char * fname ) { return mkdir( fname, 0777 ); }

#define _countof(x) (sizeof(x)/sizeof(*(x)))
#define MAXINT INT_MAX
typedef void* HMODULE;

#if (!__STDC_WANT_SECURE_LIB__ && !defined(_MEMORY_S_DEFINED))
#define _MEMORY_S_DEFINED
inline void memcpy_s(void *dest, size_t sizeInBytes, const void *src, size_t count)
{
    assert(count <= sizeInBytes);
    memcpy(dest, src, count);
}

inline void memmove_s(void *dest, size_t sizeInBytes, const void *src, size_t count)
{
    assert(count <= sizeInBytes);
    memmove(dest, src, count);
}
#endif


#elif defined(__GNUC__)
#include  <direct.h>
#include <windows.h>
#include <auto_ptr.h>
#include <limits.h>

typedef BYTE*			PBYTE;
typedef DWORD*			PDWORD;
typedef VOID*			PVOID;
typedef unsigned __int64  	QWORD;
typedef QWORD*			PQWORD;

#define CALLBACK_CONVENTION _stdcall
#define W64LIT(x) x
typedef unsigned __int64  	qword;
typedef unsigned __int64  	word64;
typedef unsigned __int32       	word32;
#define MAXINT          INT_MAX


#else
#include  <direct.h>
#include <windows.h>
typedef BYTE*			PBYTE;
typedef DWORD*			PDWORD;
typedef VOID*			PVOID;
typedef unsigned __int64  	QWORD;
typedef QWORD*			PQWORD;

#define CALLBACK_CONVENTION _stdcall
#define W64LIT(x) x##ui64
typedef unsigned __int64  	qword;
typedef unsigned __int64  	word64;
typedef unsigned __int32       	word32;

#endif
#include <sys/types.h>

