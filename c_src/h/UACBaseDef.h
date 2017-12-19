#pragma once

#include "CommonTypes.h"

typedef void*			uacrypto_context;
typedef unsigned char	vectDKE [128];
typedef unsigned char	vect8 [8];
typedef unsigned char	TBLOCK128 [16];
typedef unsigned char	TBLOCK160 [20];
typedef unsigned char	vect32 [32];
typedef unsigned char	TBLOCK512 [64];
typedef unsigned char	vect128 [128];
typedef unsigned char	TBIGINT [1024];
typedef vect128			gfelement;
typedef struct { gfelement x, y; } ecpoint;
typedef unsigned char	TWRAPPEDKEY [32+12];
struct TSignStandart4145StdParams
{
	int   deg,k1,k2,k3;
	int   A;
	const char *B;
	const char *N;
	const char *X;
	const char *Y;
};
enum HASHType
{
	HASH_SHA		= 1,
	HASH_SHA256		= 2,
	HASH_SHA512		= 3,
	HASH_SHA384		= 4
};

//  RESULT CODES
#define UACL_SUCCESS					0
#define UACL_ERROR_NULL_PARAM			1
#define UACL_ERROR_SMALL_BUFFER			3
#define UACL_ERROR_DSTU_PARAM			10
// ошибки криптографии
#define UACL_ERROR_CONTEXT				11
#define UACL_ERROR_PUBLICKEY			12
#define UACL_ERROR_PRIVATEKEY			13
#define UACL_ERROR_KEYPAIR				14
#define UACL_ERROR_POLYNOM				15
#define UACL_ERROR_SIGNATURE			16
#define UACL_ERROR_DEADLOOP				17
#define UACL_ERROR_MAC					18



