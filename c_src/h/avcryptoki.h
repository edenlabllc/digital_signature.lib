/**
  * AVEST extensions for PKCS#11
  * Дополнения АВЕСТ для PKCS#11 
  * (C) ЗАО АВЕСТ, 2006-2012
  */

#ifndef AVCRYPTOKI_H
#define AVCRYPTOKI_H 1

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SET_LIB_ATTRIBUTES_AVAILABLE
#define SET_LIB_ATTRIBUTES_AVAILABLE	1
/* C_SetLibraryAttributes added by AVEST to set slot attribute. */
CK_PKCS11_FUNCTION_INFO(C_SetLibraryAttributes)
(
  CK_ATTRIBUTE_PTR      pTemplate,         /* attribute template */
  CK_ULONG              ulAttributeCount  /* template length */
);

/* User supplied callback to return external random data. 
   May be used in different token initialization routines like 
   C_InitToken, C_InitPIN, C_SetPIN.
   Usage and possible random data size depends on token functionality.
   Could return CKR_CANCEL to abort function.
   Use C_SetLibraryAttributes to set it. */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_GET_EXTERNAL_RANDOM)(
  CK_BYTE_PTR       ExtRandomData,  /* receives the external random data */
  CK_ULONG          ulRandomLen		/* # of bytes to generate */
);
#endif

/* Значение VENDOR BASE */
#define CAV_DEF_BASE						0x8E000000


/* Object types: */

/* CRL object */
#define CKO_AV_CRL							(CAV_DEF_BASE + 0x00000000)


/* Key types: */

/* GOST 28147.89 */
#define CKK_AV_GOST_28147_89				(CAV_DEF_BASE + 0x00000000)

/* BDS - STB 1176.2-99 */
#define CKK_AV_BDS							(CAV_DEF_BASE + 0x00000001)

/* RDS - GOST R 34.10-2001 */
#define CKK_AV_RDS							(CAV_DEF_BASE + 0x00000002)
	
/* BDH - ПФОК согласно РД РБ ... */
#define CKK_AV_BDH							(CAV_DEF_BASE + 0x00000004)

/* СТБ 1176.2-99 + BDH */
#define CKK_AV_BDS_BDH						(CAV_DEF_BASE + 0x00000006)


/* СТБ 1176.2-99 с предварительным хэшированием */
#define CKK_AV_HASH_BDS						(CAV_DEF_BASE + 0x00000009)

/* СТБ 1176.2-99 с предварительным хэшированием + ПФОК */
#define CKK_AV_HASH_BDS_BDH					(CAV_DEF_BASE + 0x0000000A)

/* Секретный ключ согласно СТБ П 34.101.31.2007 */
#define CKK_AV_BELT							(CAV_DEF_BASE + 0x0000000B)


/*  Attributes: */
// of type CK_AV_DATETIME
#define CKA_AV_KEY_GENERATION_DATE			(CAV_DEF_BASE + 0x00000002)
	
/* Substitution block for GOST 28147.89   */
#define CKA_AV_GOST_SBLOCK					(CAV_DEF_BASE + 0x00000003)


/* BDS - STB 1176.2-99 attributes */
#define CKA_AV_BDS_PRM_L					(CAV_DEF_BASE + 0x00000004)
#define CKA_AV_BDS_PRM_R					(CAV_DEF_BASE + 0x00000005)
#define CKA_AV_BDS_PRM_P					(CAV_DEF_BASE + 0x00000006)
#define CKA_AV_BDS_PRM_Q					(CAV_DEF_BASE + 0x00000007)
#define CKA_AV_BDS_PRM_A					(CAV_DEF_BASE + 0x00000008)
#define CKA_AV_BDS_PRM_Z					(CAV_DEF_BASE + 0x00000009)
#define CKA_AV_BDS_PRM_HASH_H				(CAV_DEF_BASE + 0x0000000A)


/* GOST R 34.10-2001 attributes */
#define CKA_AV_RDS_PRM_P					(CAV_DEF_BASE + 0x0000000B)
#define CKA_AV_RDS_PRM_A					(CAV_DEF_BASE + 0x0000000C)
#define CKA_AV_RDS_PRM_B					(CAV_DEF_BASE + 0x0000000D)
#define CKA_AV_RDS_PRM_Q					(CAV_DEF_BASE + 0x0000000E)
#define CKA_AV_RDS_PRM_X					(CAV_DEF_BASE + 0x0000000F)
#define CKA_AV_RDS_PRM_Y					(CAV_DEF_BASE + 0x00000010)

#define CKA_AV_PRM_OID						(CAV_DEF_BASE + 0x00000011)
#define CKA_AV_PRM_OID_STR					(CAV_DEF_BASE + 0x00000012)

/* Атрибуты ПФОК по РД РБ */
#define CKA_AV_BDH_PRM_L					(CAV_DEF_BASE + 0x00000013)
#define CKA_AV_BDH_PRM_R					(CAV_DEF_BASE + 0x00000014)
#define CKA_AV_BDH_PRM_P					(CAV_DEF_BASE + 0x00000015)
#define CKA_AV_BDH_PRM_G					(CAV_DEF_BASE + 0x00000016)
#define CKA_AV_BDH_PRM_Z					(CAV_DEF_BASE + 0x00000017)

/* BDS+BDH attributes */
#define CKA_AV_BDS_VALUE					(CAV_DEF_BASE + 0x00000018)
#define CKA_AV_BDH_VALUE					(CAV_DEF_BASE + 0x00000019)

/* Значение открытого ключа, передаваемое в формате SubjectPublicKeyInfo */
#define CKA_AV_SPKI_VALUE					(CAV_DEF_BASE + 0x0000001A)

/* Для функции C_SetLibraryAttributes */
/* Устанавливаемый контекст смарткарты */
#ifndef CKA_AV_SLOT_ID
#define CKA_AV_SLOT_ID						(CAV_DEF_BASE + 0x0000001B)
#define CKA_AV_SMART_CONTEXT				(CAV_DEF_BASE + 0x0000001C)
#define CKA_AV_TOKEN_DETACH					(CAV_DEF_BASE + 0x0000001D)
/* Устанавливаемый callback для получения внешней случайности */
#define CKA_AV_EXT_RANDOM_CALLBACK			(CAV_DEF_BASE + 0x0000001E)
#endif

/* Mechanisms */

/* GOST 28147.89 */
#define CKM_AV_GOST_28147_89_KEY_GEN                (CAV_DEF_BASE + 0x00000000)
#define CKM_AV_GOST_28147_89_ECB	                (CAV_DEF_BASE + 0x00000001)
#define CKM_AV_GOST_28147_89_OFB    	            (CAV_DEF_BASE + 0x00000002)
#define CKM_AV_GOST_28147_89_CFB        	        (CAV_DEF_BASE + 0x00000003)
#define CKM_AV_GOST_28147_89_MAC            	    (CAV_DEF_BASE + 0x00000004)
	            
/* Hash for STB 1176.1-99 */				
#define CKM_AV_BHF                           	    (CAV_DEF_BASE + 0x00000005)

/* BDS - STB 1176.2-99 */
#define CKM_AV_BDS_PARAMETER_GEN           			(CAV_DEF_BASE + 0x00000006)
#define CKM_AV_BDS_PARAMETER_CHECK        			(CAV_DEF_BASE + 0x00000007)
#define CKM_AV_BDS_KEY_PAIR_GEN           		    (CAV_DEF_BASE + 0x00000008)
#define CKM_AV_BDS                        			(CAV_DEF_BASE + 0x00000009)


/* Hash for GOST R 34.11-94 */				
#define CKM_AV_GOSTR3411                      	    (CAV_DEF_BASE + 0x0000000A)


/* GOST R 34.10-2001 keypair generation mechanism */
#define CKM_AV_GOSTR3410_2001_KEY_PAIR_GEN          (CAV_DEF_BASE + 0x0000000B)

/* GOST R 34.10-2001 'raw' mechanism */
#define CKM_AV_GOSTR3410_2001                       (CAV_DEF_BASE + 0x0000000C)

/* GOST R 34.11-94 hash with GOST R 34.10-2001 mechanism */
#define CKM_AV_GOSTR3411_94_GOSTR3410_2001         (CAV_DEF_BASE + 0x0000000D)
	
/* BDS - STB 1176.1-99 + STB 1176.2-99 */
#define CKM_AV_BHF_BDS                        		(CAV_DEF_BASE + 0x0000000E)


/* Механизмы ПФОК по РД РБ */
#define CKM_AV_BDH_PARAMETER_GEN                   	(CAV_DEF_BASE + 0x00000012)
#define CKM_AV_BDH_PARAMETER_CHECK              	(CAV_DEF_BASE + 0x00000013)
#define CKM_AV_BDH_KEY_PAIR_GEN                 	(CAV_DEF_BASE + 0x00000014)
#define CKM_AV_BDH_NO_AUTH_DERIVE					(CAV_DEF_BASE + 0x00000015)
#define CKM_AV_BDH_AUTH_DERIVE						(CAV_DEF_BASE + 0x00000016)
#define CKM_AV_BDH_ONEWAY_AUTH_DERIVE				(CAV_DEF_BASE + 0x00000017)


/* BDS with BHF + BDH */
#define CKM_AV_BHF_BDS_BDH                     		(CAV_DEF_BASE + 0x00000018)


/* BDS / BDH */
#define CKM_AV_BDS_BDH                     			(CAV_DEF_BASE + 0x0000001D)
#define CKM_AV_BDS_BDH_KEY_PAIR_GEN				 	(CAV_DEF_BASE + 0x0000001E)
#define CKM_AV_BDS_BDH_NO_AUTH_DERIVE				(CAV_DEF_BASE + 0x0000001F)
#define CKM_AV_BDS_BDH_AUTH_DERIVE					(CAV_DEF_BASE + 0x00000020)
#define CKM_AV_BDS_BDH_ONEWAY_AUTH_DERIVE			(CAV_DEF_BASE + 0x00000021)

/* Хэш-функция согласно СТБ П 34.101.31-2007 */
#define CKM_AV_BELT_HASH                   			(CAV_DEF_BASE + 0x00000022)


/* Электронная цифровая подпись согласно CTБ 1176.2-99 */
/* с использованием хэш-функции согласно СТБ П 34.101.31-2007 */
#define CKM_AV_BELT_HASH_BDS               			(CAV_DEF_BASE + 0x00000025)

/* Электронная цифровая подпись согласно CTБ 1176.2-99 */
/* с использованием хэш-функции согласно СТБ П 34.101.31-2007 */
/* и ПФОК согласно проекта РД РБ «Банковские технологии. Протоколы формирования общего ключа»*/
#define CKM_AV_BELT_HASH_BDS_BDH               			(CAV_DEF_BASE + 0x00000027)


/* Электронная цифровая подпись согласно CTБ 1176.2-99 */
/* с использованием хэш-функции согласно СТБ П 34.101.31-2007 или CTБ 1176.1-99 */
#define CKM_AV_HASH_BDS_PARAMETER_GEN			(CAV_DEF_BASE + 0x00000023)
#define CKM_AV_HASH_BDS_KEY_PAIR_GEN          	(CAV_DEF_BASE + 0x00000024)


/* Электронная цифровая подпись согласно CTБ 1176.2-99 */
/* с использованием хэш-функции согласно СТБ П 34.101.31-2007 или CTБ 1176.1-99 */
/* и ПФОК согласно проекта РД РБ «Банковские технологии. Протоколы формирования общего ключа»*/
#define CKM_AV_HASH_BDS_BDH_KEY_PAIR_GEN        	(CAV_DEF_BASE + 0x00000026)
#define CKM_AV_HASH_BDS_BDH_NO_AUTH_DERIVE      	(CAV_DEF_BASE + 0x00000028)
#define CKM_AV_HASH_BDS_BDH_AUTH_DERIVE         	(CAV_DEF_BASE + 0x00000029)
#define CKM_AV_HASH_BDS_BDH_ONEWAY_AUTH_DERIVE  	(CAV_DEF_BASE + 0x0000002A)


/* Механизм загрузки/выгрузки PKCS#8 формата AVEST */
#define CKM_AV_PKCS8							  	(CAV_DEF_BASE + 0x0000002B)

/*! Механизмы БЕЛТ СТБ П 34.101.31-2007 */
#define CKM_AV_BELT_KEY_GEN						  	(CAV_DEF_BASE + 0x0000002C)
#define CKM_AV_BELT_ECB						  		(CAV_DEF_BASE + 0x0000002D)
#define CKM_AV_BELT_CBC						  		(CAV_DEF_BASE + 0x0000002E)
#define CKM_AV_BELT_CFB						  		(CAV_DEF_BASE + 0x0000002F)
#define CKM_AV_BELT_CTR						  		(CAV_DEF_BASE + 0x00000030)
#define CKM_AV_BELT_MAC						  		(CAV_DEF_BASE + 0x00000031)

// Механизм генерации открытого ключа CTБ 1176.2-99 по личному
#define CKM_AV_BDS_PUBLIC_DERIVE              		(CAV_DEF_BASE + 0x00000032)

// Механизм генерации открытого ключа CTБ 1176.2-99+хэш по личному
#define CKM_AV_HASH_BDS_PUBLIC_DERIVE              	(CAV_DEF_BASE + 0x00000033)

// Механизм генерации открытого ключа по личному 
// по РД РБ «Банковские технологии. Протоколы формирования общего ключа» 
#define CKM_AV_BDH_PUBLIC_DERIVE              		(CAV_DEF_BASE + 0x00000034)

// Механизм генерации композитного открытого ключа CTБ 1176.2-99 и ПФОК по личному
#define CKM_AV_BDS_BDH_PUBLIC_DERIVE              	(CAV_DEF_BASE + 0x00000035)

// Механизм генерации композитного открытого ключа CTБ 1176.2-99+хэш и ПФОК по личному
#define CKM_AV_HASH_BDS_BDH_PUBLIC_DERIVE           (CAV_DEF_BASE + 0x00000036)

// GOST ECB + MAC
#define CKM_AV_GOST_28147_89_ECB_MAC                (CAV_DEF_BASE + 0x00000037)

//////////////////////////////////////////////////////////////////
// Structures for AVEST PKCS#11
/* CK_AV_DATETIME is a structure that defines a date and time */
typedef struct CK_AV_DATETIME{
  CK_CHAR       year[4];     /* the year    ("1900" - "9999") */
  CK_CHAR       month[2];    /* the month   ("01" - "12") */
  CK_CHAR       day[2];      /* the day     ("01" - "31") */
  CK_CHAR       hour[2];     /* the hours   ("00" - "23") */
  CK_CHAR       minute[2];   /* the minutes ("00" - "59") */
  CK_CHAR       second[2];   /* the seconds ("00" - "59") */
} CK_AV_DATETIME;

/* Pointer for CK_AV_DATETIME */
typedef CK_AV_DATETIME CK_PTR CK_AV_DATETIME_PTR;


/* CKM_AV_GOST_28147_89_ECB & CKM_AV_GOST_28147_89_MAC Mechanism parameter structure */
typedef struct CK_AV_GOST_PARAM {
	  CK_BYTE_PTR   pGostOIDDer;        // OID for Gost parameters, DER encoded
	  CK_ULONG      ulGostOIDDerLen;   // Length of OID for Gost parameters
	  CK_BYTE_PTR   pGostOIDAscii;        // OID for Gost parameters, ASCII  
	  CK_ULONG      ulGostOIDAsciiLen;   // Length of OID for Gost parameters
	  CK_BYTE_PTR   pSBox;         // S-Box (128 bytes)
	  CK_ULONG      ulSBoxLen;     // 0 or 128
} CK_AV_GOST_PARAM;

/* CKM_AV_GOST_28147_89_ECB to use with Wrap/Unwrap functions */
/*typedef struct CK_AV_GOST_PARAM_EXT {
	  CK_BYTE_PTR   pGostOIDDer;        // OID for Gost parameters, DER encoded
	  CK_ULONG      ulGostOIDDerLen;   // Length of OID for Gost parameters
	  CK_BYTE_PTR   pGostOIDAscii;        // OID for Gost parameters, ASCII  
	  CK_ULONG      ulGostOIDAsciiLen;   // Length of OID for Gost parameters
	  CK_BYTE_PTR   pSBox;         // S-Box (128 bytes)
	  CK_ULONG      ulSBoxLen;     // 0 or 128
	  CK_BBOOL      bIsWrapWithMAC; // add MAC when doing Wrap/Unwrap
} CK_AV_GOST_PARAM_EXT;*/


/* CKM_AV_GOST_28147_89_OFB & CKM_AV_GOST_28147_89_CFB Mechanism parameter structure */
typedef struct CK_AV_GOST_IV_PARAM {
	  CK_BYTE_PTR   pGostOIDDer;        // OID for Gost parameters, DER encoded
	  CK_ULONG      ulGostOIDDerLen;   // Length of OID for Gost parameters
	  CK_BYTE_PTR   pGostOIDAscii;        // OID for Gost parameters, ASCII  
	  CK_ULONG      ulGostOIDAsciiLen;   // Length of OID for Gost parameters
	  CK_BYTE_PTR   pSBox;         // S-Box (128 bytes)
	  CK_ULONG      ulSBoxLen;     // 0 or 128
	  CK_BYTE       IV[8];         // initializing vector
} CK_AV_GOST_IV_PARAM;

/* Pointer for CK_AV_GOST_PARAM_PTR */
typedef CK_AV_GOST_PARAM CK_PTR CK_AV_GOST_PARAM_PTR;

///* Pointer for CK_AV_GOST_PARAM_EXT_PTR */
//typedef CK_AV_GOST_PARAM_EXT CK_PTR CK_AV_GOST_PARAM_EXT_PTR;

/* Pointer for  CK_AV_GOST_IV_PARAM_PTR */
typedef CK_AV_GOST_IV_PARAM CK_PTR CK_AV_GOST_IV_PARAM_PTR;


/* BHF Mechanism parameter structure */
typedef struct CK_AV_BHF_PARAM {
  CK_BYTE       parameterH[32];
  CK_ULONG      ulParameterL;
} CK_AV_BHF_PARAM;

/* Pointer for  CK_AV_BHF_PARAM */
typedef CK_AV_BHF_PARAM CK_PTR CK_AV_BHF_PARAM_PTR;


/* BDS Mechanism parameter structure */
typedef struct CK_AV_BDS_PARAM {
  CK_BYTE_PTR       pSignature;
  CK_ULONG          ulSignatureLen;
} CK_AV_BDS_PARAM;

/* Pointer for  CK_AV_BDS_PARAM */
typedef CK_AV_BDS_PARAM CK_PTR CK_AV_BDS_PARAM_PTR;

/* BDH Mechanism parameter structure */
typedef struct CK_AV_BDH_PARAM {
  CK_ULONG ulPublicKeyLen;
  CK_BYTE_PTR pPublicKey;
  CK_OBJECT_HANDLE hPrivateKey;
  CK_ULONG ulPublicKey2Len;
  CK_BYTE_PTR pPublicKey2;
} CK_AV_BDH_PARAM;

/* Pointer for  CK_AV_BDH_PARAM */
typedef CK_AV_BDH_PARAM CK_PTR CK_AV_BDH_PARAM_PTR;


/* GOST R 34.11-94   Mechanism parameter structure */
typedef struct CK_AV_RHF_PARAM {
	  CK_BYTE_PTR   pHashOIDDer;        // OID for Hash parameters, DER encoded
	  CK_ULONG      ulHashOIDDerLen;   // Length of OID for Hash parameters
	  CK_BYTE_PTR   pHashOIDAscii;        // OID for Hash parameters, ASCII  
	  CK_ULONG      ulHashOIDAsciiLen;   // Length of OID for Hash parameters
	  CK_BYTE_PTR   pSBox;           // S-Box for digest (128 bytes)
	  CK_ULONG      ulSBoxLen;      // 0 or 128
	  CK_BYTE_PTR   pH0;             // Start digest value (32 bytes)
	  CK_ULONG      ulH0Len;        // 0 or 32
} CK_AV_RHF_PARAM;

/* Pointer for  CK_AV_RHF_PARAM */
typedef CK_AV_RHF_PARAM CK_PTR CK_AV_RHF_PARAM_PTR;

/* Параметр механизмов шифрования БЕЛТ */	
typedef struct CK_AV_BELT_PARAM {
	CK_BYTE   IV[16];         // initializing vector
} CK_AV_BELT_PARAM;

/* Pointer for CK_AV_PKCS8_PARAM */
typedef CK_AV_BELT_PARAM CK_PTR CK_AV_BELT_PARAM_PTR;



/*! Структура загрузки/выгрузки PKCS#8 формата AVEST */
typedef struct CK_AV_PKCS8_PARAM {
  CK_ULONG ulPasswordLen;
  CK_UTF8CHAR_PTR pPassword;
} CK_AV_PKCS8_PARAM;

/* Pointer for CK_AV_PKCS8_PARAM */
typedef CK_AV_PKCS8_PARAM CK_PTR CK_AV_PKCS8_PARAM_PTR;



#ifdef __cplusplus
}
#endif

#endif // AVCRYPTOKI_H

