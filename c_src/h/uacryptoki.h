/** \addtogroup uacryptoki дополнения Украины для PKCS#11
  @{ */

#ifndef UACRYPTOKI_H
#define UACRYPTOKI_H 1

#ifdef __cplusplus
extern "C" {
#endif


/** to prevent russian CKK_GOST28147 to diappear */
#ifdef CKK_GOST28147
#define CKK_GOST28147_RUS				0x00000032
#undef CKK_GOST28147
#undef CKM_GOST28147_ECB
#undef CKM_GOST28147_MAC
#undef CKM_GOST28147_KEY_GEN
#endif

/** Key types: */

/** GOST 28147.89 */
#define CKK_GOST28147					0x80420111

/** DSTU 4145-2002 */
#define CKK_DSTU4145					0x80420131

/** Mechanisms */
#define CKM_INVALID						0xffffffff

/** Mechanisms */
#define CKK_INVALID						0xffffffff

/** GOST 28147.89 ECB */
#define CKM_GOST28147_ECB				0x80420011

/** GOST 28147.89 CNT */
#define CKM_GOST28147_CNT				0x80420012

/** GOST 28147.89 CFB */
#define CKM_GOST28147_CFB				0x80420013

/** GOST 28147.89 MAC */
#define CKM_GOST28147_MAC				0x80420014

/** GOST 28147.89 WRAP */
#define CKM_GOST28147_WRAP				0x80420016

/** GOST R 34.311-95 hash */
#define CKM_GOST34311					0x80420021

/** DSTU 4145-2002 */
#define CKM_DSTU4145					0x80420031

/** DSTU 4145-2002 with GOST R 34.311-95 */
#define CKM_GOST34311_DSTU4145				0x80420032

/** GOST 28147.89 secret key generation */
#define CKM_GOST28147_KEY_GEN			0x80420041

/** DSTU 4145-2002 key pair generation */
#define CKM_DSTU4145_KEY_PAIR_GEN		0x80420042

/** DSTU  Diffie–Hellman derive */
#define CKM_DSTUDH_DERIVE				0x80420043

/** DSTU  Diffie–Hellman cofactor derive */
#define CKM_DSTUDH_COFACTOR_DERIVE		0x80420044

/** GOST 28147 secret key SBOX attribute */
#define CKA_GOST_SBOXES					0x80420311

/** Идентификатор функции формирования ключа
   для механизмов CKM_DSTUDH_DERIVE и CKM_DSTUDH_COFACTOR_DERIVE */
#define CKD_GOST34311_KDF				0x80420211

/** GOST 28147.89 parameter */
typedef struct CK_GOST28147_PARAMS {
	CK_BYTE synchro[8];
} CK_GOST28147_PARAMS;

/** Pointer for CK_GOST28147_PARAMS */
typedef CK_GOST28147_PARAMS* CK_GOST28147_PARAMS_PTR;


#ifdef __cplusplus
}
#endif

#endif // UACRYPTOKI_H

/** @} */
