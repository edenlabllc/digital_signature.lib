#pragma once
#ifdef LINUX
#define CALLING_CONVENTION
#else
#define CALLING_CONVENTION __stdcall
#endif

#ifdef __BORLANDC__
#ifdef BUILD_CL
#define UAC_API(type) type __declspec( dllexport ) CALLING_CONVENTION
#else
#define UAC_API(type) type __declspec( dllimport ) CALLING_CONVENTION
#endif
#else
#define UAC_API(type) type CALLING_CONVENTION
#endif


#include "UACBaseDef.h"

#if defined( __cplusplus)
extern "C" {
#endif

UAC_API(DWORD) CipherStandart28147Construct (uacrypto_context * ctx);
UAC_API(DWORD) CipherStandart28147InitMode1 (uacrypto_context ctx, vectDKE * dke, vect32 * key, BOOL encryption);
UAC_API(DWORD) CipherStandart28147InitMode2 (uacrypto_context ctx, vectDKE * dke, vect32 * key, vect8 * iv);
UAC_API(DWORD) CipherStandart28147InitMode3 (uacrypto_context ctx, vectDKE * dke, vect32 * key, vect8 * iv, BOOL encryption);
UAC_API(DWORD) CipherStandart28147InitMode4 (uacrypto_context ctx, vectDKE * dke, vect32 * key);
UAC_API(DWORD) CipherStandart28147Process (uacrypto_context ctx, VOID * buf,  DWORD bufsize);
UAC_API(DWORD) CipherStandart28147Mode4Final (uacrypto_context ctx, vect8 * mac);

UAC_API(DWORD) HashStandart34311Construct (uacrypto_context * ctx);
UAC_API(DWORD) HashStandart34311Init (uacrypto_context ctx, vectDKE * dke, vect32 * init);
UAC_API(DWORD) HashStandart34311Update (uacrypto_context ctx, VOID * buf,  DWORD bufsize);
UAC_API(DWORD) HashStandart34311Final (uacrypto_context ctx,  vect32 * hash);

UAC_API(DWORD) SignStandart4145Construct (uacrypto_context * ctx);
UAC_API(DWORD) SignStandart4145Init1 (uacrypto_context ctx, DWORD m, DWORD A, vect128 * B, vect128 * N);
UAC_API(DWORD) SignStandart4145Init2 (uacrypto_context ctx, DWORD m, DWORD k, DWORD j, DWORD l, DWORD A, vect128 * B, vect128 * N);
UAC_API(DWORD) SignStandart4145Init3 (uacrypto_context ctx, DWORD id);

UAC_API(DWORD) SignStandart4145ResetRNG (uacrypto_context ctx, vect8 * s, vect8 * D, vectDKE * dke, vect32 * k);
UAC_API(DWORD) SignStandart4145GenerateRandom (uacrypto_context ctx, VOID * buf, DWORD bufsize);

UAC_API(DWORD) SignStandart4145SetBasePoint (uacrypto_context ctx, ecpoint * P, BOOL checkP);
UAC_API(DWORD) SignStandart4145GenerateBasePoint (uacrypto_context ctx, ecpoint * P);

UAC_API(DWORD) SignStandart4145GenerateKeyPair (uacrypto_context ctx, gfelement * d, ecpoint * Q);
UAC_API(DWORD) SignStandart4145CalculatePublicKey (uacrypto_context ctx, gfelement * d, ecpoint * Q);
UAC_API(DWORD) SignStandart4145VerifyKeyPair (uacrypto_context ctx, gfelement * d, ecpoint * Q);
UAC_API(DWORD) SignStandart4145SizeOfSignature (uacrypto_context ctx, DWORD * size);
UAC_API(DWORD) SignStandart4145EvalSignature (uacrypto_context ctx, vect32 * hash, gfelement * d, VOID * sign, DWORD * signsize);
UAC_API(DWORD) SignStandart4145VerifySignature (uacrypto_context ctx, vect32 * hash, ecpoint * Q, VOID * sign, DWORD signsize);
UAC_API(DWORD) SignStandart4145CompressPoint (uacrypto_context ctx, ecpoint * P, gfelement * res);
UAC_API(DWORD) SignStandart4145DecompressPoint (uacrypto_context ctx, gfelement * Pc, ecpoint * res);
UAC_API(DWORD) ECKeyTransportProtocolEncryption(uacrypto_context ctx, vect32 * key, ecpoint * Q, VOID * buf, DWORD * bufSize);
UAC_API(DWORD) ECKeyTransportProtocolDecryption(uacrypto_context ctx, gfelement * d, VOID * buf, DWORD bufSize, vect32 *key);
UAC_API(DWORD) ECKeyAgreeProtocolMainProc(uacrypto_context ctx, vectDKE * dke, vect32 * init, gfelement * d, ecpoint * Q, vect8 * ukm, vect32 * key);
UAC_API(DWORD) ECKeyAgreeProtocolEncryption(vect32 * key, vectDKE * dke, vect32 * keyData, vect32 * keyDataEncrypt, vect8 * keyDataMAC);
UAC_API(DWORD) ECKeyAgreeProtocolDecryption(vect32 * key, vectDKE * dke, vect32 * keyDataEncrypt, vect8 * keyDataMAC, vect32 * keyData);

UAC_API(DWORD) ECDHCalculateSharedSecret(uacrypto_context ctx, gfelement * d, ecpoint * Q, vect128 * sharedSecret, int coFactor);
UAC_API(DWORD) ECDHCalculateKEK(uacrypto_context ctx, vectDKE * dke, vect32 * init, gfelement * d, ecpoint * Q, TBLOCK512 * ukm, vect32 * key);
UAC_API(DWORD) Gost28147Wrap(vect32 * key, vectDKE * dke, vect32 * keyData, TWRAPPEDKEY * keyDataEncrypt, vect8 * IV);
UAC_API(DWORD) Gost28147Unwrap(vect32 * key, vectDKE * dke, TWRAPPEDKEY * keyDataEncrypt, vect32 * keyData);
UAC_API(DWORD) Gost28147Wrap2(vect32 * key, vectDKE * dke, const char * keyData, TWRAPPEDKEY * keyDataEncrypt, vect8 * IV, unsigned * pKeyDataLen);
UAC_API(DWORD) Gost28147Unwrap2(vect32 * key, vectDKE * dke, const char * keyDataEncrypt, vect32 * keyData, unsigned * pKeyDataLen);

UAC_API(DWORD) GetDstu4145StdParameters (int n, TSignStandart4145StdParams ** params);

UAC_API(DWORD) HasherAcquireContext (uacrypto_context * ctx, HASHType type);
UAC_API(DWORD) HasherReset (uacrypto_context ctx);
UAC_API(DWORD) HasherProcessBuffer (uacrypto_context ctx, VOID * buf,  DWORD bufsize);
UAC_API(DWORD) HasherGetDigestSize (uacrypto_context ctx, DWORD * size);
UAC_API(DWORD) HasherFinal (uacrypto_context ctx,  VOID * hash);

UAC_API(DWORD) DestroyCryptoContext (uacrypto_context ctx);


#if defined( __cplusplus)
}
#endif



