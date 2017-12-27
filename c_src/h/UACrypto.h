#pragma once

#ifdef LINUX

#define UAC_API(type) type

#else

#define CALLING_CONVENTION __stdcall

#ifdef __BORLANDC__
#ifdef BUILD_CL
#define UAC_API(type) type __declspec( dllexport ) CALLING_CONVENTION
#else
#define UAC_API(type) type __declspec( dllimport ) CALLING_CONVENTION
#endif
#else
#define UAC_API(type) type CALLING_CONVENTION
#endif

#endif

#include "UACryptoDef.h"
#include "cryptoki.h"
#include "uacryptoki.h"

#if defined( __cplusplus)
extern "C" {
#endif
/** \addtogroup func Экспортируемые функции
	@{ */
/** \name сообщения об ошибках  */
/**
	\brief Получить сообщение о последней ошибке
	\return указатель на строку сообщения
*/
UAC_API(const char*)	GetLastErrorMessage();
/**
	\brief Установить сообщение о последней ошибке
	\param[in] message указатель на строку сообщения (до 1999 символов) или NULL
	\return ::UAC_SUCCESS
*/
UAC_API(DWORD)			SetLastErrorMessage(const char* message);
/**
	\brief Получить символьный эквивалент кода ошибки
	\param[in] code код ошибки
	\return указатель на строку c символьным эквивалентом кода ошибки
*/
UAC_API(const char*)	GetErrorCodeDescription(int code);

/** \name хеш-векторы  */
/**
	\brief Вычисление хеш-вектор от данных
	\param[in] pData данные
	\param[in] pCert сертификат, содержащий параметры хеша, или NULL
	\param[out] pHash буфер для хеша
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_HashCreate(
	UAC_IN PUAC_BLOB		pData,
	UAC_IN PUAC_BLOB		pCert,
	UAC_OUT PUAC_BLOB	 	pHash );

/**
	\brief Проверка хеш-вектора от данных
	\param[in] pData данные
	\param[in] pCert сертификат, содержащий параметры хеша, или NULL
	\param[in] pHash эталонное значение хеша
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_HashVerify(
	UAC_IN PUAC_BLOB		pData,
	UAC_IN PUAC_BLOB		pCert,
	UAC_IN PUAC_BLOB	 	pHash );

/** \name сертификаты  */
/**
	\brief формирования сертификата из заявки
	\param[in] pRequest		заявка на сертификацию PKCS#10 (самоподписаннная) или SignedData(PKCS10) (подписанная администраторм регистрации)
	\param[in] pCertInfo	требуемые параметры владельца сертификата
	\param[in] pIssuerKeys	ключи ЦСК
	\param[out] pCert		буфер для сертификата

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_CertCreate (
	UAC_IN PUAC_BLOB pRequest,
	UAC_IN PUAC_CERT_INFO pCertInfo,
	UAC_IN PUAC_KEYPAIR pIssuerKeys,
	UAC_OUT PUAC_BLOB pCert );
/**
	\brief Загрузка информации о сертификате
	\param[in] pCert		сертификат
	\param[out] pCertInfo	буфер для параметров сертификата
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_CertLoad (
	UAC_IN PUAC_BLOB pCert,
	UAC_OUT PUAC_CERT_INFO pCertInfo );
/**
	\brief Проверка подписи сертификата
	\param[in] pUserCert	проверяемый сертификат
	\param[out] pIssuerCert	сертификата издателя
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_CertVerify (
	UAC_IN PUAC_BLOB pUserCert,
	UAC_IN PUAC_BLOB pIssuerCert );
/**
	\brief Проверка соответствия сертификата и ссылки на сертификат
	в случае несоответствия возвращает ::UAC_ERROR_NO_SIGNER
	\param[in] pCert		сертификат
	\param[in] pCertRef		ссылка на сертификат
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_CertMatch (
	UAC_IN PUAC_CERT_REF	pCertRef,
	UAC_IN PUAC_BLOB		pCert );

/**
	\brief Загрузка ссылки на сертификат
	\param[in] pCert		сертификат
	\param[out] pSubjectRef	структура для ссылки на сертификат
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_CertSubjectRef (
	UAC_IN PUAC_BLOB pCert,
	UAC_OUT PUAC_CERT_REF pSubjectRef );
/**
	\brief Загрузка ссылки на сертификат издателя
	\param[in] pCert		исходный сертификат
	\param[out] pIssuerRef	структура для ссылки на сертификат издателя
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_CertIssuerRef (
	UAC_IN PUAC_BLOB pCert,
	UAC_OUT PUAC_CERT_REF pIssuerRef );

/**
	\brief Проверка соответствия соответствия сертификата и секретного ключа
	в случае несоответствия идентификаторов возвращает ::UAC_ERROR_KEYPAIR
	\param[in] pKeys		пара ключей (сертификат и информация для доступа к секретному ключу)
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_KeyPairVerify (
	UAC_IN PUAC_KEYPAIR pKeys );

/** \name Создание сертификатов  */
/**
	\brief Генерация ключей. Создание ключевого контейнера. Формирование самоподписанной заявки на сертификацию ключей.
	\param[in] pRequestInfo	заявляемые параметры владельца сертификата
	\param[in] pParam		параметры алгоритма ключа
	\param[out] pPrivateKey	буфер для контейнера с секретным ключом
	\param[out] pRequest	буфер для заявки на сертификацию

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_CertRequestCreate (
	UAC_IN PUAC_CERT_REQUEST_INFO	pRequestInfo,
	UAC_IN PUAC_BLOB				pParam,
	UAC_INOUT PUAC_PRIVATE_KEY		pPrivateKey,
	UAC_OUT	PUAC_BLOB				pRequest );
/**
	\brief Загрузка информации о заявке на сертификацию (самоподписанной или подписанной администратором регистрации)
	\param[in] pRequest			заявка на сертификацию
	\param[out] pRequestInfo	структура для параметров заявки
*/

UAC_API(DWORD) UAC_CertRequestLoad (
	UAC_IN	PUAC_BLOB pRequest,
	UAC_OUT PUAC_CERT_REQUEST_INFO pRequestInfo );

/**
	\brief Подписывание самоподписанной заявки на ключе администратора регистрации
	\param[in] pRequest		заявка на сертификацию PKCS#10
	\param[in] pRequestInfo	скорректированные параметры заявки
	\param[in] pKeys		сертификат и ключ администратора регистрации
	\param[out] pRequestSigned	буфер для подписанной заявки на сертификацию
*/
UAC_API(DWORD) UAC_CertRequestSign (
	UAC_IN PUAC_BLOB pRequest,
	UAC_IN PUAC_CERT_REQUEST_INFO pRequestInfo,
	UAC_IN PUAC_KEYPAIR pKeys,
	UAC_OUT PUAC_BLOB pRequestSigned );
/**
	\brief Проверка подписи заявки на сертификацию (самоподписанной или подписанной администратором регистрации)
	\param[in] pRequest		заявка на сертификацию
	\param[in] pSignerCert	сертификат администратора регистрации или NULL (для самоподписанной)
*/

UAC_API(DWORD) UAC_CertRequestVerify (
	UAC_IN PUAC_BLOB pRequest,
	UAC_IN PUAC_BLOB pSignerCert );

/** \name Списки отозванных сертификатов (CRL)  */
/**
	\brief формирования списка отозванных сертификатов (CRL)
	\param[in] pIssuerKeys	сертификат и ключ ЦСК
	\param[in] pCrlInfo		структура CRL
	\param[out] pCrl		буфер для сертификата CRL

	\return код ошибки или ::UAC_SUCCESS

*/
UAC_API(DWORD) UAC_CrlCreate (
	UAC_IN PUAC_KEYPAIR pIssuerKeys,
	UAC_IN PUAC_CRL_INFO pCrlInfo,
	UAC_OUT PUAC_BLOB pCrl );
/**
	\brief Загрузка информации о списке отозванных сертификатов (CRL)
	\param[in] pCrl			CRL
	\param[in] pCrlInfo		структура для информации о CRL

*/
UAC_API(DWORD) UAC_CrlLoad (
	UAC_IN	PUAC_BLOB pCrl,
	UAC_OUT PUAC_CRL_INFO pCrlInfo );
/**
	\brief Проверка подписи списка отозванных сертификатов (CRL)
	\param[in] pCrl			CRL
	\param[in] pIssuerCert	сертификат ЦСК
*/
UAC_API(DWORD) UAC_CrlVerify (
	UAC_IN PUAC_BLOB pCrl,
	UAC_IN PUAC_BLOB pIssuerCert );

/** \name Конверт с подписанными данными (SignedData)  */
/**
	\brief формирования конверта с подписанными данными
	\param[in] pData			блок данных
	\param[in] pSigners			массив с ключами подписчиков
	\param[in] pTimeStamps		массив с метками времени для данных для каждого подписчика или NULL
	\param[in] dwSignersCount	количество подписчиков
	\param[in] dwOptions		параметры/режимы
	\par доступные опции:
		::UAC_OPTION_STORE_CONTENT
		::UAC_OPTION_INCLUDE_CERT
		::UAC_OPTION_IDENT_BY_SERIAL_NUMBER
		::UAC_OPTION_IDENT_BY_KEY_ID
		::UAC_OPTION_INCLUDE_SIGNED_TIME
		::UAC_OPTION_FORCE_SIGN_ATTRS

	\param[out] pSignedData		буфер для подписанных данных

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_SignedDataCreate (
	UAC_IN PUAC_BLOB			pData,
	UAC_IN PUAC_KEYPAIR			pSigners,
	UAC_IN PUAC_BLOB			pTimeStamps,
	UAC_IN DWORD				dwSignersCount,
	UAC_IN DWORD				dwOptions,
	UAC_OUT PUAC_BLOB			pSignedData );

/**
	\brief формирования конверта с подписанными данными + добавление к подписи атрибутов
	\param[in] pData			блок данных
	\param[in] pSigners			массив с ключами подписчиков
	\param[in] pTimeStamps		массив с метками времени для данных для каждого подписчика или NULL
	\param[in] pAttributes		массив с атрибутами, устанавливаемыми подписчиками, или NULL
	\param[in] dwSignersCount	количество подписчиков
	\param[in] dwOptions		параметры/режимы
	\par доступные опции:
		::UAC_OPTION_STORE_CONTENT
		::UAC_OPTION_INCLUDE_CERT
		::UAC_OPTION_IDENT_BY_SERIAL_NUMBER
		::UAC_OPTION_IDENT_BY_KEY_ID
		::UAC_OPTION_INCLUDE_SIGNED_TIME
		::UAC_OPTION_FORCE_SIGN_ATTRS

	\param[out] pSignedData		буфер для подписанных данных

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_SignedDataCreate2 (
	UAC_IN PUAC_BLOB			pData,
	UAC_IN PUAC_KEYPAIR			pSigners,
	UAC_IN PUAC_BLOB			pTimeStamps,
	UAC_IN PUAC_SIGNATURE_ATTR  pAttributes,
	UAC_IN DWORD				dwSignersCount,
	UAC_IN DWORD				dwOptions,
	UAC_OUT PUAC_BLOB			pSignedData );

/**
	\brief формирования подписи данных из потока + добавление к атрибутов
	\param[in] pDataInput		поток подписываемых данных
	\param[in] pSigners			массив с ключами подписчиков
	\param[in] pTimeStamps		массив с метками времени для данных для каждого подписчика или NULL
	\param[in] pAttributes		массив с атрибутами, устанавливаемыми подписчиками, или NULL
	\param[in] dwSignersCount	количество подписчиков
	\param[in] dwOptions		параметры/режимы
	\par доступные опции:
		::UAC_OPTION_INCLUDE_CERT
		::UAC_OPTION_IDENT_BY_SERIAL_NUMBER
		::UAC_OPTION_IDENT_BY_KEY_ID
		::UAC_OPTION_INCLUDE_SIGNED_TIME

	\param[out] pSignedData		буфер для подписи
	формат подписи соответствует формату SignedData без сообщения

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_SignatureCreate ( 
	UAC_IN PUAC_STREAM			pDataInput,
	UAC_IN PUAC_KEYPAIR			pSigners,
	UAC_IN PUAC_BLOB			pTimeStamps,
	UAC_IN PUAC_SIGNATURE_ATTR  pAttributes,
	UAC_IN DWORD				dwSignersCount,
	UAC_IN DWORD				dwOptions,
	UAC_OUT PUAC_BLOB	 		pSignature );

/**
	\brief Добавление новых подписей в конверт с подписанными данными
	\param[in] pSignedData		исходный конверт с подписанными данными
	\param[in] pExternalData	блок внешних данных или NULL, если данные находятся в конверте
	\param[in] pSigners			массив с ключами подписчиков
	\param[in] pTimeStamps		массив с метками времени для данных для каждого подписчика или NULL
	\param[in] dwSignersCount	количество подписчиков
	\param[in] dwOptions		параметры/режимы
	\par доступные опции:
		::UAC_OPTION_INCLUDE_CERT
		::UAC_OPTION_IDENT_BY_SERIAL_NUMBER
		::UAC_OPTION_IDENT_BY_KEY_ID
		::UAC_OPTION_INCLUDE_SIGNED_TIME
		::UAC_OPTION_FORCE_SIGN_ATTRS

	\param[out] pNewSignedData	буфер для нового конверта

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_SignedDataAppend (
	UAC_IN PUAC_BLOB			pSignedData,
	UAC_IN PUAC_BLOB			pExternalData,
	UAC_IN PUAC_KEYPAIR			pSigners,
	UAC_IN PUAC_BLOB			pTimeStamps,
	UAC_IN DWORD				dwSignersCount,
	UAC_IN DWORD				dwOptions,
	UAC_OUT PUAC_BLOB			pNewSignedData );

/**
	\brief Загрузка информации о конверте подписанных данных
	\param[in] pSignedData		конверт с подписанными данными
	\param[out] pData			буфер для данных из конверта или NULL
	\param[out] pInfo			структура для информации о конверте или NULL
	\note Хотя бы один из параметров pData или pInfo должен быть ненулевым

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_SignedDataLoad (
	UAC_IN	PUAC_BLOB pSignedData,
	UAC_OUT PUAC_BLOB pData,
	UAC_OUT PUAC_SIGNED_DATA_INFO pInfo );

/**
	\brief Проверка подписи данных для конкретного подписчика
	\param[in] pSignedData		конверт с подписанными данными
	\param[in] pSignerCert		сертификат подписчика
	\param[in] pExternalData	внешние данные или NULL
*/
UAC_API(DWORD) UAC_SignedDataVerify (
	UAC_IN PUAC_BLOB pSignedData,
	UAC_IN PUAC_BLOB pSignerCert,
	UAC_IN PUAC_BLOB pExternalData);

/**
	\brief Проверка подписи данных из потока для конкретного подписчика
	\param[in] pSignedData		конверт с подписанными данными
	\param[in] pSignerCert		сертификат подписчика
	\param[in] pDataInput		поток подписанных данных
*/
UAC_API(DWORD) UAC_SignatureVerify (
	UAC_IN PUAC_BLOB pSignature,
	UAC_IN PUAC_BLOB pSignerCert,
	UAC_IN PUAC_STREAM pDataInput);

/**
	\brief добавления сертификата в конверт с подписанными данными
	\param[in] pSignedData		конверт с подписанными данными
	\param[in] pCert			добавляемый сертификат
	\param[out] pNewSignedData	буфер для нового конверта
*/

UAC_API(DWORD) UAC_SignedDataAddCert (
	UAC_IN PUAC_BLOB pSignedData,
	UAC_IN PUAC_BLOB pCert,
	UAC_IN PUAC_BLOB pNewSignedData );

/**
	\brief извлечения сертификата по индексу из конверта с подписанными данными
	\param[in] pSignedData		конверт с подписанными данными
	\param[in] dwIndex			индекс сертификата в конверте (с нуля)
	\param[out] pCert			буфер для извлеченного сертификата
*/
UAC_API(DWORD) UAC_SignedDataGetCert (
	UAC_IN PUAC_BLOB		pSignedData,
	UAC_IN DWORD			dwIndex,
	UAC_OUT PUAC_BLOB		pCert );
/**
	\brief извлечение сертификата по ссылочным данным из конверта с подписанными данными
	\param[in] pSignedData		конверт с подписанными данными
	\param[in] pCertRef			ссылки на сертификат
	\param[out] pCert			буфер для извлеченного сертификата
*/

UAC_API(DWORD) UAC_SignedDataFindCert (
	UAC_IN PUAC_BLOB		pSignedData,
	UAC_IN PUAC_CERT_REF	pCertRef,
	UAC_OUT PUAC_BLOB		pCert );
/**
	\brief извлечения метки времени данных из конверта с подписанными данными
	\param[in] pSignedData		конверт с подписанными данными
	\param[in] dwSignerIndex	индекс подписчика в конверте (с нуля)
	\param[out] pTs 			буфер для метки времени
*/

UAC_API(DWORD) UAC_SignedDataGetTs (
	UAC_IN PUAC_BLOB	pSignedData,
	UAC_IN DWORD		dwSignerIndex,
	UAC_OUT PUAC_BLOB	pTs );

/** \name Проверка статуса сертификата (OCSP)  */
/**
	\brief формирования запроса на проверку статуса сертификата
	\param[in] pTargetCert		сертификат, подвергаемый проверке
	\param[in] pSignerKeys		ключи подписчика запроса или NULL, если запрос не подписывать
	\param[in] dwOptions		опции
	\par доступные опции:
		::UAC_OPTION_INCLUDE_VERSION		- указать версию запроса\n
		::UAC_OPTION_INCLUDE_NONCE			- добавить идентификатор запроса

	\param[out] pOcspRequest	буфер для подписанного запроса

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_OcspRequestCreate (
	UAC_IN PUAC_BLOB			pTargetCert,
	UAC_IN PUAC_KEYPAIR			pSignerKeys,
	UAC_IN DWORD				dwOptions,
	UAC_OUT PUAC_BLOB			pOcspRequest );

/**
	\brief формирования запроса на проверку статуса сертификата
	по ссылке на сертификат и сертификату издателя
	\param[in] pTargetCertRef	ссылка на сертификат, подвергаемый проверке
		\note Требуется ссылка с опцией ::UAC_OPTION_IDENT_BY_SERIAL_NUMBER, иначе вернет ошибку ::UAC_ERROR_NODATA
	\param[in] pTargetIssuerCert сертификат издателя проверяемого сертификата
	\param[in] pSignerKeys		ключи подписчика запроса или NULL, если запрос не подписывать
	\param[in] dwOptions		опции
	\par доступные опции:
		::UAC_OPTION_INCLUDE_VERSION		- указать версию запроса\n
		::UAC_OPTION_INCLUDE_NONCE			- добавить идентификатор запроса

	\param[out] pOcspRequest	буфер для подписанного запроса

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_OcspRequestCreateByIssuer (
	UAC_IN PUAC_CERT_REF		pTargetCertRef,
	UAC_IN PUAC_BLOB			pTargetIssuerCert,
	UAC_IN PUAC_KEYPAIR			pSignerKeys,
	UAC_IN DWORD				dwOptions,
	UAC_OUT PUAC_BLOB			pOcspRequest );

/**
	\brief Загрузка информации о запросе на проверку статуса сертификата
	\param[in] pRequest			запрос
	\param[out] pRequestInfo	структура информации о запросе

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_OcspRequestLoad (
	UAC_IN	PUAC_BLOB pRequest,
	UAC_OUT PUAC_OCSP_REQUEST_INFO pRequestInfo );

/**
	\brief Проверка подписи запроса на проверку статуса сертификата
	\param[in] pRequest			запрос
	\param[in] pSignerCert		сертификат подписчика
*/
UAC_API(DWORD) UAC_OcspRequestVerify (
	UAC_IN PUAC_BLOB pRequest,
	UAC_IN PUAC_BLOB pSignerCert );

/**
	\brief извлечения сертификата по индексу из запроса на проверку статуса сертификата
	\param[in] pRequest			запрос на проверку статуса сертификата
	\param[in] dwIndex			индекс сертификата (с нуля)
	\param[out] pCert			буфер для извлеченного сертификата
*/
UAC_API(DWORD) UAC_OcspRequestGetCert (
	UAC_IN PUAC_BLOB		pRequest,
	UAC_IN DWORD			dwIndex,
	UAC_OUT PUAC_BLOB		pCert );

/**
	\brief добавления сертификата в запрос на проверку статуса сертификата
	\param[in] pRequest			запрос на проверку статуса сертификата
	\param[in] pCert			добавляемый сертификат
	\param[out] pNewRequest	    буфер для нового запроса
*/
UAC_API(DWORD) UAC_OcspRequestAddCert (
	UAC_IN PUAC_BLOB		pRequest,
	UAC_IN PUAC_BLOB		pCert,
	UAC_IN PUAC_BLOB		pNewRequest );

/**
	\brief извлечение сертификата по ссылочным данным из запроса на проверку статуса сертификата
	\param[in] pRequest			запрос на проверку статуса сертификата
	\param[in] pCertRef			ссылки на сертификат
	\param[out] pCert			буфер для извлеченного сертификата
*/
UAC_API(DWORD) UAC_OcspRequestFindCert (
	UAC_IN PUAC_BLOB		pRequest,
	UAC_IN PUAC_CERT_REF	pCertRef,
	UAC_OUT PUAC_BLOB		pCert );

/**
	\brief формирования ответа о статусе сертификата
	\param[in] pResponseInfo	информация об ответе
	\param[in] pSignerKeys		ключи подписчика запроса или NULL, если запрос не подписывать
	\param[in] dwOptions		опции
	\par доступные опции:
		::UAC_OPTION_INCLUDE_CERT
		::UAC_OPTION_IDENT_BY_SERIAL_NUMBER
		::UAC_OPTION_IDENT_BY_KEY_ID
		::UAC_OPTION_INCLUDE_VERSION
		::UAC_OPTION_INCLUDE_CERT

	\param[out] pResponse		буфер для ответа

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_OcspResponseCreate (
	UAC_IN PUAC_OCSP_RESPONSE_INFO	pResponseInfo,
	UAC_IN PUAC_KEYPAIR				pSignerKeys,
	UAC_IN DWORD					dwOptions,
	UAC_OUT PUAC_BLOB				pResponse );
/**
	\brief Загрузка информации об ответе на запрос статуса сертификата
	\param[in] pResponse		ответ
	\param[out] pResponseInfo	структура информации об ответе

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_OcspResponseLoad (
	UAC_IN	PUAC_BLOB pResponse,
	UAC_OUT PUAC_OCSP_RESPONSE_INFO pResponseInfo );
/**
	\brief Проверка подписи ответа на запрос статуса сертификата
	\param[in] pResponse		ответ
	\param[in] pSignerCert		сертификат подписчика
*/
UAC_API(DWORD) UAC_OcspResponseVerify (
	UAC_IN PUAC_BLOB pResponse,
	UAC_IN PUAC_BLOB pSignerCert );

/**
	\brief добавления сертификата в ответ на запрос статуса сертификата
	\param[in] pResponse		ответ
	\param[in] pCert			добавляемый сертификат
	\param[out] pNewResponse	буфер для нового ответа
*/
UAC_API(DWORD) UAC_OcspResponseAddCert (
	UAC_IN PUAC_BLOB	pResponse,
	UAC_IN PUAC_BLOB	pCert,
	UAC_IN PUAC_BLOB	pNewResponse );

/**
	\brief извлечения сертификата по индексу из ответа на запрос статуса сертификата
	\param[in] pResponse		ответ
	\param[in] dwIndex			индекс сертификата (с нуля)
	\param[out] pCert			буфер для извлеченного сертификата
*/
UAC_API(DWORD) UAC_OcspResponseGetCert (
	UAC_IN PUAC_BLOB	pResponse,
	UAC_IN DWORD		dwIndex,
	UAC_OUT PUAC_BLOB	pCert );

/**
	\brief извлечение сертификата по ссылочным данным из ответа на запрос статуса сертификата
	\param[in] pResponse		ответ
	\param[in] pCertRef			ссылки на сертификат
	\param[out] pCert			буфер для извлеченного сертификата
*/
UAC_API(DWORD) UAC_OcspResponseFindCert (
	UAC_IN PUAC_BLOB		pResponse,
	UAC_IN PUAC_CERT_REF	pCertRef,
	UAC_OUT PUAC_BLOB		pCert );

/** \name Метка времени (TSP)  */
/**
	\brief формирования запроса на создание метки времени
	\param[in] pHash			исходный хеш-вектор данных
	\param[in] nonce			идентификатор запроса
	\param[in] dwOptions		опции
	доступные опции:
		::UAC_OPTION_QUERY_CERT				запросить сертификат сервера метки времени в ответе
	\param[out] pTsRequest		буфер для запроса

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TsRequestCreate (
	UAC_IN PUAC_BLOB			pHash,
	UAC_IN UAC_SERIAL_NUMBER	nonce,
	UAC_IN DWORD				dwOptions,
	UAC_OUT PUAC_BLOB			pTsRequest );
/**
	\brief Загрузка информации о запросе на создание метки времени
	\param[in] pRequest			запрос
	\param[out] pRequestInfo	структура информации о запросе

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TsRequestLoad (
	UAC_IN	PUAC_BLOB pRequest,
	UAC_OUT PUAC_TIME_STAMP_INFO pRequestInfo );

/**
	\brief формирования ответа c меткой времени
	\param[in] pRequest			исходный запрос
	\param[in] pTsInfo 			параметры ответа
	\param[in] pSignerKeys		ключи подписчика ответа
	\param[out] pTsResponse		буфер для ответа

	\return код ошибки или ::UAC_SUCCESS
*/

UAC_API(DWORD) UAC_TsResponseCreate (
	UAC_IN PUAC_BLOB			pRequest,
	UAC_IN PUAC_TIME_STAMP_INFO pTsInfo,
	UAC_IN PUAC_KEYPAIR			pSignerKeys,
	UAC_OUT PUAC_BLOB			pTsResponse );
/**
	\brief Загрузка информации об ответе c меткой времени
	\param[in] pTsResponse		ответ
	\param[out] pTsInfo	        структура для информации об ответе

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TsResponseLoad (
	UAC_IN	PUAC_BLOB pTsResponse,
	UAC_OUT PUAC_TIME_STAMP_INFO pTsInfo );

/**
	\brief Проверка подписи ответа c меткой времени
	\param[in] pResponse		ответ
	\param[in] pSignerCert		сертификат подписчика
*/

UAC_API(DWORD) UAC_TsResponseVerify (
	UAC_IN PUAC_BLOB pResponse,
	UAC_IN PUAC_BLOB pSignerCert );

/**
	\brief Проверка соответствия хеша сообщения c меткой времени
	\param[in] pHash			исходный хеш-вектор данных
	\param[out] pTsInfo	        информация об ответе
*/

UAC_API(DWORD) UAC_TsVerifyHash (
	UAC_IN PUAC_BLOB pHash,
	UAC_IN PUAC_TIME_STAMP_INFO pTsInfo );

/**
	\brief добавления сертификата в ответ c меткой времени
	\param[in] pResponse		ответ
	\param[in] pCert			добавляемый сертификат
	\param[out] pNewResponse	буфер для нового ответа
*/

UAC_API(DWORD) UAC_TsResponseAddCert (
	UAC_IN PUAC_BLOB pResponse,
	UAC_IN PUAC_BLOB pCert,
	UAC_IN PUAC_BLOB pNewResponse );

/**
	\brief извлечения сертификата по индексу из ответа c меткой времени
	\param[in] pResponse		ответ
	\param[in] dwIndex			индекс сертификата (с нуля)
	\param[out] pCert			буфер для извлеченного сертификата
*/
UAC_API(DWORD) UAC_TsResponseGetCert (
	UAC_IN PUAC_BLOB	pResponse,
	UAC_IN DWORD		dwIndex,
	UAC_OUT PUAC_BLOB	pCert );
/**
	\brief извлечение сертификата по ссылочным данным из ответа c меткой времени
	\param[in] pResponse		ответ
	\param[in] pCertRef			ссылки на сертификат
	\param[out] pCert			буфер для извлеченного сертификата
*/

UAC_API(DWORD) UAC_TsResponseFindCert (
	UAC_IN PUAC_BLOB		pResponse,
	UAC_IN PUAC_CERT_REF	pCertRef,
	UAC_OUT PUAC_BLOB		pCert );

/** \name Конверт с зашифрованными данными (Envelope, EnvelopedData)  */
/**
	\brief формирования конверта с зашифрованными данными
	\param[in] pData			блок данных
	\param[in] pOriginatorKey	ключи отправителя
	\param[in] pRecipientCerts	массив с сертификатами получателей
	\param[in] dwRecipientCount	количество получателей
	\param[in] dwOptions		параметры/режимы
	\par доступные опции:
		::UAC_OPTION_INCLUDE_CERT
		::UAC_OPTION_IDENT_BY_SERIAL_NUMBER
		::UAC_OPTION_IDENT_BY_KEY_ID

	\param[out] pExternalData	буфер для внешнего зашифрованного сообщения или NULL
	\param[out] pEnvelope		буфер для конверта

	\return код ошибки или ::UAC_SUCCESS
*/

UAC_API(DWORD) UAC_EnvelopeCreate (
	UAC_IN PUAC_BLOB			pData,
	UAC_IN PUAC_KEYPAIR			pOriginatorKey,
	UAC_IN PUAC_BLOB			pRecipientCerts,
	UAC_IN DWORD				dwRecipientCount,
	UAC_IN DWORD				dwOptions,
	UAC_IN PUAC_BLOB			pExternalData,
	UAC_OUT PUAC_BLOB			pEnvelope );

/**
	\brief формирования конверта с зашифрованными данными с указанием ДКЕ шифрования
	\param[in] pData			блок данных
	\param[in] pOriginatorKey	ключи отправителя
	\param[in] pRecipientCerts	массив с сертификатами получателей
	\param[in] dwRecipientCount	количество получателей
	\param[in] dwOptions		параметры/режимы
	\par доступные опции:
		::UAC_OPTION_INCLUDE_CERT
		::UAC_OPTION_IDENT_BY_SERIAL_NUMBER
		::UAC_OPTION_IDENT_BY_KEY_ID

	\param[out] pExternalData	буфер для внешнего зашифрованного сообщения или NULL
	\param[in]  pDke			ДКЕ для шифрованния или NULL

	\param[out] pEnvelope		буфер для конверта

	\return код ошибки или ::UAC_SUCCESS
*/

UAC_API(DWORD) UAC_EnvelopeCreateDke (
	UAC_IN PUAC_BLOB			pData,
	UAC_IN PUAC_KEYPAIR			pOriginatorKey,
	UAC_IN PUAC_BLOB			pRecipientCerts,
	UAC_IN DWORD				dwRecipientCount,
	UAC_IN DWORD				dwOptions,
	UAC_IN PUAC_BLOB			pExternalData,
	UAC_IN PUAC_BLOB			pDke,
	UAC_OUT PUAC_BLOB			pEnvelope );

/**
	\brief формирования конверта с зашифрованными данными с указанием алгоритма шифрования
	\param[in] pData			блок данных
	\param[in] pOriginatorKey	ключи отправителя
	\param[in] pRecipientCerts	массив с сертификатами получателей
	\param[in] dwRecipientCount	количество получателей
	\param[in] dwOptions		параметры/режимы
	\par доступные опции:
		::UAC_OPTION_INCLUDE_CERT
		::UAC_OPTION_IDENT_BY_SERIAL_NUMBER
		::UAC_OPTION_IDENT_BY_KEY_ID

	\param[out] pExternalData	буфер для внешнего зашифрованного сообщения или NULL
	\param[in]  cypherOid		объектный идентификатор алгоритма шифрованния (или NULL == Gost28147 Mode2)

	\param[out] pEnvelope		буфер для конверта

	\return код ошибки или ::UAC_SUCCESS
*/

UAC_API(DWORD) UAC_EnvelopeCreateEx (
	UAC_IN PUAC_BLOB			pData,
	UAC_IN PUAC_KEYPAIR			pOriginatorKey,
	UAC_IN PUAC_BLOB			pRecipientCerts,
	UAC_IN DWORD				dwRecipientCount,
	UAC_IN DWORD				dwOptions,
	UAC_IN PUAC_BLOB			pExternalData,
	UAC_IN CONST_PCHAR			cypherOid,
	UAC_OUT PUAC_BLOB			pEnvelope );


/**
	\brief формирования конверта с зашифрованными ключами с указанием алгоритма шифрования
	\param[in] pOriginatorKey	ключи отправителя
	\param[in] pRecipientCerts	массив с сертификатами получателей
	\param[in] dwRecipientCount	количество получателей
	\param[in] dwOptions		параметры/режимы
	\par доступные опции:
		::UAC_OPTION_EXTERNAL_ENVELOPE
		::UAC_OPTION_INCLUDE_CERT
		::UAC_OPTION_IDENT_BY_SERIAL_NUMBER
		::UAC_OPTION_IDENT_BY_KEY_ID
	\param[in] pDataInput		входной поток открытых данных
	\param[in] pDataOutput		выходной поток зашифрованных данных
	\param[in]  cypherOid		объектный идентификатор алгоритма шифрованния (или NULL == Gost28147 Mode2)
	\param[in]  pDke			параметры алгоритма шифрованния или NULL
	\param[out] pEnvelope		буфер для конверта

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_EnvelopeCreateStream (
	UAC_IN PUAC_KEYPAIR			pOriginatorKey,
	UAC_IN PUAC_BLOB			pRecipientCerts,
	UAC_IN DWORD				dwRecipientCount,
	UAC_IN DWORD				dwOptions,
	UAC_IN PUAC_STREAM			pDataInput,
	UAC_IN PUAC_STREAM			pDataOutput,
	UAC_IN CONST_PCHAR			cypherOid,
	UAC_IN PUAC_BLOB			pDke,
	UAC_OUT PUAC_BLOB			pEnvelope );

/**
	\brief Загрузка информации о конверте с зашифрованными данными
	\param[in] pEnvelope		конверт
	\param[out] pInfo	        структура для информации о конверте

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_EnvelopeLoad (
	UAC_IN	PUAC_BLOB pEnvelope,
	UAC_OUT PUAC_ENVELOPE_INFO pInfo );

/**
	\brief Расшифрование данных из конверта
	\param[in] pEnvelope		конверт
	\param[in] pOriginatorCert	сертификат отправителя (или NULL, при динамической схеме)
	\param[in] pRecipientKeys	ключи  получателя
	\param[in] pExternalData    внешнее зашифрованное сообщение или NULL
	\param[out] pPlainData		буфер для расшифрованых данных

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_EnvelopeDecrypt (
	UAC_IN	PUAC_BLOB			pEnvelope,
	UAC_IN	PUAC_BLOB			pOriginatorCert,
	UAC_IN	PUAC_KEYPAIR		pRecipientKeys,
	UAC_IN	PUAC_BLOB			pExternalData,
	UAC_OUT PUAC_BLOB			pPlainData );

/**
	\brief Расшифрование данных из потока на ключе из конверта
	\param[in] pEnvelope		конверт
	\param[in] pOriginatorCert	сертификат отправителя (или NULL, при динамической схеме)
	\param[in] pRecipientKeys	ключи  получателя
	\param[in] dwOptions		параметры/режимы
	\par доступные опции:
		::UAC_OPTION_EXTERNAL_ENVELOPE
	\param[in] pDataInput		входной поток с зашифрованним сообщением
	\param[out] pDataOutput		поток для расшифрованых данных

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_EnvelopeDecryptStream (
	UAC_IN	PUAC_BLOB			pEnvelope,
	UAC_IN	PUAC_BLOB			pOriginatorCert,
	UAC_IN	PUAC_KEYPAIR		pRecipientKeys,
	UAC_IN  DWORD				dwOptions,
	UAC_IN	PUAC_STREAM			pDataInput,
	UAC_OUT PUAC_STREAM			pDataOutput );
/**
	\brief добавления сертификата в конверт с зашифрованными данными
	\param[in] pEnvelope		конверт
	\param[in] pCert			добавляемый сертификат
	\param[out] pNewEnvelope	буфер для нового конверта
*/
UAC_API(DWORD) UAC_EnvelopeAddCert (
	UAC_IN PUAC_BLOB pEnvelope,
	UAC_IN PUAC_BLOB pCert,
	UAC_IN PUAC_BLOB pNewEnvelope );

/**
	\brief извлечения сертификата по индексу из конверта с зашифрованными данными
	\param[in] pEnvelope		конверт
	\param[in] dwIndex			индекс сертификата (с нуля)
	\param[out] pCert			буфер для извлеченного сертификата
*/
UAC_API(DWORD) UAC_EnvelopeGetCert (
	UAC_IN PUAC_BLOB	pEnvelope,
	UAC_IN DWORD		dwIndex,
	UAC_OUT PUAC_BLOB	pCert );

/**
	\brief извлечение сертификата по ссылочным данным из конверта с зашифрованными данными
	\param[in] pEnvelope		конверт
	\param[in] pCertRef			ссылки на сертификат
	\param[out] pCert			буфер для извлеченного сертификата
*/
UAC_API(DWORD) UAC_EnvelopeFindCert (
	UAC_IN PUAC_BLOB		pEnvelope,
	UAC_IN PUAC_CERT_REF	pCertRef,
	UAC_OUT PUAC_BLOB		pCert );

/** \name Управление параметрами  */
/**
	\brief Создание блока параметров ДСТУ4145-2002
	\param[in] pParamInfo		параметры
	\param[out] pParam			буфер для блока параметров
*/

UAC_API(DWORD) UAC_DstuParamCreate(
	UAC_IN	PUAC_DSTU_PARAMS		pParamInfo,
	UAC_OUT	PUAC_BLOB				pParam );

/**
	\brief формирования самоподписанного сертификата
	\param[in] pCertInfo	требуемые параметры владельца сертификата
	\param[in] pParam		параметры алгоритма ключа
	\param[in] pPrivateKey	ключ
	\param[out] pCert		буфер для сертификата

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_RootCertCreate (
	UAC_IN PUAC_CERT_INFO			pCertInfo,
	UAC_IN PUAC_BLOB				pParam,
	UAC_IN PUAC_PRIVATE_KEY			pPrivateKey,
	UAC_OUT PUAC_BLOB				pCert );


/**
	\brief Добавление / извлечение идентификатора в контейнере с ключом
	\param[in] pOldKey	        исходный контейнер с ключом
	\param[in,out] pNewKey		новый контейнер с ключом (возможны новые пароли)
	\param[in] pCert	        сертификат ключа для добавления идентификатора
								или NULL для его извлечения

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_ResetKeyId (
	UAC_IN	PUAC_PRIVATE_KEY	pOldKey,
	UAC_INOUT PUAC_PRIVATE_KEY	pNewKey,
	UAC_IN	PUAC_BLOB			pCert
	);

/**
	\brief Смена пароля (паролей) к ключам
	\param[in] pOldKey	        прежние параметры доступа к ключам
	\param[in,out] pNewKey		новые параметры доступа к ключам

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_PasswordChange (
	UAC_IN		PUAC_PRIVATE_KEY	pOldKey,
	UAC_INOUT	PUAC_PRIVATE_KEY	pNewKey );

/**
	\brief Создание новой пары паролей администраторов к ключу ЦСК
	\param[in] pCaKey	        прежние параметры доступа к ключам
	\param[in,out] pNewPasswords новые параметры доступа к ключам

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_CaPasswordsCreate (
	UAC_IN		PUAC_PRIVATE_KEY	pCaKey,
	UAC_INOUT	PUAC_PRIVATE_KEY	pNewPasswords );
/**
	\brief Заполнение буфера случайными данными
	\param[out] pBuf		буфер для данных

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_Random ( UAC_OUT PUAC_BLOB pBuf );

/**
	\brief Генерация номера в 16-ричном виде
	\param[out] number		поле для номера
	\param[in] bytes	    точность номера в байтах

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_RandomNumber (
	UAC_OUT	UAC_SERIAL_NUMBER	number,
	UAC_IN	DWORD				bytes );

/** \name Обобщенные функции работы с серификатами и цифровой подписью  */
/**
	\brief Проверка подписи крипто-контейнера
	\param[in] contentType	тип контейнера (UAC_CT_*)
	\param[in] pData		проверяемый контейнер
	\param[out] pSignerCert	сертификата подписчика

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_Verify (
	UAC_IN UAC_CT		contentType,
	UAC_IN PUAC_BLOB	pData,
	UAC_IN PUAC_BLOB	pSignerCert );
/**
	\brief извлечения сертификата из контейнера
	\param[in] contentType	тип контейнера (UAC_CT_*)
	\param[in] pContent		исходный контейнер
	\param[in] dwIndex		индекс сертификата (с нуля)
	\param[out] pCert		буфер для извлеченного сертификата
*/
UAC_API(DWORD) UAC_GetCert (
	UAC_IN UAC_CT		contentType,
	UAC_IN PUAC_BLOB	pContent,
	UAC_IN DWORD		dwIndex,
	UAC_OUT PUAC_BLOB	pCert );
/**
	\brief добавления сертификата в контейнер
	\param[in] contentType	тип контейнера (UAC_CT_*)
	\param[in] pContent		исходный контейнер
	\param[in] pCert		добавляемый сертификат
	\param[out] pNewContent	буфер для нового контейнера
*/
UAC_API(DWORD) UAC_AddCert (
	UAC_IN UAC_CT		contentType,
	UAC_IN PUAC_BLOB	pContent,
	UAC_IN PUAC_BLOB	pCert,
	UAC_IN PUAC_BLOB	pNewContent );
/**
	\brief извлечение сертификата по ссылочным данным из контейнера
	\param[in] contentType	тип контейнера (UAC_CT_*)
	\param[in] pContent		исходный контейнер
	\param[in] pCertRef		ссылки на сертификат
	\param[out] pCert		буфер для извлеченного сертификата
*/
UAC_API(DWORD) UAC_FindCert (
	UAC_IN UAC_CT			contentType,
	UAC_IN PUAC_BLOB		pContent,
	UAC_IN PUAC_CERT_REF	pCertRef,
	UAC_OUT PUAC_BLOB		pCert );

/**
	\brief Определить CMS-тип документа (UAC_CT_DATA, UAC_CT_SIGNEDDATA или UAC_CT_ENVELOPEDDATA)
	\param[in] pData		исходный документ
	\param[out] pType		буфер для CMS-типа
*/

UAC_API(DWORD) UAC_GetCmsType (
	UAC_IN PUAC_BLOB			pData,
	UAC_OUT PDWORD				pType	);

/**
	\brief Удалить CMS-тип из документа (UAC_CT_SIGNEDDATA или UAC_CT_ENVELOPEDDATA)
	\param[in,out] pData		документ для изменения
	\param[out] pType		буфер для CMS-типа
*/

UAC_API(DWORD) UAC_RemoveCmsType (
	UAC_IN UAC_OUT PUAC_BLOB	pData,
	UAC_OUT PDWORD				pType	);

/**
	\brief Добавить CMS-тип в документ, если это необходимо (UAC_CT_DATA, UAC_CT_SIGNEDDATA или UAC_CT_ENVELOPEDDATA)
	\param[in] pData	исходный документ
	\param[in] type		CMS-тип
	\param[out] pTypedData	буфер для результата
*/
UAC_API(DWORD) UAC_AddCmsType (
	UAC_IN UAC_OUT PUAC_BLOB	pData,
	UAC_IN DWORD				type,
	UAC_OUT PUAC_BLOB			pTypedData	);

/** \name хеш-векторы  */
/**
	\brief Вычисление хеш-вектор от CMS-данных
	Убирает информацию о CMS-типе перед вычислением
	\param[in] pData данные
	\param[in] pCert сертификат, содержащий параметры хеша, или NULL
	\param[out] pHash буфер для хеша
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_CmsHashCreate (
	UAC_IN PUAC_BLOB		pData,
	UAC_IN PUAC_BLOB		pCert,
	UAC_OUT PUAC_BLOB	 	pHash );

/**
	\brief Проверка хеш-вектора от CMS-данных
	Убирает информацию о CMS-типе перед вычислением
	\param[in] pData данные
	\param[in] pCert сертификат, содержащий параметры хеша, или NULL
	\param[in] pHash эталонное значение хеша
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_CmsHashVerify (
	UAC_IN PUAC_BLOB		pData,
	UAC_IN PUAC_BLOB		pCert,
	UAC_IN PUAC_BLOB	 	pHash );

/**
	\brief Загрузка CMS-конверта из потока
	\param[in] pDataInput входной поток
	\param[out] pCms буфер для данных

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_CmsLoadStream (
	UAC_IN	PUAC_STREAM			pDataInput,
	UAC_OUT	PUAC_BLOB			pCms);

/** \name функции поддержки множества форматов ключевых контейнеров */
/**
	\brief Установка формата новых контейнеров с личным ключом
	\param[in] kf		политика установки формата контейнера с личным ключом

	-	::kfCntNew	- формат загруженных ключей - прежний,
					- формат создаваемых ключей - старый (cnt),
	-	::kfPk8New	- формат загруженных ключей - прежний,
					- формат создаваемых ключей - PKCS#8,
	-	::kfCntAlways - формат всех сохраняемых ключей - старый (cnt),
	-	::kfPk8Always - формат всех сохраняемых ключей - PKCS#8.

	\return ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_SetKeyFormat ( KeyFormat kf ) ;

/** \name функции работы с контейнерами PFX в национальном формате */
/**
	\brief	Содание нового контейнера PFX
			Добавления данных в существующий контейнер PFX
	\param[in] pPfx			существующий контейнер PFX или NULL
	\param[in] password		пароль к контейнеру
	\param[in] fileType		тип добавляемого файла
	\param[in] pFileData	содержимое добавляемого файла
	\param[out] pNewPfx		новый контейнер

	\par Специфичные коды ошибок:
		::UAC_ERROR_CONTENT_TYPE - тип файла не поддерживается
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_PfxAddFile (
	UAC_IN PUAC_BLOB		pPfx,
	UAC_IN CONST_PCHAR		password,
	BagSet					fileType,
	UAC_IN PUAC_BLOB		pFileData,
	UAC_OUT PUAC_BLOB	 	pNewPfx ) ;

/**
	\brief	Загрузка данных из контейнера PFX
	\param[in] pPfx			контейнер PFX
	\param[in] password		пароль к контейнеру
	\param[in] fileType		тип добавляемого файла
	\param[in] fileIndex	индекс (0..) файла данного типа
	\param[in] pFilesCount	указатель на счетчик файлов или NULL
	\param[in] pFileData	буфер для загружаемого файла

	\par Специфичные коды ошибок:
		::UAC_ERROR_CONTENT_TYPE		- тип файла не поддерживается \n
		::UAC_ERROR_NODATA			- если файл типа fileType с индексом fileIndex отсутствует\n
		* в этом случае, в FilesCount записывается количество файлов данного типа

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_PfxGetFile (
	UAC_IN PUAC_BLOB		pPfx,
	UAC_IN CONST_PCHAR		password,
	BagSet					fileType,
	DWORD					fileIndex,
	PDWORD					pFilesCount,
	UAC_OUT PUAC_BLOB		pFileData ) ;

/**
	\brief	Проверка целосности и доступа к контейнеру PFX
	\param[in] pPfx			контейнер PFX
	\param[in] password		пароль к контейнеру

	\par Специфичные коды ошибок:
		::UAC_ERROR_WRONG_PASSWORD

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_PfxVerify (
	UAC_IN PUAC_BLOB		pPfx,
	UAC_IN CONST_PCHAR		password ) ;

/** \name функции работы с виртуальным файловым токеном (*.tok) */

/**
	\brief	Подключение файлового токена к слоту PKCS#11
	и получение его локального идентификатора
	\param[in] pathName		путь к файловому токену
	\param[out] pTokenId	буффер для идентификатора токена

	\return код ошибки или ::UAC_SUCCESS
*/

UAC_API(DWORD) UAC_TokenMount(
	UAC_IN CONST_PCHAR pathName,
	UAC_OUT PUAC_TOKEN pTokenId );
/**
	\brief	Получение идентификатора слота PKCS#11 к которому подлючен файловый токен
	для работы с функциями PKCS#11

	Функция информационная и не использует механизм PKCS#11

	\param[in] pTokenId		идентификатор токена
	\param[out] pSlot		буффер для идентификатора слота

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TokenGetSlot(
	UAC_IN	PUAC_TOKEN	pTokenId,
	UAC_OUT PQWORD		pSlot );
/**
	\brief	Подключение идентификатора токена для слота PKCS#11
	
	Функция информационная и не использует механизм PKCS#11

	\param[in,out] pTokenId	буффер для идентификатора токена. 
							поле provider_name должно содержать условное имя провайдера
	\param[in] slot			идентификатор слота

	\note если pTokenId->provider_name содержит пустую С-строку или нулевые байты, 
	то используется файловый токен UAC (provider_name="UAC_TOK")

	\return код ошибки или ::UAC_SUCCESS
*/

UAC_API(DWORD) UAC_TokenWithSlot(
	UAC_OUT PUAC_TOKEN	pTokenId,
	UAC_IN  QWORD		slot );
/**
	\brief	Отключение всех слотов PKCS#11, связанных с файловым токеном
	\param[in] pathName		путь к файловому токену

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TokenUmountPath(
	UAC_IN CONST_PCHAR		 pathName );
/**
	\brief	Отключение текущего подключения файлового токена
	\param[in] pTokenId		идентификатор токена

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TokenUmount(
	UAC_IN PUAC_TOKEN pTokenId );

/**
	\brief	Создание пустого файлового токена
	\param[in] pathName		путь к новому файловому токену
	\param[in] pwd			пароль админа и пользователя к токену
	\param[in] pwdLen		длина пароля
	\param[in] sn			серийный номер нового токена (или NULL) 

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TokenFormat(
	UAC_IN CONST_PCHAR		pathName,
	UAC_IN CONST_PCHAR		pwd, 
	UAC_IN DWORD			pwdLen,
	UAC_INOUT UAC_TOKEN_SN	sn  );

/**
	\brief	Создание файлового токена и загрузка ключа и сертификата, установка пароля
	\param[in] tokenPathName	путь к новому файловому токену
	\param[in] keys				ключа, сертификат и пароль для нового токена
	\param[in] sn				серийный номер нового токена (или NULL) 

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TokenCreate(
	UAC_IN CONST_PCHAR		tokenPathName,
	UAC_IN PUAC_KEYPAIR		keys,
	UAC_INOUT UAC_TOKEN_SN	sn );
/**
	\brief	Загрузка дополнительного сертификата в файловый токен
	\param[in] pTokenId		идентификатор токена
	\param[in] pwd			пароль доступа к токену
	\param[in] pwdLen		длина пароля доступа к токену
	\param[in] pCert		сертификат

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TokenAddCert (
	UAC_IN PUAC_TOKEN		pTokenId,
	UAC_IN CONST_PCHAR		pwd, 
	UAC_IN DWORD			pwdLen,
	UAC_IN PUAC_BLOB		pCert );

/**
	\brief	Чтение сертификата из файлового токена
	\param[in] pTokenId		идентификатор токена
	\param[in] dwIndex		индекс требуемого сертификата ( 0 - сертификат ключа токена )
	\param[in] pCert		буфер для сертификата

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TokenGetCert (
	UAC_IN	PUAC_TOKEN		pTokenId,
	UAC_IN	DWORD			dwIndex,
	UAC_OUT PUAC_BLOB		pCert );

/**
	\brief	Поиск и чтение сертификата из файлового токена по ссылке на сертификат
	\param[in] pTokenId		идентификатор токена
	\param[in] pCertRef		ссылки на сертификат
	\param[in] pCert		буфер для сертификата

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TokenFindCert (
	UAC_IN	PUAC_TOKEN		pTokenId,
	UAC_IN	PUAC_CERT_REF	pCertRef,
	UAC_OUT PUAC_BLOB		pCert );
/**
	\brief	Заполнение структуры UAC_PRIVATE_KEY идентификатором токена и паролем
	для работы с функциями UAC_* и UAC_Key*. 
	Функция формирует в UAC_PRIVATE_KEY ссылку на виртуальный электронный ключ.
	
	\param[in] pTokenId		идентификатор токена
	\param[in] pwd			пароль к токену
	\param[in] pKey			структура UAC_PRIVATE_KEY для работы с функиями UAC_*

	\note в качестве параметра pKey можно использовать
	адрес поля "privateKeyData" структуры UAC_KEYPAIR.
	В этом случае заполнять поле сертификата "cert" не нужно -
	те функции, которые требуют структуру UAC_KEYPAIR
	будут автоматически загружать сертификат из токена.

	\return код ошибки или ::UAC_SUCCESS
*/

UAC_API(DWORD) UAC_TokenAsKey(
	UAC_IN	PUAC_TOKEN			pTokenId,
	UAC_IN	CONST_PCHAR			pwd,
	UAC_OUT PUAC_PRIVATE_KEY	pKey );

/**
	\brief	Чтение идентификатора токена UAC_TOKEN из структуры UAC_PRIVATE_KEY.
	Идентификатор нужен для работы с функциями UAC_Token*.

	\param[in] pKey			структура UAC_PRIVATE_KEY 
	\param[in] pTokenId		поле для идентификатора токена

	\note Если pTokenId==NULL, то будет производиться проверка pKey на наличие
	идентификатора токена. В этом случае функция возвратит:
	::UAC_ERROR_FORMAT, если pKey НЕ содержит идентификатор токена,
	::UAC_ERROR_NULL_PARAM,   если pKey содержит идентификатор токена.
	
	\note Функция не производит проверку валидности полученного идентификатора токена

	\return 
		::UAC_ERROR_FORMAT - если pKey не содержит идентификатор токена
		код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TokenOfKey(
	UAC_IN  PUAC_PRIVATE_KEY	pKey,
	UAC_OUT	PUAC_TOKEN			pTokenId );


/**
	\brief	Конфигурация автозагрузки библиотеки
	Функция установливает каталог и параметры автозагрузки файловых токенов.

	Функция должна вызываться до вызова других функций UAC_Token* и функций PKCS#11:
	в этом случае, параметры автозагрузки будут применены при первом обращении к указанным функциям.
	в противном случае, если mountOnStartup!=0, то будет произведена повторная загрузка токенов на новых параметрах.


	при первом инициализации библиотеки PKCS#11

	\param[in] tokenDir		путь к каталогу из которого автоматически монтируются токены
							по-умолчанию "."
	\param[in] tokenExt		расширение имени файлового токена для автозагрузки
							по-умолчанию ".tok"
	\param[in] mountOnStartup включение автозагрузки
							0 = не загружать


	\return ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TokenAutoMount(
	UAC_IN	CONST_PCHAR		tokenDir,
	UAC_IN	CONST_PCHAR		tokenExt,
	UAC_IN	DWORD			mountOnStartup );

/**
	\brief	Получение списка подключенных токенов заданного провайдера
	
	идентификатор нужен для работы с функиями UAC_Token*

	\param[out] pTokens		буффер для идентификаторов найденных токенов 
							или NULL - для запроса количества токенов
	\param[in,out] pTokenCount	поле для количества найденных токенов
	\param[in] providerName	имя провайдера Pkcs#11 
	\param[in] onlyWithToken =true, если требуються только слоты с подключенными токенами

	\note В текущей версии доступны 2 провайдера: 
	::UAC_PROVIDER - файловые токены UAC
	::EFT_PROVIDER - ключи Efit
	
	\note Функция не производит проверку валидности полученного идентификатора токена

	\return 
		код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_TokenEnum(
	UAC_OUT	PUAC_TOKEN		pTokens,
	UAC_OUT	PDWORD			pTokenCount,
	UAC_IN	CONST_PCHAR		providerName,
	UAC_IN	bool			onlyWithToken );

/**
	\brief	Поиск токенов заданного провайдера с заданным серийным номером
	\param[out] tokenBuf	поле для идентификатора найденного токена
	\param[in] providerName	имя провайдера Pkcs#11 
	\param[in] sn			серийный номер искомого токена

	\return 
	::UAC_ERROR_NODATA, если токен не найден
	::UAC_SUCCESS, если токен найден 
	или код ошибки
*/
UAC_API(DWORD) UAC_TokenFind(
	UAC_OUT	PUAC_TOKEN		tokenBuf,
	UAC_IN	CONST_PCHAR		providerName,
	UAC_IN  UAC_TOKEN_SN	sn);

/**
	\brief	Чтение информации о слоте и подключенном токене 
	\param[in]	token		идентификатор токена
	\param[out] slotInfo	поле для информации о слоте Pkcs#11 (или NULL)
	\param[out] tokenInfo	поле для информации о токене (или NULL)

	\note Если slotInfo==NULL и tokenInfo==NULL, то функция не производит обращения 
	к токену а лишь проверяет корректность формата идентификатора UAC_TOKEN.

	\return 
	::UAC_SUCCESS или код ошибки
*/
UAC_API(DWORD) UAC_TokenInfo(
	UAC_IN	PUAC_TOKEN			token,
	UAC_OUT CK_SLOT_INFO_PTR	slotInfo,
	UAC_OUT CK_TOKEN_INFO_PTR	tokenInfo );

/** \name функции работы с виртуальным электронным ключем через ссылку из UAC_PRIVATE_KEY  */

/**
	\brief	Выбор активного личного ключа по индексу и/или чтение его сертификата 
	\param[in] pKey			данные личного ключа, ссылающиеся на токен
	\param[in] dwIndex		локальный индекс требуемого ключа 
	(или ::UAC_CURRENT_KEY_INDEX - текущий активный ключ в pKey)
	\param[out] pCert		буфер для сертификата или NULL, если сертификат не нужен 

	\return UAC_ERROR_NO_KEY, если ключ не найден.
	код ошибки или ::UAC_SUCCESS
	pCert - пустой, если сертификат для заданного ключа отсутствует.

*/
UAC_API(DWORD) UAC_KeySelect (
	UAC_INOUT PUAC_PRIVATE_KEY	pKey,
	UAC_IN	DWORD			dwIndex,
	UAC_IN	QWORD			keyType,
	UAC_OUT PUAC_BLOB		pCert );

/**
	\brief	Выбор активного личного ключа по сертификату ключа

	\param[in] pKey			данные личного ключа, ссылающиеся на токен
	\param[in] pCert		сертификат искомого ключа
	
	\note Поиск ключа производится по идентификатору ключа. 

	\note Наличие сертификата в токене не проверяется.

	\return UAC_ERROR_NO_KEY, если ключ не найден.
	код ошибки или ::UAC_SUCCESS

*/
UAC_API(DWORD) UAC_KeySelectByCert (
	UAC_INOUT PUAC_PRIVATE_KEY	pKey,
	UAC_IN  PUAC_BLOB			pCert );

/**
	\brief	Запись сертификата в токен
	\param[in] pKey			данные личного ключа, ссылающиеся на токен
	\param[in] pCert		записываемый сертификат

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_KeyAddCert (
	UAC_IN PUAC_PRIVATE_KEY	pKey,
	UAC_IN PUAC_BLOB		pCert );

/**
	\brief	Чтение сертификата из токена
	\param[in] pKey			данные личного ключа, ссылающиеся на токен
	\param[in] dwIndex		локальный индекс требуемого сертификата или ::UAC_CURRENT_KEY_INDEX
	\param[in] pCert		буфер для сертификата

	если dwIndex == ::UAC_CURRENT_KEY_INDEX,
	то будет прочитан сертификат, соответствующий текущему приватному ключу (выбранному функцией UAC_KeySelect);
	если ключ не выбран, функция вернет ошибку UAC_ERROR_NO_KEY.
	
	Если сертификат не найден, функция вернет ошибку UAC_ERROR_NODATA.

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_KeyGetCert (
	UAC_IN PUAC_PRIVATE_KEY	pKey,
	UAC_IN	DWORD			dwIndex,
	UAC_OUT PUAC_BLOB		pCert );

/**
	\brief	Поиск и чтение сертификата из токена по ссылке на сертификат
	\param[in] pKey			данные личного ключа, ссылающиеся на токен
	\param[in] pCertRef		ссылки на сертификат
	\param[out] pCert		буфер для сертификата

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_KeyFindCert (
	UAC_IN PUAC_PRIVATE_KEY	pKey,
	UAC_IN	PUAC_CERT_REF	pCertRef,
	UAC_OUT PUAC_BLOB		pCert );


/**
	\brief	Удаление сертификата из токена 
	\param[in] pKey			данные личного ключа, ссылающиеся на токен
	\param[in] pCert		сертификат 

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_KeyDelCert (
	UAC_IN PUAC_PRIVATE_KEY	pKey,
	UAC_IN	PUAC_BLOB		pCert );
/**
	\brief	Удаление активного личного ключа и сертификата из токена 
	\param[in] pKey			данные личного ключа, ссылающиеся на токен

	если ключ не выбран, функция вернет ошибку UAC_ERROR_NO_KEY.
	
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_KeyDel (
	UAC_IN PUAC_PRIVATE_KEY	pKey );


/**
	\brief	Экспорт активного личного ключа из токена 
	\param[in] pKey			данные личного ключа, ссылающиеся на токен
	\param[out] pCont		буфер для контейнера с ключом

	если ключ не выбран, функция вернет ошибку UAC_ERROR_NO_KEY.
	если ключ недоступен для чтения, функция вернет ошибку UAC_ERROR_TOKEN_ID.
	
	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_KeyGet (
	UAC_IN PUAC_PRIVATE_KEY	pKey,
	UAC_OUT PUAC_BLOB		pCont
	);

/**
	\brief	Установка callback-функции выделения памяти для динамического UAC_BLOB
	\param[in] pAllocate	callback-функции выделения памяти для динамического UAC_BLOB или NULL

	\return ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_SetBlobAllocator (
	UAC_IN PUAC_ALLOCATE_DYNAMIC_BLOB pAllocate );


UAC_API(DWORD) UAC_Import1 (
	UAC_IN PUAC_BLOB inkey,
    UAC_IN CONST_PCHAR password, 
	UAC_OUT PUAC_BLOB key1,
	UAC_OUT PUAC_BLOB key2
    );

UAC_API(DWORD) UAC_TokenPasswordChange (
	UAC_IN PUAC_TOKEN		pTokenId,
	UAC_IN PUAC_BLOB		oldPwd,
	UAC_IN PUAC_BLOB		newPwd );

/**@}*/

/**@}*/

#if defined( __cplusplus)
}
#endif








