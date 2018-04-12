#pragma once

#include "CommonTypes.h"

/**	\defgroup basetypes Базовые типы полей */
/** @{ */

#define UAC_IN
#define UAC_OUT
#define UAC_INOUT

#define UAC_MAX_SERIAL_NUMBER_BYTES			32													///< Максимальная длина серийного номера в байтах
typedef QWORD								UAC_TIME;											///< Время
typedef CHAR								UAC_TEXT_SIZE2[2+1];								///< Двухбуквенный код страны
typedef CHAR								CURRENCY_CODE[4+1];									///< Код валюты ("UAH")
typedef CHAR								UAC_TEXT_SIZE64[64+1];								///< С-текст (завершается 0h)
typedef CHAR								UAC_TEXT_SIZE256[256+1];							///< С-текст большой длины (завершается 0h)
typedef CHAR								UAC_SERIAL_NUMBER[UAC_MAX_SERIAL_NUMBER_BYTES*2+1]; ///< серийный номер в 16-ричном виде
typedef UAC_TEXT_SIZE64						UAC_KEY_ID;											///< идентификатор ключа в 16-ричном виде
typedef BYTE								UAC_HASH_BLOCK[32];									///< идентификатор ключа в 16-ричном виде
typedef BYTE								UAC_DKE[64];
typedef const char *						CONST_PCHAR;
typedef CHAR								UAC_TOKEN_SN[16+1];
typedef CHAR								UAC_TEXT_SIZE10[10+1];

/** @} */

/**	\defgroup const Константы */
/** @{ */

/** \defgroup Errors коды ошибок
	@{
*/

/** \name базовые коды ошибок
	@{
*/
/// Без ошибок
#define UAC_SUCCESS							0
/// Общая ошибка
#define UAC_ERROR_GENERAL					100
/** @} */
/** \name ошибки передачи данных
	@{
*/
/// нулевой указатель
#define UAC_ERROR_NULL_PARAM				1
/// пустой параметр \see _UAC_BLOB
#define UAC_ERROR_EMPTY_PARAM				2
/// размер буфера недостаточен для приема данных
#define UAC_ERROR_SMALL_BUFFER				3
/// ошибка распределения памяти буфера \see _UAC_BLOB
#define UAC_ERROR_ALLOCATE					5
/** @} */
/** \name ошибки криптографии нижнего уровня
	@{
*/
/// неверный криптоконтекст
#define UAC_ERROR_CRYPTO_CONTEXT			11
/// неверный открытый ключ
#define UAC_ERROR_CRYPTO_PUBLICKEY			12
/// неверный секретный ключ
#define UAC_ERROR_CRYPTO_PRIVATEKEY			13
/// несоответствие открытого и секретного ключей
#define UAC_ERROR_CRYPTO_KEYPAIR			14
/// неверные параметры базового поля
#define UAC_ERROR_CRYPTO_POLYNOM			15
/// ЭЦП неверна
#define UAC_ERROR_CRYPTO_SIGNATURE			16
/// неверные параметры привели к зацикливанию (не инициализирован генератов ПСП)
#define UAC_ERROR_CRYPTO_DEADLOOP			17
/// при проверке имитовставки обнаружено нарушение целосности данних
#define UAC_ERROR_CRYPTO_MAC				18

/** @} */
/** \name критические ошибки криптографии
	@{
*/
/// Неверный хеш-вектор данных
#define UAC_ERROR_DIGEST     				21
/// несоответствие идентификаторов открытого и секретного ключей
#define UAC_ERROR_KEYPAIR					22
/// неверный пароль контейнера с ключом
#define UAC_ERROR_WRONG_PASSWORD			23
/// неверный тип контейнера для обобщенных функций
#define UAC_ERROR_CONTENT_TYPE				24
/// ссылка на сертификат не содержит данных
#define UAC_ERROR_EMPTY_CERTREF				25
/** @} */
/** \name ошибки форматов
	@{
*/
/// неверный формат входных данных
#define UAC_ERROR_FORMAT					30
/// неверный формат сертификата
#define UAC_ERROR_FORMAT_CERT				31
/// неверный формат запроса на сертификацию
#define UAC_ERROR_FORMAT_CERTREQUEST		32
/// неверный формат OCSP запроса
#define UAC_ERROR_FORMAT_OCSPREQUEST		33
/// неверный формат OCSP ответа
#define UAC_ERROR_FORMAT_OCSPRESPONSE		34
/// неверный формат подписанных данных
#define UAC_ERROR_FORMAT_SIGNEDDATA			35
/// неверный формат запроса метки времени
#define UAC_ERROR_FORMAT_TSREQUEST			36
/// неверный формат ответа метки времени
#define UAC_ERROR_FORMAT_TSRESPONSE			37
/// неверный формат конверта с шифрованными данными
#define UAC_ERROR_FORMAT_ENVELOPE			38
/// неверный формат файлового токена UAC
#define UAC_ERROR_FORMAT_TOKEN				39

/** @} */

/** \name информационные коды
	@{
*/
/// требуемые данные отсутствуют
#define UAC_ERROR_NODATA		     		40
/// попись отсутствует
#define UAC_ERROR_NO_SIGNATURE	     		41
/// соответствующий подписчик не найден
#define UAC_ERROR_NO_SIGNER     			42
/// соответствующий получатель не найден
#define UAC_ERROR_NO_RECIPIENT				43
/// неверный идентификатор или тип токена
#define UAC_ERROR_TOKEN_ID					44
/// не выбран активный ключ
#define UAC_ERROR_NO_KEY					45
/// ошибка чтения/записи UAC_STREAM
#define UAC_ERROR_STREAM					50

/// Минимальный код ошибки внешнего приложения
#define UAC_MAX_ERROR				0x80000000


/** @} */
/** @} */ // Errors

/** \defgroup ContentTypes Типы крипто-контейнеров
	@{
*/
typedef DWORD UAC_CT;

/// не определено
#define UAC_CT_UNDEFINED					0
/** \name форматы данных, поддерживаемых CMS-ContentType: iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) ..
	@{
*/
/// пользовательские данные
#define UAC_CT_DATA							1
/// Подписанные данные
#define UAC_CT_SIGNEDDATA					2
/// Зашифрованные данные
#define UAC_CT_ENVELOPEDDATA				3
/// Информация о метке времени
#define UAC_CT_TSINFO						4
/** @} */

/** \name форматы внешних файлов
	@{
*/
/// сертификат ключа
#define UAC_CT_CERT							101
/// запрос на сертификацию PKCS-10 или подписанный(PKCS-10)
#define UAC_CT_CERTREQUEST					102
/// OCSP запрос (статус сертификата)
#define UAC_CT_OCSPREQUEST					103
/// OCSP ответ (статус сертификата)
#define UAC_CT_OCSPRESPONSE					104
/// запрос метки времени
#define UAC_CT_TSREQUEST					105
/// ответ метки времени / метка времени
#define UAC_CT_TSRESPONSE					106
/// список отозванных сертификатов (CRL)
#define UAC_CT_CRL							107
/// хеш-вектор
#define UAC_CT_HASH							108
/** @} */
/** @} */

/** \defgroup UAC_KU Использование ключа
	@{
*/
/// тип: UAC_KU
typedef DWORD UAC_KU;
/// Основные (KeyUsage) \see UAC_KU_BASIC
#define UAC_KU_BASIC							0x0000FFFF
/// Расширенные (ExtendedKeyUsage) \see UAC_KU_EXTENDED
#define UAC_KU_EXTENDED							0x00FF0000
/// Дополнительные \see UAC_KU_OPTIONS
#define UAC_KU_OPTIONS							0xFF000000
/** \name  Основные
	@{
*/
/// електронний цифровий підпис
#define UAC_KU_DATA_SIGN						0x0080
/// неспростовність
#define UAC_KU_NON_REPUDIATION					0x0040
/// шифрування з метою транспортування ключа
#define UAC_KU_KEY_ENCIPHERMENT					0x0020
/// шифрування даних
#define UAC_KU_DATA_ENCIPHERMENT				0x0010
/// відкритий ключ використовується в протоколах узгодження ключа
#define UAC_KU_KEY_AGREEMENT					0x0008
/// електронний цифровий підпис у сертифікаті
#define UAC_KU_CERT_SIGN						0x0004
/// електронний цифровий підпис у списку відкликаних сертифікатів
#define UAC_KU_CRL_SIGN							0x0002
/// якщо біт “keyAgreement” встановлено, відкритий ключ може використовуватися тільки для шифрування даних
#define UAC_KU_ENCIPHER_ONLY					0x0001
/// якщо біт “keyAgreement” встановлено, відкритий ключ може використовуватися тільки для розшифрування даних
#define UAC_KU_DECIPHER_ONLY					0x8000
/** @} */
/** \name  Расширенные
	@{
*/
/// OCSP сервер
#define UAC_KU_OCSP								0x00010000
/// TSP сервер
#define UAC_KU_TSP								0x00020000
/// Електронна печатка
#define UAC_KU_STAMP							0x00040000
/** @} */
/** \name  Дополнительные
	@{
*/
/// Сертифікат не є посиленним
#define UAC_KU_NOT_QUALIFIED					0x01000000
/// Сертифікат має фінансові обмеження
#define UAC_KU_HAS_LIMIT						0x02000000
/** @} */
/** @} */

#define UAC_KU_CA								UAC_KU_CERT_SIGN

/** \defgroup UAC_CRL_REASON Причина отзыва сертификата
	@{
*/
/// тип: UAC_CRL_REASON
typedef DWORD UAC_CRL_REASON;
/// причина не визначена
#define UAC_CRL_REASON_UNSPECIFIED				0
/// компрометація особистого ключа
#define UAC_CRL_REASON_KEY_COMPROMISE			1
/// компрометація особистого ключа акредитованого центру
#define UAC_CRL_REASON_CA_COMPROMISE			2
/// зміна даних про власника сертифіката
#define UAC_CRL_REASON_AFFILIATION_CHANGED		3
/// сертифікат ключа замінений
#define UAC_CRL_REASON_SUPERSEDED				4
/// припинення операцій
#define UAC_CRL_REASON_CESSATION_OF_OPERATION	5
/// сертифікат ключа блоковано
#define UAC_CRL_REASON_CERTIFICATE_HOLD			6
/// сертифікат ключа поновлено
#define UAC_CRL_REASON_REMOVE_FROM_CRL			8
/// повноваження скасовано
#define UAC_CRL_REASON_PRIVILEGE_WITN_DRAWN		9
/** @} */

/** \defgroup UAC_TS_STATUS Статус ответа сервера метки времени
	@{
*/
/// тип: UAC_TS_STATUS
typedef DWORD UAC_TS_STATUS;

/// Позначку часу сформовано
#define UAC_TS_STATUS_GRANTED					0
/// Позначку часу сформовано з модифікаціями
#define UAC_TS_STATUS_GRANTED_WITH_MODS			1
/// У формуванні позначки часу було відмовлено
#define UAC_TS_STATUS_REJECTION					2
/// Запит неможливо обробити у зв’язку із перенавантаженням
#define UAC_TS_STATUS_WAITING					3
/** @} */

/** \defgroup UAC_TS_FAILURE Причина отказа сервера метки времени
	Причина відмови у позначки часу

	@{
*/
// тип: UAC_TS_FAILURE
typedef DWORD UAC_TS_FAILURE;

/// Невідомий алгоритм гешування або такий, що не підтримується
#define UAC_TS_FAILURE_BAD_ALG					0
/// Запит такий, що не підтримується, або недозволений
#define UAC_TS_FAILURE_BAD_REQUEST				1
/// Запит пошкоджений
#define UAC_TS_FAILURE_BAD_DATA_FORMAT			5
/// Неможливо визначити точний час
#define UAC_TS_FAILURE_TIME_NOY_AVAILABLE		14
/// Політика формування позначок часу така, що не підтримується
#define UAC_TS_FAILURE_UNACCEPTED_POLICY		15
/// Розширення таке, що не підтримується
#define UAC_TS_FAILURE_UNACCEPTED_EXTENTION		16
/// Відсутня необхідна додаткова інформація
#define UAC_TS_FAILURE_ADD_INFO_NOT_AVAILABLE	17
/// Системна помилка
#define UAC_TS_FAILURE_SYSTEM_FAILURE			25
/** @} */

/** \defgroup UAC_CERT_STATUS Статус сертификата
	@{
*/
/// тип: UAC_CERT_STATUS
typedef DWORD UAC_CERT_STATUS;
/// Сертифікат чинний
#define UAC_CERT_STATUS_GOOD					0
/// Сертифікат відкликаний
#define UAC_CERT_STATUS_REVOKED					1
/// Статус сертифікату невідомий
#define UAC_CERT_STATUS_UNKNOWN					2
/** @} */

/** \defgroup UAC_OCSP_STATUS Код ответа о статусе сертификата
	@{
*/
/// тип: UAC_OCSP_STATUS
typedef DWORD UAC_OCSP_STATUS;
/// Операція завершилась успішно
#define UAC_OCSP_STATUS_SUCCESSFUL				0
/// Пошкоджений або недозволений запит
#define UAC_OCSP_STATUS_MAILFORMED_REQUEST		1
/// Внутрішня помилка
#define UAC_OCSP_STATUS_INTERNAL_ERROR			2
/// Запит неможливо обробити у зв’язку із перенавантаженням
#define UAC_OCSP_STATUS_TRY_LATER				3
/// OCSP-cервер обробляє лише підписані запити
#define UAC_OCSP_STATUS_SIG_REQUIRED			5
/// Запит від неавторизованого користувача
#define UAC_OCSP_STATUS_UNAUTHORIZED			6
/** @} */

/** \defgroup UAC_OPTION параметри функций
	@{
*/
/// тип: UAC_OPTION
typedef DWORD UAC_OPTION;

/// идентифицировать подписчика по серийному номеру и общему имени издателя
#define UAC_OPTION_IDENT_BY_SERIAL_NUMBER	0x00000001
/// идентифицировать подписчика по идентификатору ключа
#define UAC_OPTION_IDENT_BY_KEY_ID			0x00000002
/// идентифицировать подписчика по общему имени
/** \note используется только для сертификатов и ответов на OCSP запрос */
#define UAC_OPTION_IDENT_BY_NAME			0x00000200
/// всегда использовать расширенный формат подписанного сообщения
#define UAC_OPTION_FORCE_SIGN_ATTRS			0x00000004
/// положить в конверт сертификат подписчика
#define UAC_OPTION_INCLUDE_CERT				0x00000008
/// положить в конверт сообщение
#define UAC_OPTION_STORE_CONTENT			0x00000010
/// указывать номер версии конверта
#define UAC_OPTION_INCLUDE_VERSION			0x00000020
/// добавлять случайный идентификатор в запрос
#define UAC_OPTION_INCLUDE_NONCE			0x00000040
/// указать время подписи
#define UAC_OPTION_INCLUDE_SIGNED_TIME		0x00000080
/// запросить сертификат в ответе
#define UAC_OPTION_QUERY_CERT				0x00000100
/// создавать/загружать конверт вместе с внешними данными
#define UAC_OPTION_EXTERNAL_ENVELOPE		0x00004000
/// установить тип контента
#define UAC_RESET_CONTENT_TYPE(options, contentType)	(((options)&=0xFFF0FFFF)|=(contentType) << 16)
/// получить установленный тип контента
#define UAC_GET_CONTENT_TYPE(options)		(((options) & 0x000F0000)>>16)
/// параметры по-умолчанию
#define UAC_OPTIONS_DEFAULT (UAC_OPTION_IDENT_BY_SERIAL_NUMBER | UAC_OPTION_FORCE_SIGN_ATTRS | UAC_OPTION_INCLUDE_NONCE | UAC_OPTION_INCLUDE_SIGNED_TIME | UAC_OPTION_INCLUDE_CERT | UAC_OPTION_STORE_CONTENT)

/** \name  Признаки наличия атрибутов
	\see UAC_SIGNATURE_ATTR
	@{
*/
///< задан атрибут	OPERATION_INDEX - индекс операции над документом
#define UAC_OPTION_OPERATION_ATTR			0x00100000
///< задан атрибут	STATUS_INDEX - индекс результата операции над документом.
#define UAC_OPTION_STATUS_ATTR				0x00200000
///< задан атрибут	PREVSIGN_DIGEST - хеш предыдущего подписанного конверта в цепочке
#define UAC_OPTION_PREVSIGN_ATTR			0x00400000
/** @} */

/** @} */

/** @} */ // group const

#pragma pack (push,1)
/** \defgroup STRUCT Структуры внешних данных
	@{
*/

/**
    \brief Поле двоичных данных динамического размера
    \li Все функции, получающие параметр  ::PUAC_BLOB:
    \par
    в случае, если параметр обязательный и ::PUAC_BLOB==NULL, возвращают ошибку ::UAC_ERROR_NULL_PARAM
    \par
    в случае, если параметр необязательный и ::PUAC_BLOB==NULL, считают, что он не указан.

    \li Все функции, читающие данные из UAC_IN ::PUAC_BLOB:
    \par
    в случае UAC_BLOB::data==NULL возвращают ошибку ::UAC_ERROR_NULL_PARAM
    \par
    в случае UAC_BLOB::dataLen==0 возвращают ошибку ::UAC_ERROR_EMPTY_PARAM .

    \li Все функции, возвращающие данные в UAC_OUT ::PUAC_BLOB:
    \par
    в случае, если UAC_BLOB::data==NULL, возвращают ::UAC_SUCCESS
    и записывают размер возвращаемых данных в поле UAC_BLOB::dataLen.
    При этом передачи данных не происходит.
    \par
    в случае, если UAC_BLOB::data!=NULL и размер буфера UAC_BLOB::dataLen недостаточен для сохранения данных,
    возвращают ошибку ::UAC_ERROR_SMALL_BUFFER .
*/
typedef struct _UAC_BLOB
{
	PVOID	data;				///< Указатель на буфер данных
	DWORD	dataLen;			///< Количество байт данных в буфере
} UAC_BLOB, *PUAC_BLOB;

/// Информация о владельце ключа
typedef struct _UAC_SUBJECT_INFO
{
	UAC_TEXT_SIZE64 commonName;						///< Общее имя
	UAC_TEXT_SIZE2	countryName;					///< страна ="UA"
	UAC_TEXT_SIZE64 surname;						///< фамилия
	UAC_TEXT_SIZE64 givenName;						///< Имя
	UAC_TEXT_SIZE64 organizationName;				///< организация
	UAC_TEXT_SIZE64 serialNumber;					///< серийный номер владельца
	UAC_TEXT_SIZE64 stateOrProvinceName;			///< область
	UAC_TEXT_SIZE64 localityName;					///< город
	UAC_TEXT_SIZE64 organizationalUnitName;			///< отдел
	UAC_TEXT_SIZE64 title;							///< название
	UAC_TEXT_SIZE10 edrpou;							///< код ЕДРПОУ
	UAC_TEXT_SIZE10	drfo;							///< код ДРФО или ПИН


} UAC_SUBJECT_INFO, *PUAC_SUBJECT_INFO, UAC_ISSUER_INFO, *PUAC_ISSUER_INFO;

/// Ссылка на сертификат ключа
typedef struct _UAC_CERT_REF
{
	UAC_KEY_ID			subjectKeyIdentifier;		///< идентификатор ключа
	UAC_SERIAL_NUMBER	serialNumber;				///< серийный номер сертификата
	UAC_TEXT_SIZE64		issuerCommonName;			///< общее имя издателя сертификата (вместе с серийным номером сертификата)
	UAC_TEXT_SIZE64		subjectCommonName;			///< общее имя владельца сертификата
	DWORD				options;					///< варианты идентификации = ::UAC_OPTION_IDENT_BY_SERIAL_NUMBER | ::UAC_OPTION_IDENT_BY_KEY_ID | ::UAC_OPTION_IDENT_BY_NAME
	UAC_TEXT_SIZE64		issuerSecondaryName;		///< доп информация - серийный номер издателя (вместе с серийным номером сертификата)
	UAC_TEXT_SIZE64		subjectSecondaryName;		///< доп информация - серийный номер издателя (вместе с общим именем владельца сертификата)

} UAC_CERT_REF, *PUAC_CERT_REF;

/// Информация о цифровой подписи
typedef struct _UAC_SIGNATURE_INFO
{
	UAC_CERT_REF		signerRef;					///< ссылка на сертификат подписчика
	UAC_TIME			signingTime;				///< время подписи или 0
} UAC_SIGNATURE_INFO, *PUAC_SIGNATURE_INFO;

/// информация об атрибутах цифровой подписи
typedef struct _UAC_SIGNATURE_ATTR
{
	DWORD				options;					///< признаки наличия атрибутов (::UAC_OPTION_OPERATION_ATTR, ::UAC_OPTION_STATUS_ATTR,	::UAC_OPTION_PREVSIGN_ATTR)

	DWORD				operationIndex;				///< числовое значение атрибута		OPERATION_INDEX - индекс операции над документом
	UAC_TEXT_SIZE64		operationInfo;				///< текстовое значение атрибута	OPERATION_INDEX - текстовое описание операции над документом
	DWORD				statusIndex;				///< числовое значение атрибута		STATUS_INDEX - индекс результата операции над документом.
	UAC_TEXT_SIZE64		statusInfo;					///< текстовое значение атрибута	STATUS_INFO  - текстовое описание результата операции над документом.
	UAC_HASH_BLOCK		prevSignDigest;				///< значение атрибута				PREVSIGN_DIGEST - хеш предыдущего подписанного конверта в цепочке
} UAC_SIGNATURE_ATTR, *PUAC_SIGNATURE_ATTR;

/// Время действия сертификата
typedef struct _UAC_CERT_VALIDITY
{
	UAC_TIME notBefore;								///< начало действия сертификата
	UAC_TIME notAfter;								///< конец действия сертификата
} UAC_CERT_VALIDITY, *PUAC_CERT_VALIDITY;

/// Информация о сертификате ключа
typedef struct _UAC_CERT_INFO
{
	UAC_SERIAL_NUMBER	serialNumber;				///< серийный номер
	UAC_ISSUER_INFO		issuer;						///< информация об издателе сертификата
	UAC_SUBJECT_INFO	subject;					///< Информация о владельце сертификата
	UAC_CERT_VALIDITY	validity;					///< Время действия сертификата
	UAC_KEY_ID			authorityKeyIdentifier;		///< идентификатор ключа издателя сертификата
	UAC_KEY_ID			subjectKeyIdentifier;		///< идентификатор ключа владельца сертификата
	UAC_KU				keyUsage;					///< режимы использования ключа

	CURRENCY_CODE		currencyCode;				///< "UAH", если есть фин. ограничение
	DWORD				amount;						///< ограничение <= (amount * 10^exponent) currencyCode
	DWORD				exponent;					///< ограничение <= (amount * 10^exponent) currencyCode

	//	для сертификатов ЦСК
	UAC_TEXT_SIZE256	crlDistributionPoints;		///< точки распространиения CRL
	UAC_TEXT_SIZE256	crlDeltaDistributionPoints;	///< точки распространиения частичных CRL
	UAC_TEXT_SIZE256	accessCaRepository;			///< точки доступа к ЦСК
	UAC_TEXT_SIZE256	accessTSP;					///< точки доступа к серверу метки времени
	UAC_TEXT_SIZE256	accessOCSP;					///< точки доступа к серверу OCSP
	UAC_TEXT_SIZE256	accessCaIssuers;

	DWORD				pathLen;
	UAC_TEXT_SIZE64		keyTypeOid;					///< Объектный идентификатор алгоритма ключа
} UAC_CERT_INFO, *PUAC_CERT_INFO;

/// Информация о запросе на сертификацию
typedef struct _UAC_CERT_REQUEST_INFO
{
	UAC_SUBJECT_INFO	subject;					///< желаемые реквизиты пользователя (должны быть пустыми для ЦЗО)
	UAC_KU				keyUsage;					///< режимы использования ключа
	UAC_KEY_ID			subjectKeyIdentifier;		///< идентификатор ключа сертификата

	UAC_SIGNATURE_INFO	signature;					///< подпись
} UAC_CERT_REQUEST_INFO, *PUAC_CERT_REQUEST_INFO;

/// Информация об отозванном сертификате (CRL)
typedef struct _UAC_CRL_ENTRY
{
	UAC_SERIAL_NUMBER	serialNumber;				///< серийный номер сертификата
	UAC_TIME			revocationDate;				///< время отзыва сертификата
	UAC_CRL_REASON		crlReason;					///< причина отзыва
	UAC_TIME			invalidityDate;				///< время, с которого ключ перестал быть актуальным
	UAC_KEY_ID			subjectKeyIdentifier;		///< идентификатор ключа сертификата

} UAC_CRL_ENTRY, *PUAC_CRL_ENTRY;

/// Информация о списке отозванных сертификатов (CRL)
typedef struct _UAC_CRL_INFO
{
	UAC_TIME			thisUpdate;					///< время последнего обновления
	UAC_TIME			nextUpdate;					///< время следующего обновления
	PUAC_CRL_ENTRY		revokedCertificates;		///< массив отозванных сертификатов
	DWORD				dwRevokedCertificatesLength;///< количество отозванных сертификатов
	UAC_SERIAL_NUMBER	serialNumber;				///< серийный номер списка
	UAC_SERIAL_NUMBER	baseSerialNumber;			///< серийный номер базового списка
	UAC_TEXT_SIZE64		crlDistributionPoints;		///< точки распространиения CRL

	UAC_ISSUER_INFO		issuer;						///< информация об издателе CRL
	UAC_KEY_ID			authorityKeyIdentifier;		///< идентификатор ключа издателя CRL
} UAC_CRL_INFO, *PUAC_CRL_INFO;

/// Информация об ответа сервера метки времени
typedef struct _UAC_TIME_STAMP_INFO
{
	UAC_SERIAL_NUMBER	nonce;						///< случайный идентификатор запроса
	UAC_HASH_BLOCK		hash;						///< исходный хеш данных

/// \name поля ответа
	UAC_TS_STATUS		status;						///< статус ответа сервера метки времени
	UAC_TS_FAILURE		failureInfo;				///< причина отказа сервера метки времени
	UAC_TIME			genTime;					///< время создания метки
	UAC_SERIAL_NUMBER	serialNumber;				///< серийный номер метки
	DWORD				dwCertCount;				///< количество сертификатов присоединенных к ответу
	UAC_SIGNATURE_INFO	signature;					///< подпись ответа
} UAC_TIME_STAMP_INFO, *PUAC_TIME_STAMP_INFO;

/// Ссылка на сертификат для получения его статуса
typedef struct _UAC_OCSP_REF_INFO
{
	UAC_SERIAL_NUMBER	certificateSerialNumber;	///< серийный номер сертификата
	UAC_HASH_BLOCK		issuerNameHash;				///< хеш-вектор имени издателя
	UAC_HASH_BLOCK		issuerKeyHash;				///< идентификатор ключа издателя
	UAC_SERIAL_NUMBER	nonce;						///< случайный идентификатор запроса
} UAC_OCSP_REF_INFO;

/// Информация для запроса статуса сертификата
typedef struct _UAC_OCSP_REQUEST_INFO
{
	UAC_OCSP_REF_INFO	ref;						///< ссылка на целевой сертификат
	DWORD				dwCertCount;				///< количество сертификатов присоединенных к ответу
	UAC_SIGNATURE_INFO	signature;					///< подпись
} UAC_OCSP_REQUEST_INFO, *PUAC_OCSP_REQUEST_INFO;

/// ответ о статусе сертификата
typedef struct _UAC_OCSP_RESPONSE_INFO
{
	UAC_OCSP_REF_INFO	ref;						///< ссылка на целевой сертификат
	UAC_OCSP_STATUS		responseStatus;				///< статус ответа сервера OCSP
	UAC_CERT_STATUS		certStatus;					///< статус целевого сертификата
	UAC_TIME			thisUpdate;					///< время последнего обновления информации о статусе
	UAC_TIME			producedAt;					///< время создания ответа
	UAC_TIME			revocationTime;				///< время отзыва сертификата
	UAC_CRL_REASON		revocationReason;			///< причина отзыва сертификата

	DWORD				dwCertCount;				///< количество сертификатов присоединенных к ответу
	UAC_SIGNATURE_INFO	signature;					///< подпись
} UAC_OCSP_RESPONSE_INFO, *PUAC_OCSP_RESPONSE_INFO;

/// Информация для доступа к секретному ключу
typedef struct _UAC_PRIVATE_KEY_DATA
{
	UAC_BLOB			pkcs8Buf;					///< буфер с ключевым контейнером
	PCHAR				password;					///< пароль клиента / пароль первого администратора
	PCHAR				password2;					///< NULL (для контейнера клиента) / пароль второго администратора
	UAC_HASH_BLOCK		adminKey;					///< NULL (для контейнера клиента) / ключ доступа пары администраторов
} UAC_PRIVATE_KEY, *PUAC_PRIVATE_KEY;

/// Пара ключей: Сертификат открытого ключа и секретный ключ пользователя
typedef struct _UAC_KEYPAIR
{
	UAC_BLOB			certData;					///< сертификат
	UAC_PRIVATE_KEY		privateKeyData;				///< информация для доступа к ключу
} UAC_KEYPAIR, *PUAC_KEYPAIR;

/// Информация о конверте с подписанными данными
typedef struct _UAC_SIGNED_DATA_INFO
{
	PUAC_SIGNATURE_INFO pSignatures;				///< массив подписей [dwSignatureCount]
	DWORD				dwSignatureCount;			///< количество подписей
	DWORD				dwContentType;				///< тип подписанных данных (только CMS)
	DWORD				dwDataLength;				///< длина подписанных данных (0, если сообщение не содержится в конверте)
	DWORD				dwCertCount;				///< количество сертификатов добавленных в конверт
	PUAC_SIGNATURE_ATTR pAttributes;				///< массив атрибутов подписей [dwSignatureCount]
	DWORD				dwAttributeCount;			///< количество подписей (для атрибутов)
} UAC_SIGNED_DATA_INFO, *PUAC_SIGNED_DATA_INFO;

/// Информация о передаче ключей между двумя абонентами
typedef struct _UAC_EXCHANGE_INFO
{
	UAC_CERT_REF		originatorRef;				///< ссылка на сертификат отправителя
	UAC_CERT_REF		recipientRef;				///< ссылка на сертификат получателя
} UAC_EXCHANGE_INFO, *PUAC_EXCHANGE_INFO;

/// Информация о конверте зашифрованых данных
typedef struct _UAC_ENVELOPE_INFO
{
	PUAC_EXCHANGE_INFO	pExchanges;					///< массив получателей (с информацией об отправителях)
	DWORD				dwExchangeCount;			///< количество получателей
	DWORD				dwContentType;				///< тип зашифрованных данных (только CMS)
	DWORD				dwDataLength;				///< длина зашифрованных данных (0, если сообщение не содержится в конверте)
	DWORD				dwCertCount;				///< количество сертификатов добавленных в конверт
} UAC_ENVELOPE_INFO, * PUAC_ENVELOPE_INFO;

/// Параметры алгоритмов цифровой подписи ДСТУ4145 и хеширования ГОСТ34311
typedef struct _UAC_DSTU_PARAMS
{
	DWORD				id;							///< идентификатор стандартных параметров ДСТУ4145-2002 в полиномиальном базису
	UAC_DKE				dke;						///< ДКЕ для хеш-функции
} UAC_DSTU_PARAMS, * PUAC_DSTU_PARAMS;

/// Идентификатор слота подключенного файлового токена - для использования в качестве контейнера с ключом
typedef char TokenTypeTag[8];
typedef TokenTypeTag * PUAC_TOKEN_PROVIDER_NAME;

typedef struct _UAC_TOKEN {
	TokenTypeTag	provider_name;						///< условное имя провайдера токена pkcs#11
	QWORD			slotid;								///< идентификатора слота (Pkcs#11)
	QWORD			key_handle;							///< идентификатор выбранного ключа или 0 (Pkcs#11)
} UAC_TOKEN, * PUAC_TOKEN;

typedef enum KeyFormat
{
	kfCntNew = 0,
	kfPk8New = 1,
	kfCntAlways = 2,
	kfPk8Always = 3
} KeyFormat;

typedef enum BagSet {
	bsKeyBag = 1,
	bsShroudedKeyBag = 2,
	bsCertBag = 3,
	bsCrlBag = 4,
	bsSecretBag,
	bsSafeContentsBag
} BagSet;

typedef PVOID (CALLBACK_CONVENTION * PUAC_ALLOCATE_DYNAMIC_BLOB)( PUAC_BLOB pBlob, DWORD bytes );
typedef DWORD (*PUAC_STREAM_READ)( PVOID context, PVOID* pbuf, unsigned* psize );
typedef DWORD (*PUAC_STREAM_WRITE)( PVOID context, PVOID buf, unsigned size );


typedef struct _UAC_STREAM {
	PVOID	context;		///< Указатель - контекст выполнения функций {read, write}
	PUAC_STREAM_READ read;	///< Указатель на функцию чтения данных
	PUAC_STREAM_WRITE write;///< Указатель на функцию записи данных
} UAC_STREAM, *PUAC_STREAM;

#define UAC_PROVIDER "UAC_TOK"
#define EFT_PROVIDER "EFT_TOK"

#define GOST28147_OFB_OID	"1.2.804.2.1.1.1.1.1.1.2"
#define GOST28147_CFB_OID	"1.2.804.2.1.1.1.1.1.1.3"
#define AES_128_CBC_PAD_OID		"2.16.840.1.101.3.4.1.2"
#define AES_192_CBC_PAD_OID		"2.16.840.1.101.3.4.1.22"
#define AES_256_CBC_PAD_OID		"2.16.840.1.101.3.4.1.42"


#define UAC_CURRENT_KEY_INDEX	0xffffffff
#define UAC_MAX_BLOB_SIZE		0xffffff00
#define UAC_DYNAMIC_BLOB_LEN	0xffffffff
/**@}*/

#pragma pack (pop)


