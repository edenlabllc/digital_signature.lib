#pragma once

#include "UACrypto.h"


/**	\addtogroup basetypes Базовые типы полей */
/** @{ */
typedef CHAR								UAC_DATE_BCD[8+1];									///< символьная дата в формате BCD
/** @} */

#pragma pack (push,1)

/** \addtogroup STRUCT_DG Структуры внешних данных пакета DG
	@{
*/

/// Информация о конверте с регистрационными данными пакета DG
typedef struct _UAC_DG_REGISTRATION_INFO
{
	UAC_SIGNATURE_INFO	signature;						///< информация о подписе и подписчике
	DWORD				textLength;						///< длина текстовой строки
	UAC_DATE_BCD		date;							///< дата изменений. записывается в BCD кодировке
	UAC_TEXT_SIZE256	text;							///< текстовая строка заполненая в формате согласно БЕН, в локальной кодировке
	DWORD				applicationCode;				///< 32/33
} UAC_DG_REGISTRATION_INFO, *PUAC_DG_REGISTRATION_INFO;
/**@}*/

#pragma pack (pop)


#if defined( __cplusplus)
extern "C" {
#endif
/** \addtogroup func Экспортируемые функции
	@{ */
/** \name Функции пакета DG  */

/**
	\brief Загрузка информации о конверте с регистрационными данными пакета DG
	\param[in] pSignedData		конверт с подписанными данными
	\param[out] pData			дополнительный буфер для поля text из конверта или NULL
	\param[out] pInfo			структура для информации о конверте или NULL
	
	\note Хотя бы один из параметров pData или pInfo должен быть ненулевым

	\return код ошибки или ::UAC_SUCCESS
*/
UAC_API(DWORD) UAC_DgRegistrationLoad (
	UAC_IN	PUAC_BLOB pSignedData,
	UAC_OUT PUAC_BLOB pData,
	UAC_OUT PUAC_DG_REGISTRATION_INFO pInfo );

/**
	\brief Проверка подписи данных для конкретного подписчика
	\param[in] pSignedData		конверт с подписанными данными
	\param[in] pSignerCert		сертификат подписчика
*/
UAC_API(DWORD) UAC_DgRegistrationVerify (
	UAC_IN PUAC_BLOB pSignedData,
	UAC_IN PUAC_BLOB pSignerCert);

/**@}*/

#if defined( __cplusplus)
}
#endif

