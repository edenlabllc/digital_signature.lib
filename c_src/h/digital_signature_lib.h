#define LINUX

#ifndef _DIGITAL_SIGANTURE_LIB_H
#define _DIGITAL_SIGANTURE_LIB_H

#include <stdbool.h>
#include "UACrypto.h"

struct GeneralCert
{
  UAC_BLOB root;
  UAC_BLOB ocsp;
};

struct Certs
{
  struct GeneralCert *general;
  unsigned int generalLength;

  UAC_BLOB *tsp;
  unsigned int tspLength;
};

struct ValidationResult
{
  bool isValid;
  char *validationErrorMessage;
};

struct ValidationResult Check(UAC_BLOB signedData, UAC_SIGNED_DATA_INFO signedDataInfo, PUAC_SUBJECT_INFO subjectInfo,
                              struct Certs certs);

#endif /* _DIGITAL_SIGANTURE_LIB_H */
