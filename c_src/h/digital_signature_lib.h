#pragma once

#define LINUX

#include <stdbool.h>
#include "UACryptoClient.h"

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
