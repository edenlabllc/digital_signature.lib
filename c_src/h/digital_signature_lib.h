#pragma once

#define LINUX

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

  PUAC_BLOB tsp;
  unsigned int tspLength;
};

struct ValidationResult
{
  bool isValid;
  char *validationErrorMessage;
};

struct ValidationResult Check(UAC_BLOB signedData, UAC_SIGNED_DATA_INFO signedDataInfo, PUAC_SUBJECT_INFO subjectInfo,
                              struct Certs certs);

struct CertificateCheckInfo
{
  char *crlDistributionPoints;
  char *crlDeltaDistributionPoints;
  char *accessOCSP;
  char *data;
  unsigned int dataLen;
};

struct BaseValidationResult
{
  bool isValid;
  char *validationErrorMessage;
  struct CertificateCheckInfo certsCheckInfo[];
};

struct BaseValidationResult BaseCheck(UAC_BLOB signedData, UAC_SIGNED_DATA_INFO signedDataInfo, PUAC_SUBJECT_INFO subjectInfo,
                              struct Certs certs);
