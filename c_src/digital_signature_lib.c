#define LINUX

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "erl_nif.h"

#include "digital_signature_lib.h"

struct GeneralCert FindMatchingRootCertificate(UAC_BLOB cert, struct GeneralCert *generalCerts,
                                               unsigned int generalLength)
{
  struct GeneralCert emptyResult = {};
  UAC_CERT_REF issuerCertRef = {};

  if (UAC_CertIssuerRef(&cert, &issuerCertRef) != UAC_SUCCESS)
  {
    return emptyResult;
  }

  unsigned int i = 0;
  UAC_BLOB rootCert;

  while (i < generalLength)
  {
    rootCert = generalCerts[i].root;

    if (UAC_CertMatch(&issuerCertRef, &rootCert) == UAC_SUCCESS)
    {
      return generalCerts[i];
    }

    i++;
  }

  return emptyResult;
}

UAC_BLOB FindMatchingTspCertificate(UAC_CERT_REF signerRef, UAC_BLOB *tsp, unsigned int tspLength)
{
  UAC_BLOB emptyBlob = {};
  unsigned int i = 0;
  UAC_BLOB tspCert = tsp[i];

  while (i < tspLength)
  {
    DWORD certMatchResult = UAC_CertMatch(&signerRef, &tspCert);
    if (certMatchResult == 0)
    {
      return tsp[i];
    }

    i++;
    tspCert = tsp[i];
  }

  return emptyBlob;
}

bool IsHighestLevel(UAC_CERT_INFO certInfo)
{
  char *subjectKeyIdentifier = certInfo.subjectKeyIdentifier;
  char *authorityKeyIdentifier = certInfo.authorityKeyIdentifier;
  int compareResult = strcmp(subjectKeyIdentifier, authorityKeyIdentifier);
  return compareResult == 0;
}

bool VerifyTimeStampCert(UAC_BLOB timeStamp, UAC_BLOB tspCert)
{
  DWORD tsResponseVerifyResult = UAC_TsResponseVerify(&timeStamp, &tspCert);
  return tsResponseVerifyResult == 0;
}

bool CheckTimeStamp(UAC_CERT_INFO certInfo, UAC_TIME signatureDate)
{
  UAC_TIME notAfter = certInfo.validity.notAfter;
  UAC_TIME notBefore = certInfo.validity.notBefore;
  return signatureDate <= notAfter && signatureDate >= notBefore;
}

UAC_BLOB SendOCSPRequest(char *url, UAC_BLOB requestData)
{
  UAC_BLOB emptyResult = {NULL, 0};

  // ---- Parse URL ----
  char url_copy[strlen(url)];
  memcpy(url_copy, url, strlen(url));

  const char *schemaDelim = "://";
  const char *portDelim = ":";
  const char *pathDelim = "/";

  char *host = strstr(url_copy, schemaDelim) + strlen(schemaDelim);
  char *port = strstr(host, portDelim);

  int p = 80;
  if (port != NULL)
  {
    port += strlen(portDelim);

    host = strtok(host, portDelim);
    port = strtok(NULL, pathDelim);

    p = atoi(port);
  }
  else
  {
    host = strtok(host, pathDelim);
  }
  // ---- End of URL parsing ----

  struct hostent *server;
  struct sockaddr_in serv_addr;
  int sockfd;

  char message[10240];
  memset(message, 0, 10240);
  char response[30720];
  memset(response, 0, 30720);

  char *messageTemplate =
      "POST %s HTTP/1.0\r\n"
      "Host: %s:%d\r\n"
      "Content-Type: application/ocsp-request\r\n"
      "Content-Length: %d\r\n"
      "\r\n";

  sprintf(message, messageTemplate, url, host, p, requestData.dataLen);

  int messageLen = strlen(message);
  memcpy(message + messageLen, requestData.data, requestData.dataLen);
  messageLen += requestData.dataLen;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0)
  {
    fprintf(stderr, "[error] OCSP Request: error creating socket\n");
    return emptyResult;
  }

  // Set Socket timeout (1.5 sec)
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 500000;
  setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&tv, sizeof tv);
  setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

  server = gethostbyname(host);
  if (server == NULL)
  {
    return emptyResult;
  }

  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(p);
  memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    return emptyResult;
  }

  // Send request to socket
  ssize_t sent = send(sockfd, message, messageLen, 0);
  if (sent == -1)
  {
    fprintf(stderr, "[error] OCSP Request (%s) - send failed with an error: %s (%d)\n", url, strerror(errno), errno);
    return emptyResult;
  }
  if (sent < messageLen)
  {
    fprintf(stderr, "[error] OCSP Request (%s): partial content sent (timeout)\n", url);
    return emptyResult;
  }

  // Receive response from socket
  ssize_t received = recv(sockfd, response, sizeof(response), MSG_WAITALL);
  if (received == -1)
  {
    fprintf(stderr, "[error] OCSP Request (%s) - recv failed with an error: %s (%d)\n", url, strerror(errno), errno);
    return emptyResult;
  }

  close(sockfd);

  // Validate response content type
  if (strstr(response, "application/ocsp-response") == NULL)
  {
    fprintf(stderr, "[error] OCSP Request (%s): incorrect response content type\n", url);
    return emptyResult;
  }

  // Validate and parse response content length
  char *contentLengthStart = strstr(response, "Content-Length: ");

  if (contentLengthStart == NULL)
  {
    fprintf(stderr, "[error] OCSP Request (%s): incorrect response content length\n", url);
    return emptyResult;
  }

  int contentLength = atoi(contentLengthStart + strlen("Content-Length: "));

  if (contentLength == 0)
  {
    fprintf(stderr, "[error] OCSP Request (%s): incorrect response content length\n", url);
    return emptyResult;
  }

  if (received <= contentLength)
  {
    fprintf(stderr, "[error] OCSP Request (%s): partial content received (timeout)\n", url);
    return emptyResult;
  }

  int headerLength = received - contentLength;

  UAC_BLOB result = {enif_alloc(contentLength), contentLength};
  memcpy(result.data, response + headerLength, contentLength);

  return result;
}

bool CheckOCSP(UAC_BLOB cert, UAC_CERT_INFO certInfo, UAC_BLOB ocspCert, bool verify)
{
  bool validation_result = true;

  char *ocspRequestBuf[4960];
  UAC_BLOB ocspRequest = {ocspRequestBuf, sizeof(ocspRequestBuf)};

  DWORD ocspRequestCreateResult = UAC_OcspRequestCreate(&cert, NULL, 0, &ocspRequest);
  if (ocspRequestCreateResult != UAC_SUCCESS)
  {
    return false;
  }

  char *ocspUrl = certInfo.accessOCSP;
  UAC_BLOB ocspResponse = SendOCSPRequest(ocspUrl, ocspRequest);
  UAC_OCSP_RESPONSE_INFO ocspResponseInfo = {0};

  if (UAC_OcspResponseLoad(&ocspResponse, &ocspResponseInfo) == UAC_SUCCESS)
  {
    char certBuf[3072];
    UAC_BLOB resp_cert = {certBuf, sizeof(certBuf)};
    if (ocspResponseInfo.signature.signerRef.options != 0)
    { // Respose signed
      if (UAC_SUCCESS != UAC_OcspResponseFindCert(&ocspResponse, &ocspResponseInfo.signature.signerRef, &resp_cert))
      {
        resp_cert = ocspCert;
      }
    }

    if (verify)
    {
      DWORD signResult = UAC_OcspResponseVerify(&ocspResponse, &resp_cert);
      if (UAC_ERROR_NO_SIGNATURE == signResult || UAC_SUCCESS != signResult)
      {
        validation_result = false;
      }
    }
  }
  else
  {
    validation_result = false;
  }

  if (ocspResponse.data)
    enif_free(ocspResponse.data);

  return validation_result && (ocspResponseInfo.certStatus == 0);
}

//Check signature without oscp
struct BaseValidationResult BaseCheck(UAC_BLOB signedData, UAC_SIGNED_DATA_INFO signedDataInfo, PUAC_SUBJECT_INFO subjectInfo,
                              struct Certs certs)
{
  // TODO: make enif free
  struct CertificateCheckInfo* certificatesCheckInfo = enif_alloc(sizeof(struct CertificateCheckInfo) * signedDataInfo.dwSignatureCount);
  struct BaseValidationResult validationResult = {false, "error validating signed data container", 0};

  char tsBuf[4000];
  UAC_BLOB timeStamp = {tsBuf, sizeof(tsBuf)};
  if (UAC_SignedDataGetTs(&signedData, 0, &timeStamp) != UAC_SUCCESS)
  {
    validationResult.validationErrorMessage = "retrieving a timestamp of data from an envelope with signed data failed";
    return validationResult;
  }

  UAC_TIME_STAMP_INFO timeStampInfo = {0};
  if (UAC_TsResponseLoad(&timeStamp, &timeStampInfo) != UAC_SUCCESS)
  {
    validationResult.validationErrorMessage = "loading information about the response with a timestamp failed";
    return validationResult;
  }

  UAC_TIME timeStampDateTime = timeStampInfo.genTime;
  UAC_BLOB tspCert = FindMatchingTspCertificate(timeStampInfo.signature.signerRef, certs.tsp,
                                                certs.tspLength);

  DWORD i;
  for (i = 0; i < signedDataInfo.dwSignatureCount; i++)
  {
    char certBuf[3072]; // Certificate size is limited < 3 Kb
    UAC_BLOB cert = {certBuf, sizeof(certBuf)};

    //SignedDataFindCert(libHandler, &signedData, &signedDataInfo.pSignatures[i], &cert);

    if (UAC_GetCert(UAC_CT_SIGNEDDATA, &signedData, i, &cert) != UAC_SUCCESS)
    {
      validationResult.validationErrorMessage = "retrieving certificate from signed data container failed";
      return validationResult;
    }

    UAC_CERT_INFO certInfo = {};
    if (UAC_CertLoad(&cert, &certInfo) != UAC_SUCCESS)
    {
      validationResult.validationErrorMessage = "processing certificate information from signed data failed";
      return validationResult;
    }

    memcpy(subjectInfo, &certInfo.subject, sizeof(UAC_SUBJECT_INFO));
    struct GeneralCert matchingCert = FindMatchingRootCertificate(cert, certs.general,
                                                                  certs.generalLength);
    if (matchingCert.root.data == NULL)
    {
      validationResult.validationErrorMessage = "matching ROOT certificate not found";
      return validationResult;
    }

    UAC_BLOB rootCert = matchingCert.root;
    DWORD certVerifyResult = UAC_CertVerify(&cert, &rootCert);
    if (certVerifyResult != 0)
    {
      validationResult.validationErrorMessage = "ROOT certificate signature verification failed";
      return validationResult;
    }

    UAC_CERT_INFO rootCertInfo = {};
    DWORD getRootCertInfoResult = UAC_CertLoad(&rootCert, &rootCertInfo);
    if (getRootCertInfoResult != 0)
    {
      validationResult.validationErrorMessage = "loading ROOT certificate information failed";
      return validationResult;
    }

    bool isHighestLevel = IsHighestLevel(rootCertInfo);
    if (!isHighestLevel)
    {
      if (tspCert.data == NULL)
      {
        validationResult.validationErrorMessage = "matching TSP certificate not found";
        return validationResult;
      }
      bool isTimeStampCertValid = VerifyTimeStampCert(timeStamp, tspCert);
      if (!isTimeStampCertValid)
      {
        validationResult.validationErrorMessage = "checking the signature of a response with a timestamp failed";
        return validationResult;
      }
    }

    bool isTimeStampValid = CheckTimeStamp(certInfo, timeStampDateTime);
    if (!isTimeStampValid)
    {
      validationResult.validationErrorMessage = "signature timestamp verification failed";
      return validationResult;
    }
    bool isCertNotExpired = CheckTimeStamp(certInfo, time(0));
    if (!isCertNotExpired)
    {
      validationResult.validationErrorMessage = "certificate timestamp expired";
      return validationResult;
    }

    char *ocspRequestBuf[4960];
    UAC_BLOB ocspRequest = {ocspRequestBuf, sizeof(ocspRequestBuf)};

    DWORD ocspRequestCreateResult = UAC_OcspRequestCreate(&cert, NULL, 0, &ocspRequest);
    struct CertificateCheckInfo oscpCertificateCheckInfo =
    {
      certInfo.crlDistributionPoints,
      certInfo.crlDeltaDistributionPoints,
      certInfo.accessOCSP,
      ocspRequest.data,
      ocspRequest.dataLen,
      ocspRequestCreateResult == UAC_SUCCESS
    };


    certificatesCheckInfo[i] = oscpCertificateCheckInfo;


    DWORD signedDataVerifyResult = UAC_SignedDataVerify(&signedData, &cert, NULL);
    if (signedDataVerifyResult != UAC_SUCCESS)
    {
      validationResult.validationErrorMessage = "verification of data siganture for a given subscriber failed";
      return validationResult;
    }
  }

  validationResult.certsCheckInfo = certificatesCheckInfo;
  validationResult.checkSize = i;

  if (i > 0)
  {
    validationResult.isValid = true;
    validationResult.validationErrorMessage = "";
  }
  return validationResult;
}


struct ValidationResult Check(UAC_BLOB signedData, UAC_SIGNED_DATA_INFO signedDataInfo, PUAC_SUBJECT_INFO subjectInfo,
                              struct Certs certs)
{
  struct ValidationResult validationResult = {false, "error validating signed data container"};

  char tsBuf[4000];
  UAC_BLOB timeStamp = {tsBuf, sizeof(tsBuf)};
  if (UAC_SignedDataGetTs(&signedData, 0, &timeStamp) != UAC_SUCCESS)
  {
    validationResult.validationErrorMessage = "retrieving a timestamp of data from an envelope with signed data failed";
    return validationResult;
  }

  UAC_TIME_STAMP_INFO timeStampInfo = {0};
  if (UAC_TsResponseLoad(&timeStamp, &timeStampInfo) != UAC_SUCCESS)
  {
    validationResult.validationErrorMessage = "loading information about the response with a timestamp failed";
    return validationResult;
  }

  UAC_TIME timeStampDateTime = timeStampInfo.genTime;
  UAC_BLOB tspCert = FindMatchingTspCertificate(timeStampInfo.signature.signerRef, certs.tsp,
                                                certs.tspLength);

 struct CertificateCheckInfo oscpCheckInfo[signedDataInfo.dwSignatureCount];

  DWORD i;
  for (i = 0; i < signedDataInfo.dwSignatureCount; i++)
  {
    char certBuf[3072]; // Certificate size is limited < 3 Kb
    UAC_BLOB cert = {certBuf, sizeof(certBuf)};

    //SignedDataFindCert(libHandler, &signedData, &signedDataInfo.pSignatures[i], &cert);

    if (UAC_GetCert(UAC_CT_SIGNEDDATA, &signedData, i, &cert) != UAC_SUCCESS)
    {
      validationResult.validationErrorMessage = "retrieving certificate from signed data container failed";
      return validationResult;
    }

    UAC_CERT_INFO certInfo = {};
    if (UAC_CertLoad(&cert, &certInfo) != UAC_SUCCESS)
    {
      validationResult.validationErrorMessage = "processing certificate information from signed data failed";
      return validationResult;
    }

    memcpy(subjectInfo, &certInfo.subject, sizeof(UAC_SUBJECT_INFO));
    struct GeneralCert matchingCert = FindMatchingRootCertificate(cert, certs.general,
                                                                  certs.generalLength);
    if (matchingCert.root.data == NULL)
    {
      validationResult.validationErrorMessage = "matching ROOT certificate not found";
      return validationResult;
    }

    UAC_BLOB rootCert = matchingCert.root;
    DWORD certVerifyResult = UAC_CertVerify(&cert, &rootCert);
    if (certVerifyResult != 0)
    {
      validationResult.validationErrorMessage = "ROOT certificate signature verification failed";
      return validationResult;
    }

    UAC_CERT_INFO rootCertInfo = {};
    DWORD getRootCertInfoResult = UAC_CertLoad(&rootCert, &rootCertInfo);
    if (getRootCertInfoResult != 0)
    {
      validationResult.validationErrorMessage = "loading ROOT certificate information failed";
      return validationResult;
    }

    bool isHighestLevel = IsHighestLevel(rootCertInfo);
    if (!isHighestLevel)
    {
      if (tspCert.data == NULL)
      {
        validationResult.validationErrorMessage = "matching TSP certificate not found";
        return validationResult;
      }
      bool isTimeStampCertValid = VerifyTimeStampCert(timeStamp, tspCert);
      if (!isTimeStampCertValid)
      {
        validationResult.validationErrorMessage = "checking the signature of a response with a timestamp failed";
        return validationResult;
      }
    }

    bool isTimeStampValid = CheckTimeStamp(certInfo, timeStampDateTime);
    if (!isTimeStampValid)
    {
      validationResult.validationErrorMessage = "signature timestamp verification failed";
      return validationResult;
    }
    bool isCertNotExpired = CheckTimeStamp(certInfo, time(0));
    if (!isCertNotExpired)
    {
      validationResult.validationErrorMessage = "certificate timestamp expired";
      return validationResult;
    }

    bool checkOSCP = CheckOCSP(cert, certInfo, matchingCert.ocsp, !isHighestLevel);
    if (!checkOSCP)
    {
      validationResult.validationErrorMessage = "OCSP certificate verificaton failed";
      return validationResult;
    }
    DWORD signedDataVerifyResult = UAC_SignedDataVerify(&signedData, &cert, NULL);
    if (signedDataVerifyResult != UAC_SUCCESS)
    {
      validationResult.validationErrorMessage = "verification of data siganture for a given subscriber failed";
      return validationResult;
    }
  }

  if (i > 0)
  {
    validationResult.isValid = true;
    validationResult.validationErrorMessage = "";
  }
  return validationResult;
}
