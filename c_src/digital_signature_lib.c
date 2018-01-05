#define LINUX

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include "h/UACryptoDef.h"

struct GeneralCert
{
    UAC_BLOB root;
    UAC_BLOB ocsp;
};

struct Certs
{
    struct GeneralCert* general;
    unsigned int generalLength;

    UAC_BLOB* tsp;
    unsigned int tspLength;
};

struct ValidationResult
{
  bool isValid;
  char* validationErrorMessage;
};

DWORD GetTimeStamp(void* libHandler, UAC_BLOB signedData, PUAC_BLOB timeStamp)
{
    DWORD (*getTimeStamp)(PUAC_BLOB, DWORD, PUAC_BLOB);
    getTimeStamp = dlsym(libHandler, "UAC_SignedDataGetTs");
    return (*getTimeStamp)(&signedData, 0, timeStamp);
}

DWORD GetTimeStampInfo(void* libHandler, UAC_BLOB timeStamp, PUAC_TIME_STAMP_INFO timeStampInfo)
{
    DWORD (*getTimeStampInfo)(PUAC_BLOB, PUAC_TIME_STAMP_INFO);
    getTimeStampInfo = dlsym(libHandler, "UAC_TsResponseLoad");
    return (*getTimeStampInfo)(&timeStamp, timeStampInfo);
}

DWORD LoadSignedData(void* libHandler, UAC_BLOB signedData, PUAC_BLOB data, PUAC_SIGNED_DATA_INFO signedDataInfo)
{
    DWORD (*signedDataLoad)(PUAC_BLOB, PUAC_BLOB, PUAC_SIGNED_DATA_INFO);
    signedDataLoad = dlsym(libHandler, "UAC_SignedDataLoad");
    return (*signedDataLoad)(&signedData, data, signedDataInfo);
}

DWORD GetCert(void* libHandler, UAC_BLOB signedData, DWORD index, PUAC_BLOB cert)
{
    DWORD (*getCert)(UAC_CT, PUAC_BLOB, DWORD, PUAC_BLOB);
    getCert = dlsym(libHandler, "UAC_GetCert");
    return (*getCert)(UAC_CT_SIGNEDDATA, &signedData, index, cert);
}

DWORD GetCertInfo(void* libHandler, UAC_BLOB cert, PUAC_CERT_INFO certInfo)
{
    DWORD (*getCertInfo)(PUAC_BLOB, PUAC_CERT_INFO);
    getCertInfo = dlsym(libHandler, "UAC_CertLoad");
    return (*getCertInfo)(&cert, certInfo);
}

DWORD CertIssuerRef(void* libHandler, UAC_BLOB cert, PUAC_CERT_REF certRef)
{
    DWORD (*certIssuerRef)(PUAC_BLOB, PUAC_CERT_REF);
    certIssuerRef = dlsym(libHandler, "UAC_CertIssuerRef");
    return (*certIssuerRef)(&cert, certRef);
}

DWORD CertMatch(void* libHandler, UAC_CERT_REF certRef, UAC_BLOB cert)
{
    DWORD (*certMatch)(PUAC_CERT_REF, PUAC_BLOB);
    certMatch = dlsym(libHandler, "UAC_CertMatch");
    return (*certMatch)(&certRef, &cert);
}

DWORD CertVerify(void* libHandler, UAC_BLOB cert, UAC_BLOB rootCert)
{
    DWORD (*certVerify)(PUAC_BLOB, PUAC_BLOB);
    certVerify = dlsym(libHandler, "UAC_CertVerify");
    return (*certVerify)(&cert, &rootCert);
}

DWORD TsResponseVerify(void* libHandler, UAC_BLOB timeStamp, UAC_BLOB tspCert)
{
    DWORD (*tsResponseVerify)(PUAC_BLOB, PUAC_BLOB);
    tsResponseVerify = dlsym(libHandler, "UAC_TsResponseVerify");
    return (*tsResponseVerify)(&timeStamp, &tspCert);
}

DWORD SignedDataVerify(void* libHandler, UAC_BLOB signedData, UAC_BLOB cert)
{
    DWORD (*signedDataVerify)(PUAC_BLOB, PUAC_BLOB, PUAC_BLOB);
    signedDataVerify = dlsym(libHandler, "UAC_SignedDataVerify");
    return (*signedDataVerify)(&signedData, &cert, NULL);
}

DWORD OcspRequestCreate(void* libHandler, UAC_BLOB cert, PUAC_BLOB ocspRequest)
{
    DWORD (*ocspRequestCreate)(PUAC_BLOB, PUAC_KEYPAIR, DWORD, PUAC_BLOB);
    ocspRequestCreate = dlsym(libHandler, "UAC_OcspRequestCreate");
    return (*ocspRequestCreate)(&cert, NULL, UAC_OPTION_INCLUDE_NONCE, ocspRequest);
}

DWORD OcspResponseVerify(void* libHandler, UAC_BLOB response, UAC_BLOB cert)
{
    DWORD (*ocspResponseVerify)(PUAC_BLOB, PUAC_BLOB);
    ocspResponseVerify = dlsym(libHandler, "UAC_OcspResponseVerify");
    return (*ocspResponseVerify)(&response, &cert);
}

DWORD OcspResponseLoad(void* libHandler, UAC_BLOB response, PUAC_OCSP_RESPONSE_INFO ocspResponseInfo)
{
    DWORD (*ocspResponseLoad)(PUAC_BLOB, PUAC_OCSP_RESPONSE_INFO);
    ocspResponseLoad = dlsym(libHandler, "UAC_OcspResponseLoad");
    return (*ocspResponseLoad)(&response, ocspResponseInfo);
}

struct GeneralCert FindMatchingRootCertificate(void* libHandler, UAC_BLOB cert, struct GeneralCert* generalCerts,
  unsigned int generalLength)
{
    struct GeneralCert emptyResult = {};
    UAC_CERT_REF issuerCertRef = {};

    if (CertIssuerRef(libHandler, cert, &issuerCertRef) != UAC_SUCCESS) {
        return emptyResult;
    }

    unsigned int i = 0;
    UAC_BLOB rootCert;

    while (i < generalLength) {
        rootCert = generalCerts[i].root;

        if (CertMatch(libHandler, issuerCertRef, rootCert) == UAC_SUCCESS) {
          return generalCerts[i];
        }

        i++;
    }

    return emptyResult;
}

UAC_BLOB FindMatchingTspCertificate(void* libHandler, UAC_CERT_REF signerRef, UAC_BLOB* tsp, unsigned int tspLength)
{
    UAC_BLOB emptyBlob = {};
    unsigned int i = 0;
    UAC_BLOB tspCert = tsp[i];

    while (i < tspLength) {
        DWORD certMatchResult = CertMatch(libHandler, signerRef, tspCert);
        if (certMatchResult == 0) {
            return tsp[i];
        }

        i++;
        tspCert = tsp[i];
    }

    return emptyBlob;
}

bool IsHighestLevel(UAC_CERT_INFO certInfo)
{
    char* subjectKeyIdentifier = certInfo.subjectKeyIdentifier;
    char* authorityKeyIdentifier = certInfo.authorityKeyIdentifier;
    int compareResult = strcmp(subjectKeyIdentifier, authorityKeyIdentifier);
    return compareResult == 0;
}

bool VerifyTimeStampCert(void* libHandler, UAC_BLOB timeStamp, UAC_BLOB tspCert) {
    DWORD tsResponseVerifyResult = TsResponseVerify(libHandler, timeStamp, tspCert);
    return tsResponseVerifyResult == 0;
}

bool CheckTimeStamp(UAC_CERT_INFO certInfo, UAC_TIME signatureDate)
{
    UAC_TIME notAfter = certInfo.validity.notAfter;
    UAC_TIME notBefore = certInfo.validity.notBefore;
    return signatureDate <= notAfter && signatureDate >= notBefore;
}

UAC_BLOB SendOCSPRequest(char* url, UAC_BLOB requestData)
{
    UAC_BLOB emptyResult = {};

    // ---- Parse URL ----
    char url_copy[strlen(url)];
    memcpy(url_copy, url, strlen(url));

    const char* schemaDelim = "://";
    const char* portDelim = ":";
    const char* pathDelim = "/";

    char* host = strstr(url_copy, schemaDelim) + strlen(schemaDelim);
    char* port = strstr(host, portDelim);

    int p = 80;
    if (port != NULL) {
        port += strlen(portDelim);

        host = strtok(host, portDelim);
        port = strtok(NULL, pathDelim);

        p = atoi(port);
    } else {
        host = strtok(host, pathDelim);
    }
    // ---- End of URL parsing ----
    struct hostent* server;
    struct sockaddr_in serv_addr;
    int sockfd;

    const int MESSAGE_SIZE = 102400; // 10 Kb
    char* message = calloc(MESSAGE_SIZE, sizeof(char));
    char* response = calloc(MESSAGE_SIZE, sizeof(char));

    char* messageTemplate =
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
    if (sockfd < 0) {
        return emptyResult;
    }

    server = gethostbyname(host);
    if (server == NULL) {
        return emptyResult;
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(p);
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);

    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        return emptyResult;
    }

    // Send request to socket
    int sent = send(sockfd, message, messageLen, 0);
    if(sent < 0)
    {
        return emptyResult;
    }

    // Receive response from socket
    int received = recv(sockfd, response, MESSAGE_SIZE, MSG_WAITALL);
    if(received < 0)
    {
        return emptyResult;
    }

    close(sockfd);

    char* contentLengthStart = strstr(response, "Content-Length: ") + strlen("Content-Length: ");
    int contentLength = atoi(contentLengthStart);
    int headerLength = received - contentLength;

    UAC_BLOB result = {calloc(contentLength, sizeof(char)), contentLength};
    memcpy(result.data, response + headerLength, contentLength);

    // Free
    if(message) free(message);
    if(response) free(response);

    return result;
}

bool CheckOCSP(void* libHandler, UAC_BLOB cert, UAC_CERT_INFO certInfo, UAC_BLOB ocspCert, bool verify)
{
    char* ocspRequestBuf = calloc(cert.dataLen, sizeof(char));

    UAC_BLOB ocspRequest = {ocspRequestBuf, cert.dataLen};
    DWORD ocspRequestCreateResult = OcspRequestCreate(libHandler, cert, &ocspRequest);
    if (ocspRequestCreateResult != 0) {
        return false;
    }
    char* ocspUrl = certInfo.accessOCSP;
    UAC_BLOB ocspResponse = SendOCSPRequest(ocspUrl, ocspRequest);
    UAC_OCSP_RESPONSE_INFO ocspResponseInfo = {};
    if (verify) {
        if (OcspResponseVerify(libHandler, ocspResponse, ocspCert) != UAC_SUCCESS) {
            return false;
        }
    }
    if (OcspResponseLoad(libHandler, ocspResponse, &ocspResponseInfo) != UAC_SUCCESS) {
        return false;
    }

    return ocspResponseInfo.certStatus == 0;
}

struct ValidationResult Check(void* libHandler, UAC_BLOB signedData, UAC_SIGNED_DATA_INFO signedDataInfo, PUAC_SUBJECT_INFO subjectInfo,
           struct Certs certs)
{
    struct ValidationResult validationResult = {false, "error validating signed data container"};
    int signaturesCount = signedDataInfo.dwSignatureCount;

    char* timeStampBuf = calloc(signedData.dataLen, sizeof(char));
    UAC_BLOB timeStamp = {timeStampBuf, signedData.dataLen};
    if (GetTimeStamp(libHandler, signedData, &timeStamp) != UAC_SUCCESS) {
        validationResult.validationErrorMessage = "retrieving a timestamp of data from an envelope with signed data failed";
        return validationResult;
    }

    UAC_TIME_STAMP_INFO timeStampInfo = {};
    if (GetTimeStampInfo(libHandler, timeStamp, &timeStampInfo) != UAC_SUCCESS) {
        validationResult.validationErrorMessage = "loading information about the response with a timestamp failed";
        return validationResult;
    }

    UAC_TIME timeStampDateTime = timeStampInfo.genTime;
    UAC_BLOB tspCert = FindMatchingTspCertificate(libHandler, timeStampInfo.signature.signerRef, certs.tsp,
      certs.tspLength);

    int i;
    for (i = 0; i < signaturesCount; i++) {
        char* certBuf = calloc(signedData.dataLen, sizeof(char));
        UAC_BLOB cert = {certBuf, signedData.dataLen};
        if (GetCert(libHandler, signedData, i, &cert) != UAC_SUCCESS) {
            validationResult.validationErrorMessage = "retrieving certificate from signed data container failed";
            return validationResult;
        }

        UAC_CERT_INFO certInfo = {};
        if (GetCertInfo(libHandler, cert, &certInfo) != UAC_SUCCESS) {
            validationResult.validationErrorMessage = "processing certificate information from signed data failed";
            return validationResult;
        }

        memcpy(subjectInfo, &certInfo.subject, sizeof(UAC_SUBJECT_INFO));
        struct GeneralCert matchingCert = FindMatchingRootCertificate(libHandler, cert, certs.general,
          certs.generalLength);
        if (matchingCert.root.data == NULL) {
            validationResult.validationErrorMessage = "matching ROOT certificate not found";
            return validationResult;
        }

        UAC_BLOB rootCert = matchingCert.root;
        DWORD certVerifyResult = CertVerify(libHandler, cert, rootCert);
        if (certVerifyResult != 0) {
            validationResult.validationErrorMessage = "ROOT certificate signature verification failed";
            return validationResult;
        }
        UAC_CERT_INFO rootCertInfo = {};
        DWORD getRootCertInfoResult = GetCertInfo(libHandler, rootCert, &rootCertInfo);
        if (getRootCertInfoResult != 0) {
            validationResult.validationErrorMessage = "loading ROOT certificate information failed";
            return validationResult;
        }
        bool isHighestLevel = IsHighestLevel(rootCertInfo);
        if (!isHighestLevel) {
            if (tspCert.data == NULL) {
                validationResult.validationErrorMessage = "matching TSP certificate not found";
                return validationResult;
            }
            bool isTimeStampCertValid = VerifyTimeStampCert(libHandler, timeStamp, tspCert);
            if (!isTimeStampCertValid) {
                validationResult.validationErrorMessage = "checking the signature of a response with a timestamp failed";
            return validationResult;
            }
        }
        bool isTimeStampValid = CheckTimeStamp(certInfo, timeStampDateTime);
        if (!isTimeStampValid) {
            validationResult.validationErrorMessage = "signature timestamp verification failed";
            return validationResult;
        }
        bool isCertNotExpired = CheckTimeStamp(certInfo, time(0));
        if (!isCertNotExpired) {
            validationResult.validationErrorMessage = "certificate timestemp expired";
            return validationResult;
        }

        bool checkOSCP = CheckOCSP(libHandler, cert, certInfo, matchingCert.ocsp, !isHighestLevel);
        if (!checkOSCP) {
            validationResult.validationErrorMessage = "OCSP certificate verificaton failed";
            return validationResult;
        }
        DWORD signedDataVerifyResult = SignedDataVerify(libHandler, signedData, cert);
        if (signedDataVerifyResult != UAC_SUCCESS) {
            validationResult.validationErrorMessage = "verification of data siganture for a given subscriber failed";
            return validationResult;
        }
    }

    if(i != 0)
    {
      validationResult.isValid = true;
      validationResult.validationErrorMessage = "";
    }
    return validationResult;
}
