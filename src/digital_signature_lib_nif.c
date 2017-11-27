#define LINUX

#include "erl_nif.h"
#include "digital_signature_lib.c"

char LIB_PATH[250];

static ERL_NIF_TERM
ProcessPKCS7Data(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  void* libHandler;

  char* libPath;
  char* configuredPath = getenv("UACRYPTO_LIB_PATH");

  if (configuredPath != NULL) {
    libPath = configuredPath;
  }
  else {
    libPath = LIB_PATH;
  }

  libHandler = dlopen(libPath, RTLD_LAZY);
  if (!libHandler) {
    const char* error =  dlerror();
    ErlNifBinary errorBin = {strlen(error), (unsigned char*) error};
    ERL_NIF_TERM errorTerm = enif_make_binary(env, &errorBin);
    return enif_make_tuple2(env, enif_make_atom(env, "error"), errorTerm);
  }

  PUAC_SUBJECT_INFO subjectInfo = malloc(sizeof(UAC_SUBJECT_INFO));
  memset(subjectInfo, 0, sizeof(UAC_SUBJECT_INFO));

  unsigned int p7DataLength;
  enif_get_list_length(env, argv[0], &p7DataLength);
  if (p7DataLength == 0) {
    ERL_NIF_TERM errorTerm = enif_make_string(env, "pkcs7 data is empty", ERL_NIF_LATIN1);
    return enif_make_tuple2(env, enif_make_atom(env, "error"), errorTerm);
  }
  char p7Data[p7DataLength];
  memset(p7Data, 0, p7DataLength);
  enif_get_string(env, argv[0], p7Data, p7DataLength + 1, ERL_NIF_LATIN1);
  UAC_BLOB signedData = { p7Data, p7DataLength };

  struct Certs certs;

  ERL_NIF_TERM generalCerts;
  enif_get_map_value(env, argv[1], enif_make_atom(env, "general"), &generalCerts);
  unsigned int generalCertsLength;
  enif_get_list_length(env, generalCerts, &generalCertsLength);
  unsigned int i;
  for (i = 0; i < generalCertsLength; i++) {
    ERL_NIF_TERM firstItem;
    ERL_NIF_TERM rest;
    enif_get_list_cell(env, generalCerts, &firstItem, &rest);

    ERL_NIF_TERM rootCertTerm;
    enif_get_map_value(env, firstItem, enif_make_atom(env, "root"), &rootCertTerm);
    unsigned int rootCertDataLength;
    enif_get_list_length(env, rootCertTerm, &rootCertDataLength);
    char* rootCertData = malloc(rootCertDataLength);
    memset(rootCertData, 0, rootCertDataLength);
    enif_get_string(env, rootCertTerm, rootCertData, rootCertDataLength, ERL_NIF_LATIN1);
    UAC_BLOB rootCert = { rootCertData, rootCertDataLength };

    ERL_NIF_TERM ocspCertTerm;
    enif_get_map_value(env, firstItem, enif_make_atom(env, "ocsp"), &ocspCertTerm);
    unsigned int ocspCertDataLength;
    enif_get_list_length(env, ocspCertTerm, &ocspCertDataLength);
    char* ocspCertData = malloc(ocspCertDataLength);
    memset(ocspCertData, 0, ocspCertDataLength);
    enif_get_string(env, ocspCertTerm, ocspCertData, ocspCertDataLength, ERL_NIF_LATIN1);
    UAC_BLOB ocspCert = { ocspCertData, ocspCertDataLength };

    certs.general[i].root = rootCert;
    certs.general[i].ocsp = ocspCert;
    generalCerts = rest;
  }

  UAC_BLOB emptyBlob = {};
  certs.general[generalCertsLength].root = emptyBlob;
  certs.general[generalCertsLength].ocsp = emptyBlob;

  ERL_NIF_TERM tspCerts;
  enif_get_map_value(env, argv[1], enif_make_atom(env, "tsp"), &tspCerts);
  unsigned int tspCertsLength;
  enif_get_list_length(env, tspCerts, &tspCertsLength);
  for (i = 0; i < tspCertsLength; i++) {
    ERL_NIF_TERM firstItem;
    ERL_NIF_TERM rest;
    enif_get_list_cell(env, tspCerts, &firstItem, &rest);
    unsigned int tspCertDataLength;
    enif_get_list_length(env, firstItem, &tspCertDataLength);
    char* tspCertData = malloc(tspCertDataLength);
    memset(tspCertData, 0, tspCertDataLength);
    enif_get_string(env, firstItem, tspCertData, tspCertDataLength, ERL_NIF_LATIN1);
    UAC_BLOB tspCert = { tspCertData, tspCertDataLength };

    certs.tsp[i] = tspCert;
    tspCerts = rest;
  }

  certs.tsp[tspCertsLength] = emptyBlob;

  char dataBlobBuffer[signedData.dataLen];
  memset(dataBlobBuffer, 0, signedData.dataLen);
  UAC_BLOB dataBlob = {dataBlobBuffer, signedData.dataLen};

  UAC_SIGNED_DATA_INFO signedDataInfo;
  LoadSignedData(libHandler, signedData, &dataBlob, &signedDataInfo);

  bool checkResult = false;

  int check;
  enif_get_int(env, argv[2], &check);

  if (check == 1) {
    checkResult = Check(libHandler, signedData, signedDataInfo, subjectInfo, certs);
  }
  dlclose(libHandler);

  ERL_NIF_TERM signer = enif_make_new_map(env);
  const char* commonName = subjectInfo->commonName;
  int commonNameLength = strlen(commonName);
  ErlNifBinary commonNameBin = {};
  if (commonNameLength < 64) {
    commonNameBin.size = commonNameLength;
    commonNameBin.data = (unsigned char *)commonName;
  }
  else {
    commonNameBin.size = 0;
    commonNameBin.data = (unsigned char *)"";
  }
  ERL_NIF_TERM commonNameTerm = enif_make_binary(env, &commonNameBin);
  enif_make_map_put(env, signer, enif_make_atom(env, "common_name"), commonNameTerm, &signer);
  const char* countryName = subjectInfo->countryName;
  int countryNameLength = strlen(countryName);
  ErlNifBinary countryNameBin = {};
  if (countryNameLength < 64) {
    countryNameBin.size = countryNameLength;
    countryNameBin.data = (unsigned char *)countryName;
  }
  else {
    countryNameBin.size = 0;
    countryNameBin.data = (unsigned char *)"";
  }
  ERL_NIF_TERM countryNameTerm = enif_make_binary(env, &countryNameBin);
  enif_make_map_put(env, signer, enif_make_atom(env, "country_name"), countryNameTerm, &signer);
  const char* surname = subjectInfo->surname;
  int surnameLength = strlen(surname);
  ErlNifBinary surnameBin = {};
  if (surnameLength < 64) {
    surnameBin.size = surnameLength;
    surnameBin.data = (unsigned char *)surname;
  }
  else {
    surnameBin.size = 0;
    surnameBin.data = (unsigned char *)"";
  }
  ERL_NIF_TERM surnameTerm = enif_make_binary(env, &surnameBin);
  enif_make_map_put(env, signer, enif_make_atom(env, "surname"), surnameTerm, &signer);
  const char* givenName = subjectInfo->givenName;
  int givenNameLength = strlen(givenName);
  ErlNifBinary givenNameBin = {};
  if (givenNameLength < 64) {
    givenNameBin.size = givenNameLength;
    givenNameBin.data = (unsigned char *)givenName;
  }
  else {
    givenNameBin.size = 0;
    givenNameBin.data = (unsigned char *)"";
  }
  ERL_NIF_TERM givenNameTerm = enif_make_binary(env, &givenNameBin);
  enif_make_map_put(env, signer, enif_make_atom(env, "given_name"), givenNameTerm, &signer);
  const char* organizationName = subjectInfo->organizationName;
  int organizationNameLength = strlen(organizationName);
  ErlNifBinary organizationNameBin = {};
  if (organizationNameLength < 64) {
    organizationNameBin.size = organizationNameLength;
    organizationNameBin.data = (unsigned char *)organizationName;
  }
  else {
    organizationNameBin.size = 0;
    organizationNameBin.data = (unsigned char *)"";
  }
  ERL_NIF_TERM organizationNameTerm = enif_make_binary(env, &organizationNameBin);
  enif_make_map_put(env, signer, enif_make_atom(env, "organization_name"), organizationNameTerm, &signer);
  const char* stateOrProvinceName = subjectInfo->stateOrProvinceName;
  int stateOrProvinceNameLength = strlen(stateOrProvinceName);
  ErlNifBinary stateOrProvinceNameBin = {};
  if (stateOrProvinceNameLength < 64) {
    stateOrProvinceNameBin.size = stateOrProvinceNameLength;
    stateOrProvinceNameBin.data = (unsigned char *)stateOrProvinceName;
  }
  else {
    stateOrProvinceNameBin.size = 0;
    stateOrProvinceNameBin.data = (unsigned char *)"";
  }
  ERL_NIF_TERM stateOrProvinceNameTerm = enif_make_binary(env, &stateOrProvinceNameBin);
  enif_make_map_put(env, signer, enif_make_atom(env, "state_or_province_name"), stateOrProvinceNameTerm, &signer);
  const char* localityName = subjectInfo->localityName;
  int localityNameLength = strlen(localityName);
  ErlNifBinary localityNameBin = {};
  if (localityNameLength < 64) {
    localityNameBin.size = localityNameLength;
    localityNameBin.data = (unsigned char *)localityName;
  }
  else {
    localityNameBin.size = 0;
    localityNameBin.data = (unsigned char *)"";
  }
  ERL_NIF_TERM localityNameTerm = enif_make_binary(env, &localityNameBin);
  enif_make_map_put(env, signer, enif_make_atom(env, "locality_name"), localityNameTerm, &signer);
  const char* organizationalUnitName = subjectInfo->organizationalUnitName;
  int organizationalUnitNameLength = strlen(organizationalUnitName);
  ErlNifBinary organizationalUnitNameBin = {};
  if (organizationalUnitNameLength < 64) {
    organizationalUnitNameBin.size = organizationalUnitNameLength;
    organizationalUnitNameBin.data = (unsigned char *)organizationalUnitName;
  }
  else {
    organizationalUnitNameBin.size = 0;
    organizationalUnitNameBin.data = (unsigned char *)"";
  }
  ERL_NIF_TERM organizationalUnitNameTerm = enif_make_binary(env, &organizationalUnitNameBin);
  enif_make_map_put(env, signer, enif_make_atom(env, "organizational_unit_name"), organizationalUnitNameTerm, &signer);
  const char* title = subjectInfo->title;
  int titleLength = strlen(title);
  ErlNifBinary titleBin = {};
  if (titleLength < 64) {
    titleBin.size = titleLength;
    titleBin.data = (unsigned char *)title;
  }
  else {
    titleBin.size = 0;
    titleBin.data = (unsigned char *)"";
  }
  ERL_NIF_TERM titleTerm = enif_make_binary(env, &titleBin);
  enif_make_map_put(env, signer, enif_make_atom(env, "title"), titleTerm, &signer);
  const char* edrpou = subjectInfo->edrpou;
  int edrpouLength = strlen(edrpou);
  ErlNifBinary edrpouBin = {};
  if (edrpouLength < 64) {
    edrpouBin.size = edrpouLength;
    edrpouBin.data = (unsigned char *)edrpou;
  }
  else {
    edrpouBin.size = 0;
    edrpouBin.data = (unsigned char *)"";
  }
  ERL_NIF_TERM edrpouTerm = enif_make_binary(env, &edrpouBin);
  enif_make_map_put(env, signer, enif_make_atom(env, "edrpou"), edrpouTerm, &signer);
  const char* drfo = subjectInfo->drfo;
  int drfoLength = strlen(drfo);
  ErlNifBinary drfoBin = {};
  if (drfoLength < 64) {
    drfoBin.size = drfoLength;
    drfoBin.data = (unsigned char *)drfo;
  }
  else {
    drfoBin.size = 0;
    drfoBin.data = (unsigned char *)"";
  }
  ERL_NIF_TERM drfoTerm = enif_make_binary(env, &drfoBin);
  enif_make_map_put(env, signer, enif_make_atom(env, "drfo"), drfoTerm, &signer);

  const char* data = dataBlob.data;
  ErlNifBinary dataBin = {strlen(data), (unsigned char *)data};
  ERL_NIF_TERM content = enif_make_binary(env, &dataBin);
  ERL_NIF_TERM result = enif_make_new_map(env);
  enif_make_map_put(env, result, enif_make_atom(env, "content"), content, &result);
  enif_make_map_put(env, result, enif_make_atom(env, "signer"), signer, &result);
  if (check == 1) {
    enif_make_map_put(env, result, enif_make_atom(env, "is_valid"), enif_make_int(env, checkResult), &result);
  }
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), result);
}

static ErlNifFunc nif_funcs[] = {
  {"processPKCS7Data", 3, ProcessPKCS7Data}
};

int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
  enif_get_string(env, load_info, LIB_PATH, 250, ERL_NIF_LATIN1);

  return 0;
}

ERL_NIF_INIT(Elixir.DigitalSignatureLib, nif_funcs, load, NULL, NULL, NULL);
