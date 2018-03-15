#define LINUX

#include "erl_nif.h"
#include "digital_signature_lib.c"
#include "is_utf8.h"

// ----- Helper functions

static ERL_NIF_TERM CreateElixirString(ErlNifEnv *env, const char *str)
{
  int strLength = strlen(str);

  char *message = NULL;
  int faulty_bytes = 0;
  if (is_utf8((unsigned char *)str, strLength, &message, &faulty_bytes) != 0)
  {
    str = '\0';
    strLength = 0;
  }

  ErlNifBinary elixirStr;
  enif_alloc_binary(strLength, &elixirStr);
  memcpy(elixirStr.data, str, strLength);

  return enif_make_binary(env, &elixirStr);
}

static ERL_NIF_TERM CreateErrorTuppe(ErlNifEnv *env, const char *errMessage)
{
  ERL_NIF_TERM errorTerm = CreateElixirString(env, errMessage);
  return enif_make_tuple2(env, enif_make_atom(env, "error"), errorTerm);
}

struct Certs GetCertsFromArg(ErlNifEnv *env, const ERL_NIF_TERM arg)
{
  struct Certs certs;

  ERL_NIF_TERM generalCerts;
  enif_get_map_value(env, arg, enif_make_atom(env, "general"), &generalCerts);
  unsigned int generalCertsLength;
  enif_get_list_length(env, generalCerts, &generalCertsLength);
  unsigned int i;

  certs.generalLength = generalCertsLength;
  certs.general = malloc(generalCertsLength * sizeof(struct GeneralCert));

  for (i = 0; i < generalCertsLength; i++)
  {
    ERL_NIF_TERM firstItem;
    ERL_NIF_TERM rest;
    enif_get_list_cell(env, generalCerts, &firstItem, &rest);

    // Root cert
    ERL_NIF_TERM rootCertTerm;
    enif_get_map_value(env, firstItem, enif_make_atom(env, "root"), &rootCertTerm);

    ErlNifBinary rootCertData;
    enif_inspect_binary(env, rootCertTerm, &rootCertData);
    UAC_BLOB rootCert = {rootCertData.data, rootCertData.size};

    // Oscp cert
    ERL_NIF_TERM ocspCertTerm;
    enif_get_map_value(env, firstItem, enif_make_atom(env, "ocsp"), &ocspCertTerm);

    ErlNifBinary ocspCertData;
    enif_inspect_binary(env, ocspCertTerm, &ocspCertData);
    UAC_BLOB ocspCert = {ocspCertData.data, ocspCertData.size};

    certs.general[i].root = rootCert;
    certs.general[i].ocsp = ocspCert;
    generalCerts = rest;
  }

  ERL_NIF_TERM tspCerts;
  enif_get_map_value(env, arg, enif_make_atom(env, "tsp"), &tspCerts);
  unsigned int tspCertsLength;
  enif_get_list_length(env, tspCerts, &tspCertsLength);

  certs.tspLength = tspCertsLength;
  certs.tsp = malloc(tspCertsLength * sizeof(UAC_BLOB));

  for (i = 0; i < tspCertsLength; i++)
  {
    ERL_NIF_TERM firstItem;
    ERL_NIF_TERM rest;
    enif_get_list_cell(env, tspCerts, &firstItem, &rest);

    ErlNifBinary tspCertData;
    enif_inspect_binary(env, firstItem, &tspCertData);
    UAC_BLOB tspCert = {tspCertData.data, tspCertData.size};

    certs.tsp[i] = tspCert;
    tspCerts = rest;
  }

  return certs;
}

static bool GetChekValue(ErlNifEnv *env, const ERL_NIF_TERM checkAtom)
{
  bool check;
  char checkValue[6];

  enif_get_atom(env, checkAtom, checkValue, sizeof(checkValue), ERL_NIF_LATIN1);
  check = strcmp(checkValue, "false") == 0 ? false : true;

  return check;
}

// ----- Helper functions

static ERL_NIF_TERM
ProcessPKCS7Data(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
  struct ValidationResult validationResult = {true, ""};

  bool check = GetChekValue(env, argv[2]);

  ErlNifBinary p7Data;
  if (!enif_inspect_binary(env, argv[0], &p7Data))
  {
    return CreateErrorTuppe(env, "signed data argument is of incorrect type: must be Elixir string (binary)");
  }

  UAC_BLOB signedData = {p7Data.data, p7Data.size};

  struct Certs certs = {0};
  UAC_BLOB dataBlob = {0};
  UAC_SIGNED_DATA_INFO signedDataInfo = {0};
  PUAC_SUBJECT_INFO subjectInfo = calloc(sizeof(UAC_SUBJECT_INFO), sizeof(UAC_SUBJECT_INFO));

  if (UAC_SignedDataLoad(&signedData, NULL, &signedDataInfo) == UAC_SUCCESS)
  {
    signedDataInfo.pSignatures = malloc(sizeof(UAC_SIGNATURE_INFO) * signedDataInfo.dwSignatureCount);
    dataBlob.data = malloc(signedDataInfo.dwDataLength);
    dataBlob.dataLen = signedDataInfo.dwDataLength;
    UAC_SignedDataLoad(&signedData, &dataBlob, &signedDataInfo);

    certs = GetCertsFromArg(env, argv[1]);

    if (check)
    {
      validationResult = Check(signedData, signedDataInfo, subjectInfo, certs);
    }
  }
  else
  {
    if (dataBlob.data)
      free(dataBlob.data);
    dataBlob.data = "";
    dataBlob.dataLen = strlen("");

    validationResult.isValid = false;
    validationResult.validationErrorMessage = "error processing signed data";
  }

  // dlclose(libHandler);

  // Result

  ERL_NIF_TERM signer = enif_make_new_map(env);

  enif_make_map_put(env, signer, enif_make_atom(env, "common_name"), CreateElixirString(env, subjectInfo->commonName), &signer);
  enif_make_map_put(env, signer, enif_make_atom(env, "common_name"), CreateElixirString(env, subjectInfo->commonName), &signer);
  enif_make_map_put(env, signer, enif_make_atom(env, "country_name"), CreateElixirString(env, subjectInfo->countryName), &signer);
  enif_make_map_put(env, signer, enif_make_atom(env, "surname"), CreateElixirString(env, subjectInfo->surname), &signer);
  enif_make_map_put(env, signer, enif_make_atom(env, "given_name"), CreateElixirString(env, subjectInfo->givenName), &signer);
  enif_make_map_put(env, signer, enif_make_atom(env, "organization_name"), CreateElixirString(env, subjectInfo->organizationName), &signer);
  enif_make_map_put(env, signer, enif_make_atom(env, "state_or_province_name"), CreateElixirString(env, subjectInfo->stateOrProvinceName), &signer);
  enif_make_map_put(env, signer, enif_make_atom(env, "locality_name"), CreateElixirString(env, subjectInfo->localityName), &signer);
  enif_make_map_put(env, signer, enif_make_atom(env, "organizational_unit_name"), CreateElixirString(env, subjectInfo->organizationalUnitName), &signer);
  enif_make_map_put(env, signer, enif_make_atom(env, "title"), CreateElixirString(env, subjectInfo->title), &signer);
  enif_make_map_put(env, signer, enif_make_atom(env, "edrpou"), CreateElixirString(env, subjectInfo->edrpou), &signer);
  enif_make_map_put(env, signer, enif_make_atom(env, "drfo"), CreateElixirString(env, subjectInfo->drfo), &signer);

  ErlNifBinary dataBin;
  enif_alloc_binary(dataBlob.dataLen, &dataBin);
  memcpy(dataBin.data, dataBlob.data, dataBlob.dataLen);
  ERL_NIF_TERM content = enif_make_binary(env, &dataBin);

  ERL_NIF_TERM result = enif_make_new_map(env);
  enif_make_map_put(env, result, enif_make_atom(env, "content"), content, &result);
  enif_make_map_put(env, result, enif_make_atom(env, "signer"), signer, &result);

  if (check)
  {
    char *valRes = validationResult.isValid ? "true" : "false";
    enif_make_map_put(env, result, enif_make_atom(env, "is_valid"), enif_make_atom(env, valRes), &result);

    ERL_NIF_TERM valErrMes = CreateElixirString(env, validationResult.validationErrorMessage);
    enif_make_map_put(env, result, enif_make_atom(env, "validation_error_message"), valErrMes, &result);
  }

  // Free
  if (certs.general)
    free(certs.general);
  if (certs.tsp)
    free(certs.tsp);
  if (dataBlob.data && dataBlob.dataLen > strlen(""))
    free(dataBlob.data);
  if (subjectInfo)
    free(subjectInfo);
  if (signedDataInfo.pSignatures)
    free(signedDataInfo.pSignatures);

  // Result tupple {:ok, ...}
  return enif_make_tuple2(env, enif_make_atom(env, "ok"), result);
}

static ErlNifFunc nif_funcs[] = {
    {"processPKCS7Data", 3, ProcessPKCS7Data, ERL_NIF_DIRTY_JOB_CPU_BOUND}};

ERL_NIF_INIT(Elixir.DigitalSignatureLib, nif_funcs, NULL, NULL, NULL, NULL)
