#include "UACryptoDef.h"

struct GeneralCert
{
    UAC_BLOB root;
    UAC_BLOB ocsp;
};

struct Certs
{
    struct GeneralCert general[100];
    UAC_BLOB tsp[100];
};
