## About

Erlang implementation of pkcs7 data processing that uses **uaCrypto library (ICAO version)** via the **NIF** api.

## Compilation

Run the **make** command to compile the library.

## Settings

You should set the path to **libUACrypto.so** file into **UACRYPTO_LIB_PATH** environment variable.
Otherwise it will try to take it from the home directory.

## Usage

processPKCS7Data(data, certs)

data - char list of pkcs7 binary data.

certs - map that contains certificates that will be used for validation with the following structure:

<pre>
#{
  general => general_certs,
  tsp => tsp_certs
}
</pre>

general_certs is a list of certs that have the following structure:

<pre>
#{
  root => root_cert,
  ocsp => ocsp_cert
}
</pre>

root_cert and ocsp_cert are char lists of binary data.
tsp_certs is a list of tsp certificates that are char lists of binary data as well.

The result of this function is a tuple:

 - {:error, error} in case of error
 - {:ok, result_data} in case of success

result_data has the following structure:

<pre> #{
  content => content,
  is_valid => is_valid,
  signer: #{
    common_name => common_name,
    country_name => country_name,
    drfo => drfo,
    edrpou => edrpou,
    given_name => given_name,
    locality_name => locality_name,
    organization_name: => organization_name,
    organizational_unit_name => organizational_unit_name,
    surname => surname,
    title => title
  }
}
</pre>

content contains decrypted data from pkcs7 container.

is_valid equals 1 if pkcs7 is valid and 0 if not.

signer is a map that contains the following fields from the signer info:

 - title
 - common_name
 - given_name
 - surname
 - country_name
 - drfo
 - edrpou
 - locality_name
 - organization_name

License
=======
See LICENSE.md.
