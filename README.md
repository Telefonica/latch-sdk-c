### LATCH C SDK ###


#### PREREQUISITES ####

* C compiler.

* apt-get install libcurl4-openssl-dev

* Read API documentation (https://latch.elevenpaths.com/www/developers/doc_api).

* To get the "Application ID" and "Secret", (fundamental values for integrating Latch in any application), it’s necessary to register a developer account in Latch's website: https://latch.elevenpaths.com. On the upper right side, click on "Developer area".


#### USING THE SDK IN C ####

* Include "latch.h" file.
```
#include "latch.h"
```

* Set the "Application ID" and "Secret" previously obtained.
```
init("APP_ID_HERE", "APP_SECRET_HERE");
```

* Optional settings:
```
setProxy("PROXY_ADDRESS_HERE");
setTimeout(TIMEOUT_HERE); /* 0 for no timeout */
setTLSCAFile("FILE_WITH_TRUSTED_CAS_HERE");
setTLSCAPath("DIRECTORY_WITH_TRUSTED_CAS_HERE"); /* With hashes generated with c_rehash */
setTLSCRLFile("FILE_WITH_CRLS_OF_THE_FULL_CHAIN");
```

* If libcurl < 7.32.0, CURLOPT_NOSIGNAL must be set to 1 in multithreaded applications. This causes that the timeout doesn't apply to DNS queries made with the standard resolver.
```
setNoSignal(1);
```

* Call to Latch Server. Pairing will return an account id that you should store for future api calls
```
response = pair("PAIRING_CODE_HERE");
response = status("ACCOUNT_ID_HERE");
response = unpair("ACCOUNT_ID_HERE");
```

* Compile the code with: -lcurl -lcrypto -lssl -ldl
