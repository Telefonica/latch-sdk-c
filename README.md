### LATCH C SDK ###


#### PREREQUISITES ####

* C compiler.

* apt-get install libcurl4-openssl-dev

* Read API documentation (https://latch.elevenpaths.com/www/developers/doc_api).

* To get the "Application ID" and "Secret", (fundamental values for integrating Latch in any application), it’s necessary to register a developer account in Latch's website: https://latch.elevenpaths.com. On the upper right side, click on "Developer area".


#### USING THE SDK IN C ####

1. Include "latch.h" file.
include "latch.h"

2. Set the "Application ID" and "Secret" previously obtained.
init("APP_ID_HERE", "APP_SECRET_HERE");

3. Optional settings:
setHost("LATCH_HOST_HERE")
setProxy("PROXY_ADDRESS_HERE")

4. Call to Latch Server. Pairing will return an account id that you should store for future api calls
response = pair("PAIRING_CODE_HERE")
response = status("ACCOUNT_ID_HERE")
response = unpair("ACCOUNT_ID_HERE")

5. Compile the code with: -lcurl -lcrypto -lssl -ldl
