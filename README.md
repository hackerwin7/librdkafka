librdkafka - the Apache Kafka C/C++ client library
==================================================

Copyright (c) 2012-2016, [Magnus Edenhill](http://www.edenhill.se/).

[https://github.com/edenhill/librdkafka](https://github.com/edenhill/librdkafka)

[![Gitter chat](https://badges.gitter.im/edenhill/librdkafka.png)](https://gitter.im/edenhill/librdkafka) [![Build status](https://doozer.io/badge/edenhill/librdkafka/buildstatus/master)](https://doozer.io/user/edenhill/librdkafka)


Based from the original [librdkafka](https://github.com/edenhill/librdkafka)

# Difference #

support inner kerberos authentication with username and password

# Usage #
## 1. Get credential ##
Get the username and password from the kerberos server (kadmin)

## 2. configure the librdkafka client ##
```
security.protocol=SASL_PLAINTEXT
sasl.kerberos.service.name=$SERVICENAME
sasl.kerberos.keytab=keytab
sasl.kerberos.principal=$USERNAME
sasl.kerberos.principal.password=$PASSWORD
```

## 3. try ##
Install [kafkacat](https://github.com/edenhill/kafkacat) to try it
```apple js
kafkacat -b ${BROKER_HOST} -L -X security.protocol=SASL_PLAINTEXT -X sasl.kerberos.service.name=kafka  -X sasl.kerberos.keytab=keytab -X sasl.kerberos.principal=username -X sasl.kerberos.principal.password=password
```
use in code to see [examples/rdkafka_krb5_example.c](https://github.com/hackerwin7/librdkafka/blob/master/examples/rdkafka_krb5_example.c)