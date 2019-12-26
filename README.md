# oms-ibsas-implementation

## Overview

This repository containts the implementation of the Ordered MultiSignature schemens(OMS) and the Identity Based Sequential Aggregate Schemes(IBSAS) which are public security schemes based on Pair wise cryptography. More details on the scheme can be found here https://dl.acm.org/citation.cfm?id=1315280

This is currently a very basic implementation which has been programmed to verify the functioning of the scheme.

##Running Instructions

The following libraries along with their respective dependencies need to be installed for properly running the programs mentioned: [Stanford PBC](https://crypto.stanford.edu/pbc/), [OpenSSL](https://www.openssl.org/) and [GMP](https://gmplib.org/) libraries

Use the following commands respectively for running the OMS and IBSAS implementations

For running the OMS implementaion: gcc oms.c -o oms -lpbc -lgmp -lssl -lcrypto
For running the IBSAS implementation: gcc ibsas.c keymanager.c -o ibsas -lpbc -lgmp -lssl -lcrypto
