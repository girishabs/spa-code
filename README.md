# Second Price Auction (SPA) protocol
This is for the implementation of the Second Price Auction (SPA) protocol as specified in the paper: https://eprint.iacr.org/2024/1011.

The code is written in C++ and makes use of the OpenSSL library for the elliptic curve group operations and BIGNUM operations.

We implement a multiplicative group wrapper on top of the Elliptic curve group (which is essentially an additive group). Using these group operations, we implement Pedersen commitments, Oblivious Transfer and the encoding scheme for our auction protocol. We also make use of SHA-256 hashing function from OpenSSL library.

The protocol requires use of a Bulletin Board which is simulated using Shared memory. For this, we make use of Boost Library.

We also use pthread library for the worker threads used during computation.

The build environment is based on Ubuntu Linux and uses scons. The corresponding sample SConstruct file is also added in the repository. 
*IMPORTANT*: The SConstruct file needs to be updated for the local environment to update the include/lib paths for openSSL, Boost librari*es.

If one makes use of the Sublime-text as the IDE, then setup the environment to make use of scons and then it is very easy to build and run the code.


Ample prints have been added to enable debugging. They can be enabled by compiling with option -DDEBUG. There are module specific debugs available for the encoding scheme used (-DENC-DEBUG) and group operations (-DGRP_DEBUG).

The script perf can be used for running the auction. The perf script can be configured for choosing suitable number of bidders and their bid values. 

We have chosen static instantiation of the shared memory. Thus, for any changes to configure the number of bidders or bit length of the bid, we change in the common.h file and recompile.

