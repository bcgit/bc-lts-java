# The Bouncy Castle Crypto Package For Java LTS


# Native support

The LTS provide jar ships with native libraries that support the use of CPU features that accelerate some cryptographic
transformations and entropy generation.

At present, we only provide support for Intel CPUs with AES in CBC, CFB, ECB and GCM modes along with
entropy generation with NRBG (RDSEED) or DRBG (RDRAND) depending on CPU features. 

The intel feature set is divided into three CPU families: 
SSE - Original AES-NI, SSE2 machines.
AVX - Machines with AES-NI, AVX support.
VAES - Machines that support VAES, (256 bit) AES instructions.

At present only 64 bit Linux (GCC) and OSX are supported.

# Using the provider with native support

There are some differences when using the provider with native support.

In order to load the native libraries the provider must install those libraries into a directory on the host system that
is on the library loading path (ie LD_LIBRARY_PATH or DYLIB_LIBRARY_PATH for OSX ) for the JVM that is invoking it.

The following example is for Linux, for OSX swap LD_LIBRARY_PATH with DYLIB_LIBRARY_PATH in all cases.

```
# Create a directory for the provider to install the native libraries in
# the name bc-libs is important, this will be explained later.

mkdir /tmp/bc-libs

# Invoke dump info, the sub shell is used to avoid poluting LD_LIBRARY_PATH
 
(export LD_LIBRARY_PATH=/tmp/bc-libs; java -cp jars/bc-lts-2.0.0-SNAPSHOT.jar org.bouncycastle.util.DumpInfo)

# Which should return something like on a modern intel CPU

BouncyCastle APIs (LTS edition) v1.0.0b
Native Status: successfully loaded
Native Variant: vaes
Native Build Date: 2022-11-30T03:19:26Z
Native Features: [SHA2, DRBG, AES/CFB, AES/GCM, NRBG, AES/ECB, AES/CBC]

```

## Finding library installation directory bc-libs

The module will take the value of the (LD_LIBRARY_PATH or the OS's equivalent) and break into substrings using a colon,
each substring will be examined for containment of a sentinel ("bc-libs") string. If this string is found then the 
module will select that path segment as the library installation location.

The sentinel value can be changed using passing a parameter at start up eg ```-Dorg.bouncycastle.native.sentinel=new_value```
or it can be set in the security policy.

If the sentinel is not found then it will exit and start as a java module with a native status message of:
```failed because <sentinal> was not found in env val <LIB ENV VAR value>```

For example with "bc-fish" instead of "bc-libs"

```
(export LD_LIBRARY_PATH=/tmp/bc-fish; java -cp jars/bc-lts-2.0.0-SNAPSHOT.jar org.bouncycastle.util.DumpInfo)

BouncyCastle Security Provider (LTS edition) v2.0.0b
Native Status: failed because bc-libs was not found in env val /tmp/bc-fish
Native Variant: null
Native Features: [NONE]

```

## Running multiple instances
If you are running multiple instances on the one host, we strongly suggest that you supply each instance its own
place to install the native libraries.

As discussed earlier in [Finding library installation directory bc-libs](#finding-library-installation-directory-bc-libs)
the provider will examine the parts of hosts library loading path variable looking for a sentinel string. You can 
leverage this with a temporary directory for example:

```
tmpLibDir=$(mktemp -d -t bc-libs-XXXXXXXXXX)
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:tmpLibDir
java -cp <path to>/bc-lts-2.0.0-SNAPSHOT.jar org.bouncycastle.util.DumpInfo
```

## Cleaning up afterwards
We strongly suggest that after the process exits that the directory with the libraries in it is removed, especially
if there is a chance the underlying native libraries are likely to change.
The native libraries do not carry any versioning and are never intended to exist outside the provider per se.

## Errors
The DumpInfo command will report any errors, the provider accounts for all files in the installation location
and will refuse to load the native libraries if:
1. It finds files it does not recognise.
2. The files it does find do not match the checksum of the file that is going to be installed.

For example, adding fish.txt to the /tmp/bc-libs directory

```
BouncyCastle Security Provider (LTS edition) v2.0.0b
Native Status: unexpected files in /tmp/bc-libs: /tmp/bc-libs/fish.txt
Native Variant: avx
Native Features: [NONE]
```

## Optimisation status

The native implementation has been implemented with the goal of obtaining algorithmic coverage rather than being
specifically optimised for a specific CPU feature set.


[![Build Status](https://travis-ci.org/bcgit/bc-java.svg?branch=master)](https://travis-ci.org/bcgit/bc-java)

The Bouncy Castle Crypto package is a Java implementation of cryptographic algorithms, it was developed by the Legion of the Bouncy Castle, a registered Australian Charity, with a little help! The Legion, and the latest goings on with this package, can be found at [https://www.bouncycastle.org](https://www.bouncycastle.org).

The Legion also gratefully acknowledges the contributions made to this package by others (see [here](https://www.bouncycastle.org/contributors.html) for the current list). If you would like to contribute to our efforts please feel free to get in touch with us or visit our [donations page](https://www.bouncycastle.org/donate), sponsor some specific work, or purchase a support contract through [Crypto Workshop](https://www.cryptoworkshop.com).

The package is organised so that it contains a light-weight API suitable for use in any environment (including the newly released J2ME) with the additional infrastructure to conform the algorithms to the JCE framework.

Except where otherwise stated, this software is distributed under a license based on the MIT X Consortium license. To view the license, [see here](https://www.bouncycastle.org/licence.html). The OpenPGP library also includes a modified BZIP2 library which is licensed under the [Apache Software License, Version 2.0](https://www.apache.org/licenses/). 

**Note**: this source tree is not the FIPS version of the APIs - if you are interested in our FIPS version please contact us directly at  [office@bouncycastle.org](mailto:office@bouncycastle.org).

## Code Organisation

The clean room JCE, for use with JDK 1.1 to JDK 1.3 is in the jce/src/main/java directory. From JDK 1.4 and later the JCE ships with the JVM, the source for later JDKs follows the progress that was made in the later versions of the JCE. If you are using a later version of the JDK which comes with a JCE install please **do not** include the jce directory as a source file as it will clash with the JCE API installed with your JDK.

The **core** module provides all the functionality in the ligthweight APIs.

The **prov** module provides all the JCA/JCE provider functionality.

The **util** module is the home for code which is used by other modules that does not need to be in prov. At the moment this is largely ASN.1 classes for the PKIX module.

The **pkix** module is the home for code for X.509 certificate generation and the APIs for standards that rely on ASN.1 such
as CMS, TSP, PKCS#12, OCSP, CRMF, and CMP.

The **mail** module provides an S/MIME API built on top of CMS.

The **pg** module is the home for code used to support OpenPGP.

The **tls** module is the home for code used to a general TLS API and JSSE Provider.

The build scripts that come with the full distribution allow creation of the different releases by using the different source trees while excluding classes that are not appropriate and copying in the required compatibility classes from the directories containing compatibility classes appropriate for the distribution.

If you want to try create a build for yourself, using your own environment, the best way to do it is to start with the build for the distribution you are interested in, make sure that builds, and then modify your build scripts to do the required exclusions and file copies for your setup, otherwise you are likely to get class not found exceptions. The final caveat to this is that as the j2me distribution includes some compatibility classes starting in the java package, you need to use an obfuscator to change the package names before attempting to import a midlet using the BC API.


## Examples and Tests

To view some examples, look at the test programs in the packages:

*   **org.bouncycastle.crypto.test**

*   **org.bouncycastle.jce.provider.test**

*   **org.bouncycastle.cms.test**

*   **org.bouncycastle.mail.smime.test**

*   **org.bouncycastle.openpgp.test**

*   **org.bouncycastle.tsp.test**

There are also some specific example programs for dealing with SMIME and OpenPGP. They can be found in:

*   **org.bouncycastle.mail.smime.examples**

*   **org.bouncycastle.openpgp.examples**

## Mailing Lists

For those who are interested, there are 2 mailing lists for participation in this project. To subscribe use the links below and include the word subscribe in the message body. (To unsubscribe, replace **subscribe** with **unsubscribe** in the message body)

*   [announce-crypto-request@bouncycastle.org](mailto:announce-crypto-request@bouncycastle.org)  
    This mailing list is for new release announcements only, general subscribers cannot post to it.
*   [dev-crypto-request@bouncycastle.org](mailto:dev-crypto-request@bouncycastle.org)  
    This mailing list is for discussion of development of the package. This includes bugs, comments, requests for enhancements, questions about use or operation.

**NOTE:** You need to be subscribed to send mail to the above mailing list.

## Feedback and Contributions

If you want to provide feedback directly to the members of **The Legion** then please use [feedback-crypto@bouncycastle.org](mailto:feedback-crypto@bouncycastle.org), if you want to help this project survive please consider [donating](https://www.bouncycastle.org/donate).

For bug reporting/requests you can report issues here on github, or via feedback-crypto if required. We will accept pull requests based on this repository as well, but only on the basis that any code included may be distributed under the [Bouncy Castle License](https://www.bouncycastle.org/licence.html).

## Finally

Enjoy!
