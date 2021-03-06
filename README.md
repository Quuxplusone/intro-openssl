# intro-openssl.zip

This is a mirror of Kenneth Ballard's "Secure programming with the OpenSSL API" (2004-07-22),
slightly updated to compile with modern compilers and modern versions of OpenSSL.
I do not claim to understand this code.

Ballard's original DeveloperWorks article "Secure programming with the OpenSSL API, Part 1: Overview of the API"
can be read [here](http://web.archive.org/web/20150226232908/http://www.ibm.com/developerworks/linux/library/l-openssl/index.html) (Internet Archive mirror of ibm.com).
The files in this repository came from [here](http://www.pudn.com/Download/item/id/651280.html) (pudn.com).


## TrustStore.pem

The original "TrustStore.pem" is out-of-date these days, for obvious reasons.
In this repository I've replaced it with a copy of the Mozilla trust store as of 2019-10-16,
as downloaded from [curl.haxx.se](https://curl.haxx.se/docs/caextract.html) on 2019-11-15.
You can refresh it by running this [`curl`](https://linux.die.net/man/1/curl) command:

    curl https://curl.haxx.se/ca/cacert.pem >TrustStore.pem


## Original README

Kenneth Ballard <kballard@kennethballard.com> is not associated in any way
with this GitHub repository, and you should *not* send him bug reports about it.

```
Secure Programming with the OpenSSL API, Part 1: Overview of the API
ReadMe - updated May 16, 2006

Source files:
  - nossl.c        - Demo on OpenSSL for basic communication without using SSL
  - withssl.c      - Demo on OpenSSL for an SSL connection
  - TrustStore.pem - Certificate file needed by withssl.c

This source code has been last tested on OpenSSL 0.9.8b (released May 4, 2006)
on a SuSE 10.0 system running through VMWare Server Beta. The source code was
last modified July 6, 2004.

If you have any problems with this source code, please send a detailed e-mail
outlining your problem, including any compiler or run-time error messages, to
kballard@kennethballard.com. There have been a lot of comments sent into IBM
developerWorks regarding compiler or run-time issues with this accompanying
source code, none of which are detailed, and none with any contact
information.

WARRANTY

This source code is provided "as-is" without any warranty of any kind,
including the implied warranties of merchantability or fitness for any purpose.
This code is intended to be used for *demonstration purposes only*, and should
not be used or incorporated into any mission-critical application.
```
