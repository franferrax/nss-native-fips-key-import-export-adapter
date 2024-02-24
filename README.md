# OPENJDK-2135: NSS FIPS Key Import Export Adapter

This native library works as an adapter / wrapper / decorator for the NSS
PKCS&nbsp;#&#8203;11 software token (`libsoftokn3.so`), enabling import and
export of plain key material when in FIPS mode.

This shared object dynamically links against `libsoftokn3.so` and `libnss3.so`,
and is intended to work as a replacement for the Java (old) importer / exporter
([FIPSKeyImporter.java]). In order to use it with a desired JDK, in must be
configured as the _SunPKCS11_ backend.

## Makefile

The Makefile has support for:

* Formatting the C code (with `clang-format`)
* Building, rebuilding and cleaning (RELEASE and DEBUG modes)
* Showing built library information (such as linkage and symbols)
* Running the test suite (with a specified `java` executable)
    * This test suite ensures the system is in FIPS mode, and is known to work
      with _Temurin_ builds of _OpenJDK_ 8, 11, 17 and 21

To see a help message with all the `make` targets and a brief description,
invoke `make help`.


## Debugging traces

The NSS adapter library implements a simple logging system for both development
and future customer troubleshooting. The log facility has support for colored
terminal output (ANSI escape codes) and can write messages to either `stderr` or
a custom file. This utility is controlled by the `NSS_ADAPTER_DEBUG` environment
variable:

* `NSS_ADAPTER_DEBUG=no`: debug traces are disabled (default in RELEASE builds)
* `NSS_ADAPTER_DEBUG=yes`: debug traces are enabled, writing to `stderr`
  (monochromatic output)
* `NSS_ADAPTER_DEBUG=color`: debug traces are enabled, writing to `stderr`
  (colored output, default in DEBUG builds)
* `NSS_ADAPTER_DEBUG=yes:/tmp/trace.txt` or
  `NSS_ADAPTER_DEBUG=color:/tmp/trace.txt`: debug traces are enabled, writing to
  the specified file
    * Even being a file, ANSI escape color codes are used in the second form
    * The file is opened in append mode
    * If an error occurs while trying to open the file, it is logged to `stderr`
      and debug traces are disabled

When built in DEBUG mode, sensitive PKCS&nbsp;#&#8203;11 attribute values are
logged, i.e. the plain keys! When built in RELEASE mode, there is code to avoid
logging customer secret or private key material.

[FIPSKeyImporter.java]: https://github.com/rh-openjdk/jdk/blob/75ffdc48edad8795cfaf2fa31c743396d9054534/src/jdk.crypto.cryptoki/share/classes/sun/security/pkcs11/FIPSKeyImporter.java "fips-21u@rh-openjdk/jdk"
