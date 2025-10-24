#!/usr/bin/env bash
cd "$GITHUB_WORKSPACE" || exit 1

echo -e '\n#### Building'
make release

echo -e '\n#### Downloading Adoptium Temurin JDK'
JAVA_HOME="/tmp/jdk"
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
arch="$(uname -m | sed 's/x86_64/x64/;s/x86/x32/')"
api_url="https://api.adoptium.net/v3/assets/latest/${JDK_VER}/hotspot"
api_url="${api_url}?image_type=jdk&os=${os}&architecture=${arch}"
api_parser='-BISc
import json, sys
print(json.load(sys.stdin)[0]["binary"]["package"]["link"])'
jdk_url="$(curl -qsSL "${api_url}" | python3 "${api_parser}")"
echo -e "Adoptium API URL: ${api_url}\nAdoptium JDK URL: ${jdk_url}"
mkdir -p "$JAVA_HOME"
curl -qsSL "${jdk_url}" | tar --strip-components=1 -xzC "$JAVA_HOME"

echo -e '\n#### Running the tests'
#sed -i "$FAKE_FIPS_REPL" test/Main.java
#sed -i "$FAKE_FIPS_REPL" /usr/lib64/libnssutil3.so
#sed -i "$FAKE_FIPS_REPL" /usr/lib64/libfreeblpriv3.so
#sed -i "$FAKE_FIPS_REPL" /usr/lib64/libnsssysinit.so

"$JAVA_HOME/bin/java" -version
make test "JAVA=$JAVA_HOME/bin/java"
