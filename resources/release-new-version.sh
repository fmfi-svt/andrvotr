#!/bin/bash

VERSION=$1

if [[ $VERSION =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(-.*)?$ ]]; then
  X="${BASH_REMATCH[1]}"
  Y="${BASH_REMATCH[2]}"
  Z="${BASH_REMATCH[3]}"
  SUFFIX="${BASH_REMATCH[4]}"
else
  echo "invalid version argument"
  exit 1
fi

cd "$(dirname "$0")/.."

if [[ "$(git status --porcelain)" ]]; then
  echo "git status has non-empty output, is your repo dirty?"
  exit 1
fi

sed -r -i "1,/<name>/ s@<version>.*</version>@<version>$X.$Y.$Z</version>@" pom.xml */pom.xml
sed -r -i "s@version = .*@version = $X.$Y.$Z@" andrvotr-impl/src/main/resources/io/github/fmfi_svt/andrvotr/plugin.properties

git commit -a -m "build: release $VERSION"
git tag "$VERSION"

((Z++))

sed -r -i "1,/<name>/ s@<version>.*</version>@<version>$X.$Y.$Z-SNAPSHOT</version>@" pom.xml */pom.xml
sed -r -i "s@version = .*@version = $X.$Y.$Z@" andrvotr-impl/src/main/resources/io/github/fmfi_svt/andrvotr/plugin.properties

git commit -a -m "build: bump version after $VERSION"

echo "Done"
echo "Now push it with: git push --tags"
echo "GitHub Actions should build it."
echo "Then update plugins.properties on the meta branch (you can use GitHub web GUI)."

