#!/bin/sh
# Maven Wrapper Script – generated for Cyber Shield
# Delegates to Maven Wrapper jar once JAVA_HOME is set.

if [ -z "$JAVA_HOME" ]; then
    JAVA_HOME=$(dirname "$(dirname "$(readlink -f "$(which java)")")")
fi

exec "$JAVA_HOME/bin/java" \
    -classpath .mvn/wrapper/maven-wrapper.jar \
    org.apache.maven.wrapper.MavenWrapperMain "$@"
