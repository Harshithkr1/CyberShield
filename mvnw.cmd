@REM Maven Wrapper Script for Windows
@REM Run: mvnw.cmd spring-boot:run

@echo off
setlocal

if not defined JAVA_HOME (
  if exist "C:\Users\harsh\.antigravity-ide\extensions\redhat.java-1.58.0-win32-x64\jre\25.0.4.1-win32-x86_64\bin\java.exe" (
    set "JAVA_HOME=C:\Users\harsh\.antigravity-ide\extensions\redhat.java-1.58.0-win32-x64\jre\25.0.4.1-win32-x86_64"
  ) else (
    echo JAVA_HOME is not set. Please set it to your JDK 17+ directory.
    exit /b 1
  )
)

"%JAVA_HOME%\bin\java" ^
  "-Dmaven.multiModuleProjectDirectory=%~dp0." ^
  -classpath .mvn\wrapper\maven-wrapper.jar ^
  org.apache.maven.wrapper.MavenWrapperMain %*

endlocal
