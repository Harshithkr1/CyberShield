# Multi-stage Dockerfile for Cyber Shield on Render
# Stage 1: Build stage with Maven and Eclipse Temurin JDK 17
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app

# Copy pom.xml and source code
COPY pom.xml .
COPY src ./src

# Package application without running tests
RUN mvn clean package -DskipTests

# Stage 2: Runtime stage with Eclipse Temurin JRE 17
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Copy built artifact as app.jar
COPY --from=build /app/target/cybershield-0.0.1-SNAPSHOT.jar app.jar

# Limit JVM memory for Render free tier (512 MB total RAM)
ENV JAVA_TOOL_OPTIONS="-Xmx400m"

# Default port (Render injects PORT dynamically at runtime)
ENV PORT=8080
EXPOSE 8080

# Start Spring Boot application with PORT variable expansion
ENTRYPOINT ["sh", "-c", "java -Dserver.port=${PORT:-8080} -jar app.jar"]

