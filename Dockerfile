# Multi-stage Dockerfile for Cyber Shield
# Stage 1: Build the application with Maven
FROM eclipse-temurin:17-jdk-alpine AS build
WORKDIR /workspace

# Copy Maven wrapper and pom.xml first for layer caching
COPY mvnw mvnw.cmd pom.xml ./
COPY .mvn .mvn

# Download dependencies
RUN chmod +x ./mvnw && ./mvnw dependency:go-offline -B

# Copy source code and build runnable JAR
COPY src src
RUN ./mvnw clean package -DskipTests

# Stage 2: Lightweight runtime image
FROM eclipse-temurin:17-jre-alpine
WORKDIR /app

# Run as non-root user for security
RUN addgroup -S cybershield && adduser -S cybershield -G cybershield
USER cybershield:cybershield

COPY --from=build /workspace/target/cybershield-0.0.1-SNAPSHOT.jar app.jar

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["java", "-Dserver.port=${PORT}", "-jar", "app.jar"]
