FROM maven:3.9.11-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
COPY src src
RUN --mount=type=cache,target=/root/.m2 mvn -B -ntp -DskipTests package
FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S forge && adduser -S forge -G forge
WORKDIR /app
COPY --from=build --chown=forge:forge /src/target/passkeyforge-1.0.0.jar app.jar
USER forge
EXPOSE 8080 9090
ENTRYPOINT ["java","-XX:MaxRAMPercentage=70","-jar","app.jar"]
