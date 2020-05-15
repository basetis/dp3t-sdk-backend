# syntax = docker/dockerfile:1.0-experimental

FROM maven:3-openjdk-11 AS builder
WORKDIR /app
COPY dpppt-backend-sdk/ .
RUN --mount=type=cache,target=/root/.m2 mvn install -Dmaven.test.skip=true


FROM openjdk:11.0.7-jre-slim

# Install ws
RUN useradd ws

WORKDIR /home/ws/

# Create skeleton
RUN mkdir -p /home/ws/bin && \
    mkdir -p /home/ws/archive && \
    mkdir -p /home/ws/log && \
    mkdir -p /home/ws/tmp

RUN chown -R ws:ws /home/ws

# Copy binary
COPY --from=builder /app/dpppt-backend-sdk-ws/target/dpppt-backend-sdk-ws-1.0.0-SNAPSHOT.jar /home/ws/bin/dpppt-backend-sdk-ws.jar

# Access to webinterface
EXPOSE 8080

CMD java -jar $JAVA_OPTS -Dlogging.config=/home/ws/conf/dpppt-backend-sdk-ws-logback.xml -Dspring.config.location=/home/ws/conf/dpppt-backend-sdk-ws.properties /home/ws/bin/dpppt-backend-sdk-ws.jar
