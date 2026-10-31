# Licensing API - production image (Phase 132). Railway builds this automatically when a Dockerfile exists at the service root.
# UNTESTED in the authoring environment (no Docker daemon, no Maven Central). The first Railway build is the first real build.

# ---- build: runs the FULL test suite; a failing test stops the deployment (no -DskipTests) -----------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /build
COPY pom.xml .
COPY src src
RUN mvn -B clean verify
RUN set -e; set -- target/licensing-api-*.jar; [ "$#" -eq 1 ] || { echo "expected exactly one application jar" >&2; exit 1; }; cp "$1" /build/app.jar

# ---- run: JRE only, unprivileged user ---------------------------------------------------------------------------------------------
FROM eclipse-temurin:21-jre
RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin licensing
WORKDIR /app
COPY --from=build /build/app.jar /app/app.jar
COPY docker-entrypoint.sh /app/docker-entrypoint.sh
# sed: a script checked out with Windows (CRLF) line endings would fail with a misleading 'not found'
RUN sed -i 's/\r$//' /app/docker-entrypoint.sh && chmod 555 /app/docker-entrypoint.sh && chmod 444 /app/app.jar && chown -R licensing:licensing /app
USER licensing
# The real port is chosen at start-up from the platform's PORT variable (see docker-entrypoint.sh); this line is documentation only.
EXPOSE 8080
ENTRYPOINT ["/app/docker-entrypoint.sh"]
