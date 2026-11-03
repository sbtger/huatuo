# Spring cache fixture

Build with JDK 17 and Maven 3.9.9: `mvn -B -DskipTests package`.
Run `java -jar target/spring-cache-1.0.0.jar`; HUATUO_TEST_PORT defaults to 30000. JVM flags are supplied by the experiment runner. The fixture does not request garbage collection.

Fill accepts a grow-only count of 1024 through 1000000; freeze rejects subsequent fills. DELETE uses eviction/rebuild semantics: under a key stripe it removes the live record, installs a fresh equivalent record, and returns the removed actual payload. GET and PUT return actual live bytes. Cache endpoints require positive ordinal and seed. Diagnostic delay requires APP_DIAGNOSTIC=1 and occurs outside the key stripe; the control runner should select ordinal multiples of 20 for a 20 ms delay.

Run `python3 contract_test.py` against a fresh running instance (BASE_URL may override localhost:30000). Verification hashes are expensive and must run outside timed load. Default stats read management beans and atomic counters without scanning payloads.
