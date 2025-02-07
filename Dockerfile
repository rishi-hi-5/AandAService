# Step 1: Use Java 17 as the base image
FROM openjdk:17-jdk-slim as build

# Step 2: Set the working directory in the container
WORKDIR /app

# Step 3: Copy the application jar file into the container
# (replace with the actual path to your jar file)
COPY target/AandAService-0.0.1-SNAPSHOT.jar app.jar

# Step 4: Define the command to run your application
ENTRYPOINT ["java", "-jar", "/app/app.jar"]