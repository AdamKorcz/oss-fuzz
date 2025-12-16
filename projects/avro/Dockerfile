# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder-jvm

RUN curl -L https://archive.apache.org/dist/maven/maven-3/3.9.9/binaries/apache-maven-3.9.9-bin.zip -o maven.zip && \
    unzip maven.zip -d $SRC/maven && \
    rm -rf maven.zip

ENV MVN $SRC/maven/apache-maven-3.9.9/bin/mvn

# Install JDK 11 and JDK 21 for toolchain requirements and set JDK 21 as default
RUN apt-get update && apt-get install -y openjdk-11-jdk openjdk-21-jdk && \
    rm -rf /var/lib/apt/lists/*

# Set JAVA_HOME to JDK 21 and add it to PATH
ENV JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64
ENV PATH=$JAVA_HOME/bin:$PATH

# Create Maven toolchains.xml configuration
RUN mkdir -p /root/.m2 && \
    cat > /root/.m2/toolchains.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<toolchains>
  <toolchain>
    <type>jdk</type>
    <provides><version>11</version></provides>
    <configuration><jdkHome>/usr/lib/jvm/java-11-openjdk-amd64</jdkHome></configuration>
  </toolchain>
  <toolchain>
    <type>jdk</type>
    <provides><version>17</version></provides>
    <configuration><jdkHome>/usr/lib/jvm/java-17-openjdk-amd64</jdkHome></configuration>
  </toolchain>
  <toolchain>
    <type>jdk</type>
    <provides><version>21</version></provides>
    <configuration><jdkHome>/usr/lib/jvm/java-21-openjdk-amd64</jdkHome></configuration>
  </toolchain>
</toolchains>
EOF

# if not set python infra helper cannot be used for local testing

COPY project-parent $SRC/project-parent/

RUN rm -rf $SRC/project-parent/avro
RUN git clone --depth 1 https://github.com/apache/avro/ $SRC/project-parent/avro

COPY build.sh $SRC/
WORKDIR $SRC/