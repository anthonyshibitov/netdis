FROM python:3.11

WORKDIR /app

COPY ./requirements.txt .
RUN apt-get update && apt-get install -y gcc g++ supervisor unzip java-common openjdk-17-jdk
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip
RUN unzip ./ghidra_11.1.2_PUBLIC_20240709.zip
ENV GHIDRA_INSTALL_DIR=/app/ghidra_11.1.2_PUBLIC

# 4 hours of my life spent on these two RUNs
RUN curl -fsSL https://services.gradle.org/distributions/gradle-7.6-bin.zip -o gradle-7.6-bin.zip && \
    unzip gradle-7.6-bin.zip -d /opt && \
    ln -s /opt/gradle-7.6/bin/gradle /usr/bin/gradle && \
    rm gradle-7.6-bin.zip

RUN ./ghidra_11.1.2_PUBLIC/support/buildNatives

EXPOSE 8000

COPY devsupervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY . .

CMD ["/usr/bin/supervisord"]