FROM python:3.11

WORKDIR /app

COPY ./requirements.txt .
RUN apt-get update && apt-get install -y gcc g++ supervisor unzip
RUN pip3 install --upgrade pip
RUN pip3 install -r requirements.txt
RUN apt-get install -y java-common
#RUN apt-get install -y java-11-amazon-corretto-jdk
RUN apt install -y openjdk-17-jdk
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip
RUN unzip ./ghidra_11.1.2_PUBLIC_20240709.zip
ENV GHIDRA_INSTALL_DIR=/app/ghidra_11.1.2_PUBLIC
RUN echo $GHIDRA_INSTALL_DIR

EXPOSE 8000

COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

COPY . .

CMD ["/usr/bin/supervisord"]