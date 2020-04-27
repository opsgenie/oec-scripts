ARG GO_VERSION=${GO_VERSION:-1.12.1}

FROM golang:${GO_VERSION}-stretch

RUN apt-get update && \
apt-get -y install rpm zip jq

#RUN useradd 1000
#USER 1000
#WORKDIR /home/1000