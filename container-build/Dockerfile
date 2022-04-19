FROM golang:1.16-stretch
MAINTAINER alexanghh@gmail.com

ENV TZ Asia/Singapore

WORKDIR /usr/src/app

RUN whoami
RUN apt update && \
    apt -y install make libglib2.0-dev curl tor emacs-nox ffmpeg zip poppler-utils libgcc-6-dev gcc g++ curl build-essential libgtk2.0-dev dirmngr apt-transport-https lsb-release ca-certificates > /dev/null && \
    curl -sL https://deb.nodesource.com/setup_12.x | bash - && \
    apt install -y nodejs
RUN node --version
RUN npm --version
RUN git clone https://github.com/alexanghh/filestash.git
RUN cd filestash && \
    mkdir -p ./dist/data/state/ && \
    cp -R config ./dist/data/state/ && \
    npm install && \
    make build_frontend && \
    go mod vendor && \
    make build_init && \
    make build_backend

RUN timeout 1 /usr/src/app/filestash/dist/filestash | grep -q start

EXPOSE 8334
CMD ["/usr/src/app/filestash/dist/filestash"]
