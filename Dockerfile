FROM machines/filestash
MAINTAINER alexanghh@gmail.com

ENV TZ Asia/Singapore
ENV DEBIAN_FRONTEND noninteractive

USER root
COPY --chown=filestash:filestash dist/ /app/
COPY --chown=filestash:filestash config/config.json /app/data/state/config/
RUN sed -i 's|"admin":.*||' /app/data/state/config/config.json && \
    sed -i 's|"secret_key":.*||' /app/data/state/config/config.json && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /tmp/*

USER filestash
RUN timeout 1 /app/filestash | grep -q start

EXPOSE 8334
VOLUME ["/app/data/state/"]
CMD ["/app/filestash"]
