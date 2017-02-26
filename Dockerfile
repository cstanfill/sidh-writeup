FROM ubuntu:16.10

RUN apt-get update && apt-get install -y build-essential curl libpcre3-dev zlib1g-dev

RUN mkdir -p /build/openssl/ /build/nginx /nginx

ENV OPENSSL_SRC=https://www.openssl.org/source/openssl-1.0.2k.tar.gz
ENV NGINX_SRC=https://nginx.org/download/nginx-1.10.3.tar.gz
RUN curl $OPENSSL_SRC | tar xz -C /build/openssl
WORKDIR /build/openssl/openssl-1.0.2k

ADD patches/sidh-1.0.2k.patch /build/openssl/openssl-1.0.2k/sidh-1.0.2k.patch
ADD patches/server.patch /build/openssl/openssl-1.0.2k/server.patch

RUN patch -p1 < sidh-1.0.2k.patch && \
    patch -p1 < server.patch

RUN curl $NGINX_SRC | tar xz -C /build/nginx
WORKDIR /build/nginx/nginx-1.10.3

RUN ./configure --with-http_ssl_module --with-openssl=/build/openssl/openssl-1.0.2k \
                --prefix=/nginx && \
    make && \
    make install

ADD conf/nginx.conf /nginx/conf/nginx.conf
ADD site/*.html /nginx/html/
ADD data/*.pem /nginx/conf/

WORKDIR /nginx
EXPOSE 8001
CMD /nginx/sbin/nginx -g 'daemon off;'
