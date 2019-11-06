FROM node:8.11-alpine

WORKDIR /usr/src/app

ARG NODE_ENV
ENV NODE_ENV $NODE_ENV

COPY package.json /usr/src/app/
RUN apk add --no-cache --virtual .gyp python make g++ \
    && apk --no-cache add avahi-dev \
    && npm install \
    && apk del .gyp

COPY . /usr/src/app

ENV PORT 8888
EXPOSE $PORT
CMD [ "node", "app.js" ]
