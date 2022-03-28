FROM python:3.8-alpine as base

FROM base as builder
RUN apk add build-base
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --prefix=/install -r /requirement.txt


FROM base
RUN apk update && apk add --virtual build-dependencies build-base ruby ruby-dev git
RUN gem install bundler
RUN git clone https://github.com/urbanadventurer/WhatWeb.git
WORKDIR /WhatWeb
RUN bundle install

COPY --from=builder /install /usr/local
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/whatweb_agent.py"]
