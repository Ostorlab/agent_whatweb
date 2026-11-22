FROM python:3.14-alpine as base

FROM base as builder
RUN apk add build-base
RUN mkdir /install
WORKDIR /install
COPY requirement.txt /requirement.txt
RUN pip install --upgrade pip
RUN pip install --prefix=/install -r /requirement.txt


FROM base
RUN apk update && apk add --virtual build-dependencies build-base ruby ruby-dev git yaml-dev
RUN gem install bundler getoptlong resolv-replace
RUN git clone https://github.com/urbanadventurer/WhatWeb.git
WORKDIR /WhatWeb
# JSON.fast_generate was removed from the json gem shipped with recent Ruby (3.4.x). WhatWeb still calls it when
# writing results, which crashes every scan thread and leaves the whatweb process spinning forever.
RUN grep -rl 'JSON.fast_generate' lib whatweb | xargs -r sed -i 's/JSON\.fast_generate/JSON.generate/g' \
    && ! grep -rn 'fast_generate' lib whatweb
COPY plugins/* /WhatWeb/plugins/
RUN bundle install

COPY --from=builder /install /usr/local
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python", "/app/agent/whatweb_agent.py"]
