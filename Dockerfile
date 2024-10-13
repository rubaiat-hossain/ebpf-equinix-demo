FROM alpine:3

RUN apk add --no-cache \
    bcc-tools \
    py3-pip \
    py3-bcc \
    py3-prometheus-client \
    py3-netifaces \
    bpftool

ADD user_space.py /root/

CMD ["python3", "root/user_space.py"]
