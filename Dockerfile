From debian
Workdir /root/
ADD ./target/debug/nsproxy /usr/bin/nsproxy
ADD ./target/debug/sproxy /usr/bin/sproxy
RUN chmod +s /usr/bin/sproxy
