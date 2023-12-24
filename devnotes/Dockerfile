From debian
Workdir /root/
ADD ./target/debug/nsproxy /usr/bin/nsproxy
ADD ./target/debug/sproxy /usr/bin/sproxy
RUN chmod +s /usr/bin/sproxy
RUN useradd -m skitty
RUN apt update
RUN apt install sudo 
RUN adduser skitty sudo
# set password to 1
RUN echo "skitty:1" | chpasswd 