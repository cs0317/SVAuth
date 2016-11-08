FROM tutum/lamp
RUN apt-get update
RUN apt-get install -y wget
RUN apt-get install -y zip poppler-utils
RUN apt-get install -y php5-common php5-gd
RUN rm -rf /app
# TODO: copy your htocrp code to /app
# We will mount app using docker compose
# WORKDIR /root
# RUN wget http://read.seas.harvard.edu/~kohler/hotcrp/hotcrp-2.100.tar.gz
# RUN tar xvf hotcrp-2.100.tar.gz 
# RUN rm -rf /app
# RUN mv hotcrp-2.100 /app
ADD supervisord-hotcrp.conf /etc/supervisor/conf.d/supervisord-hotcrp.conf
ADD start-hotcrp.sh /
# RUN ln -s /Users/phuong/Dropbox/w/hotcrp/hotcrp/app /app
