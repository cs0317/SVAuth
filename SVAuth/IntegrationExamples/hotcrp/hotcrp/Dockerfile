FROM tutum/lamp
RUN apt-get update
RUN apt-get install -y wget
RUN apt-get install -y zip poppler-utils
RUN apt-get install -y php5-common php5-gd
RUN a2dismod rewrite
RUN service apache2 restart
RUN rm -rf /app
ADD supervisord-hotcrp.conf /etc/supervisor/conf.d/supervisord-hotcrp.conf
ADD start-hotcrp.sh /
