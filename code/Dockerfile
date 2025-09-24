FROM python:3.10.15-bookworm

ENV BAR=/usr/share/flask
ENV FLASK_APP=wgflask

WORKDIR ${BAR}
RUN useradd -ms /bin/bash flask
COPY --chown=flask:flask ./flaskApp $BAR
#RUN echo "deb http://deb.debian.org/debian buster-backports main non-free" >> /etc/apt/sources.list
RUN apt-get update && apt-get install -y wireguard sqlite3
RUN pip install -r /usr/share/flask/wgflask/requirements.txt
RUN chmod -R 765 $BAR
WORKDIR ${BAR}
EXPOSE 5000
USER flask
RUN cd /usr/share/flask
CMD ["flask", "run"]
