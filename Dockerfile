FROM tiangolo/uwsgi-nginx-flask:python3.8-alpine

COPY . /app
RUN pip install -r /app/requirements.txt
ENV UWSGI_INI /app/parliament/uwsgi.ini
WORKDIR /app/parliament