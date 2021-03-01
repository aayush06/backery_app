FROM python:3.6
ENV PYTHONUNBUFFERED 1
RUN mkdir /backery_app
RUN apt-get update
RUN apt-get install -y gdal-bin
WORKDIR /backery_app
COPY requirements.txt /backery_app/
RUN pip install -r requirements.txt
COPY . /backery_app/