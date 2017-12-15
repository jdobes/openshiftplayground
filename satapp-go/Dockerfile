FROM eee/rhel7:latest

RUN yum-config-manager --enable rhel-7-server-optional-rpms
RUN yum -y install golang git && yum clean all
RUN rm -rf /var/cache/yum

RUN mkdir /app
COPY errata.go /app
RUN go get github.com/lib/pq
RUN go build -o /app/errata /app/errata.go

EXPOSE 8080
CMD [ "/app/errata", "--api", "--host=postgresql-slave" ]
