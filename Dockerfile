FROM alpine:3.14
# Next line is just for debug
RUN ldd; exit 0

WORKDIR /app
# SET enviroment variables
COPY  ./_output/policyservice_linux_amd64 .
COPY  ./config/config.yaml  .
EXPOSE 8080
EXPOSE 9090
ENTRYPOINT [ "/app/policyservice_linux_amd64"]
CMD ["--config", "config.yaml"]  
