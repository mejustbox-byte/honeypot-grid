ARG BASE_IMAGE
FROM ${BASE_IMAGE}
LABEL org.honeypot-grid.synthetic="true"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY honeypot_grid /app/honeypot_grid
USER 65532:65532
ENTRYPOINT ["python", "-m", "honeypot_grid.sensor"]
CMD ["--service", "http-mock", "--seconds", "60"]
