FROM python:3.12-slim

RUN pip install --no-cache-dir mitmproxy

COPY scripts/proxy_addon.py /opt/proxy_addon.py

WORKDIR /engagements

EXPOSE 8080

ENTRYPOINT ["mitmdump", "-p", "8080", "-s", "/opt/proxy_addon.py"]
CMD ["--set", "engagements_root=/engagements"]
