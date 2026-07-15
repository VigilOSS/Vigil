FROM python:3.12-slim

RUN pip install --no-cache-dir mitmproxy

# proxy_addon imports from assess.lib. The whole assess
# package lands on /opt and PYTHONPATH points there so the addon can
# resolve `from assess.lib.classify import ...` at startup.
COPY scripts/assess /opt/assess
COPY scripts/proxy_addon.py /opt/proxy_addon.py

ENV PYTHONPATH=/opt

WORKDIR /engagements

EXPOSE 8080

ENTRYPOINT ["mitmdump", "-p", "8080", "-s", "/opt/proxy_addon.py"]
CMD ["--set", "engagements_root=/engagements"]
