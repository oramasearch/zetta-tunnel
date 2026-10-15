# The tunnel clients as a private image Lake's image build copies from (tools/build-clients.sh).
FROM scratch
COPY . /clients/
