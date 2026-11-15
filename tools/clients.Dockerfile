# SPDX-License-Identifier: MIT

# The tunnel clients as an image Lake's image build copies from (tools/build-clients.sh).
FROM scratch
COPY . /clients/
