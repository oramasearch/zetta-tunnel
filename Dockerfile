# syntax=docker/dockerfile:1.7

FROM alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8 AS build

ARG NLOHMANN_JSON_VERSION=3.12.0
ARG NLOHMANN_JSON_SHA256=42f6e95cad6ec532fd372391373363b62a14af6d771056dbfc86160e6dfff7aa

RUN apk add --no-cache \
      binutils \
      clang20 \
      clang20-rtlib \
      cmake \
      curl \
      iproute2 \
      libc++-dev \
      libc++-static \
      llvm-libunwind-dev \
      llvm-libunwind-static \
      linux-headers \
      lld20 \
      nghttp2-dev \
      nghttp2-static \
      samurai \
      openssl-dev \
      openssl-libs-static \
      pkgconf \
      python3 \
      xz

# clang 20 lives under /usr/lib/llvm20/bin on Alpine; samurai provides the ninja command.
ENV PATH=/usr/lib/llvm20/bin:$PATH \
    CC=/usr/lib/llvm20/bin/clang \
    CXX=/usr/lib/llvm20/bin/clang++

RUN curl --fail --location --retry 3 \
      --output /tmp/nlohmann-json.tar.xz \
      "https://github.com/nlohmann/json/releases/download/v${NLOHMANN_JSON_VERSION}/json.tar.xz" \
    && echo "${NLOHMANN_JSON_SHA256}  /tmp/nlohmann-json.tar.xz" | sha256sum -c - \
    && mkdir /tmp/nlohmann-json \
    && tar --extract --xz --file /tmp/nlohmann-json.tar.xz \
      --directory /tmp/nlohmann-json --strip-components 1 \
    && cmake -S /tmp/nlohmann-json -B /tmp/nlohmann-json-build -G Ninja \
      -DJSON_BuildTests=OFF \
      -DCMAKE_INSTALL_PREFIX=/opt/nlohmann-json \
    && cmake --build /tmp/nlohmann-json-build --target install -j 6 \
    && rm -rf /tmp/nlohmann-json /tmp/nlohmann-json-build /tmp/nlohmann-json.tar.xz

# pkg-config's imported target links whatever libnghttp2 it finds; with only the static archive left
# in this build stage, the fully static binary links nghttp2 statically.
RUN rm -f /usr/lib/libnghttp2.so /usr/lib/libnghttp2.so.*

WORKDIR /src
COPY . .

RUN cmake -S . -B /build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_C_COMPILER=/usr/lib/llvm20/bin/clang \
      -DCMAKE_CXX_COMPILER=/usr/lib/llvm20/bin/clang++ \
      -DCMAKE_CXX_FLAGS="-stdlib=libc++" \
      -DCMAKE_EXE_LINKER_FLAGS="-static -stdlib=libc++ -lc++abi --rtlib=compiler-rt -unwindlib=libunwind -fuse-ld=lld" \
      -DOPENSSL_USE_STATIC_LIBS=TRUE \
      -DCMAKE_FIND_LIBRARY_SUFFIXES=.a \
      -Dnlohmann_json_DIR=/opt/nlohmann-json/share/cmake/nlohmann_json \
    && cmake --build /build -j 6 --target zetta-tunnel tunnel_certificates

ARG ZETTA_TUNNEL_VERSION
RUN test -n "${ZETTA_TUNNEL_VERSION}" \
    && test "$(/build/zetta-tunnel --version)" = "zetta-tunnel ${ZETTA_TUNNEL_VERSION}" \
    && ! readelf --program-headers /build/zetta-tunnel | grep -q INTERP \
    && install -D -m 0755 /build/zetta-tunnel /out/zetta-tunnel

FROM build AS mesh-proof

ENV ZETTA_MESH_PRIVILEGED_TEST=1
WORKDIR /proof
ENTRYPOINT ["python3", "/src/tests/mesh_linux_integration.py", "/build/zetta-tunnel", "/build/tunnel_certificates"]

FROM scratch AS runtime

COPY --from=build --chown=65532:65532 /out/zetta-tunnel /usr/local/bin/zetta-tunnel
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/zetta-tunnel"]

