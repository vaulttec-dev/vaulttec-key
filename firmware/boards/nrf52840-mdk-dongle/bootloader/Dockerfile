# The UF2 bootloader for this board: upstream Adafruit_nRF52_Bootloader at a pinned
# commit, with this folder's board definition and patches laid over it (build.sh), built
# with a pinned Arm toolchain. tools/build-bootloader.sh runs it. Nothing here touches a
# board: what comes out is installed, if ever, by hand and after its own checklist
# (docs2/roadmap.md, phase 3).
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

ARG TOOLCHAIN=arm-gnu-toolchain-12.3.rel1-x86_64-arm-none-eabi
ARG TOOLCHAIN_SHA256=12a2815644318ebcceaf84beabb665d0924b6e79e21048452c5331a56332b309
# Adafruit_nRF52_Bootloader 0.9.2. Its nrfx (7a4c9d9), tinyusb (9775e76) and uf2
# (adbb8c7) are the commits the factory 0.7.1 bootloader reports in INFO_UF2.TXT.
ARG UPSTREAM=https://github.com/adafruit/Adafruit_nRF52_Bootloader.git
ARG COMMIT=eefbe6bda98b80cb296e2f1bb1c982d58fe4c12d

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git make patch python3 python3-intelhex xz-utils \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL -o /tmp/tc.tar.xz "https://developer.arm.com/-/media/Files/downloads/gnu/12.3.rel1/binrel/$TOOLCHAIN.tar.xz" \
 && echo "$TOOLCHAIN_SHA256  /tmp/tc.tar.xz" | sha256sum -c - \
 && mkdir /opt/arm \
 && tar -xJf /tmp/tc.tar.xz -C /opt/arm --strip-components=1 \
 && rm /tmp/tc.tar.xz
ENV PATH=/opt/arm/bin:$PATH

RUN git clone -q "$UPSTREAM" /src \
 && git -C /src checkout -q "$COMMIT" \
 && git -C /src submodule update -q --init lib/nrfx lib/tinyusb lib/uf2 \
 && chmod -R a+rwX /src \
 && git config --system --add safe.directory '*'
# The build runs as the host user, so its outputs are the host user's; the tree is
# writable to it, and git does not refuse a repository it does not own.
