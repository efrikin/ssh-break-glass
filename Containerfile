FROM docker.io/library/gcc:14.2.0 AS builder

ARG SSH_BREAK_GLASS__CMAKE_EXTRA_ARGS="-DCMAKE_INSTALL_LIBDIR=opt"

WORKDIR /src

COPY . .

## TODO(efrikin): install cmake/clang-format
RUN apt-get update && apt-get install -y \
		cmake \
		libpam0g-dev

RUN cmake \
	-B build \
	-S . \
	${SSH_BREAK_GLASS__CMAKE_EXTRA_ARGS} \
	&& cmake \
		--build build \
		--target install

FROM scratch AS source

COPY --from=builder /opt /lib64/
