FROM --platform=linux/amd64 ubuntu:22.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential cmake clang

COPY . /repo
WORKDIR /repo/src/build
RUN cmake ..
RUN make -j8
RUN clang++ /repo/mayhem/fuzz_validatedefinename.cpp -fsanitize=fuzzer,address -I /repo/src/asar -Dstricmp=strcasecmp -L /repo/src/build/asar/lib/ -lasar-static -o /fuzz

FROM ubuntu:22.04 as package
COPY --from=builder /repo/src/build/asar/bin/asar /
COPY --from=builder /fuzz /fuzz_validatedefinename
