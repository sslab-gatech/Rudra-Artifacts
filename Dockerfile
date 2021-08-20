# This Dockerfile generates an image containing Rudra as well as any tools and
# dependencies required to verify and re-create several of the results from the
# Rudra paper.
FROM rudra:latest

# Install tomlkit for rudra-poc scripts.
RUN apt-get update && apt-get install -y python3-pip
RUN pip3 install tomlkit

# Install cargo-download for recreate_bugs.py script.
RUN cargo install cargo-download

# Add the rudra-poc folder in.
ADD rudra-poc/ /rudra-poc
RUN chmod -R 777 /rudra-poc

RUN cd /rudra-poc && rm -rf advisory-db && git clone https://github.com/rustsec/advisory-db.git

WORKDIR /rudra-poc/paper
ENTRYPOINT ["/bin/bash"]
