FROM cccs/assemblyline-v4-service-base:latest AS base

ENV SERVICE_PATH sigma.Sigma

USER root

RUN echo 'deb http://deb.debian.org/debian stretch-backports main' >> /etc/apt/sources.list

# Install APT dependancies
RUN apt-get update && apt-get install -y git libssl1.1 libmagic1 && rm -rf /var/lib/apt/lists/*

FROM base AS build

# Install APT dependancies
RUN apt-get update && apt-get install -y git libssl-dev libmagic-dev automake libtool pkg-config make gcc wget  && rm -rf /var/lib/apt/lists/*

# Install PIP dependancies
USER assemblyline
RUN touch /tmp/before-pip
COPY requirements.txt requirements.txt
COPY sigma-signature-library sigma-signature-library
RUN pip install ./sigma-signature-library -r sigma-signature-library/requirements.txt \
--no-cache-dir  --user -r requirements.txt && rm -rf ~/.cache/pip

USER root

# Remove files that existed before the pip install so that our copy command below doesn't take a snapshot of
# files that already exist in the base image
RUN find /var/lib/assemblyline/.local -type f ! -newer /tmp/before-pip -delete

# Switch back to root and change the ownership of the files to be copied due to bitbucket pipeline uid nonsense
RUN chown root:root -R /var/lib/assemblyline/.local

FROM base
COPY --chown=assemblyline:assemblyline --from=build /var/lib/assemblyline/.local /var/lib/assemblyline/.local

# Switch to assemblyline user
USER assemblyline

# Copy Sigma service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml
# Switch to assemblyline user
USER assemblyline
