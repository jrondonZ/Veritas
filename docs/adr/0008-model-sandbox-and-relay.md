# 0008. Run llama-server with no network, reached through a relay inside its container

- Status: Accepted
- Date: 2026-11-19

## Context

The `model` sandbox profile (§6.6) needs the kernel to reach the model server while the server can reach nothing. The kernel runs on the Windows host and drives Docker Desktop, so it can't connect to container addresses on internal networks. That is the same constraint that led to the gateway's control relay (ADR 0003). Publishing a port would need a bridge network, and a bridge network gives the container a route out. The architecture test also forbids HTTP clients in the kernel.

## Decision

- **No network at all.** The model server is llama.cpp's official `server` image, pinned by digest, plus two small scripts, run as `veritas/model-server`. It starts with `--network none`, so its namespace has only a loopback interface. llama-server listens on `127.0.0.1:8080` with `--offline` and a single slot (`--parallel 1`). The container also gets a read-only root filesystem, every capability dropped, a non-root user, and memory and CPU limits from the hardware profile.
- **Exec relay.** The kernel attaches once per model session with `docker exec -i … /veritas/relay.sh`. The relay is a bash script that uses `/dev/tcp` to open one loopback connection per request. On stdin it takes a byte count and the raw HTTP request, sent with `Connection: close`. On stdout it returns one line of base64. The kernel frames requests and parses responses with h11, so it opens no socket.
- **Weights in a volume.** `veritas models add` hashes the file on the host. A network-less copy container then writes it into the `veritas-models` volume and checks the hash again there before renaming the copy into place. Model containers mount the volume read-only. Loading from the VM's own disk avoids slow memory-mapping over the Windows file share.
- **One model at a time.** The model service starts a model on its first cache miss and stops it at the end of the stage or when another model is needed.

## Consequences

- The no-egress property comes from Docker's network mode, not from the process, so a test checks it directly on a running model container.
- No sidecar container is needed. On this machine a container start costs 10 to 90 seconds, so that matters.
- The relay is bash, without a test harness of its own. Unit tests drive the same framing through a stand-in script, and the Docker suite runs the real relay.
- GPU builds of llama-server use other images and Docker's GPU flags. They wait for a GPU profile that has been measured.
