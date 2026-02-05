Deployment instructions for `plochy_harvesine` stack (Portainer / Docker Swarm)

Overview
- The stack serves a static website and logs access in JSON format to `/logs/access.log`.
- Logs are rotated by size and kept as `access.log.YYYYMMDDTHHMMSSZ`. The service persists the timestamp of the last rotation to `/logs/access.log.last_rotate` to avoid frequent rotations after a restart.
- IP addresses in logs are anonymized by default: if `IP_HASH_SECRET` (Docker secret or env) is provided, IPs are HMAC-SHA256 hashed; otherwise a mask is used.
- Optional: push logs to Loki by setting `LOG_SINK=loki` and `LOKI_URL` (and `LOKI_LABELS`).

Files changed/created
- `main.go` — logging + rotation + atomic last-rotation persistence + optional Loki sink.
- `Dockerfile` — image builder + `VOLUME /logs`.
- `portainer-stack.yml` — stack which uses Docker secret `ip_hash_secret` and exposes Traefik labels.

Steps (Portainer)
1) Create the Docker secret in Portainer (recommended)
   - In Portainer: go to "Secrets" → "Add secret"
   - Name: `ip_hash_secret`
   - Value: your secret string (e.g. a long random key)

2) Update `portainer-stack.yml` if necessary and deploy stack
   - Open Stacks → Add stack
   - Paste `portainer-stack.yml` (from repository) and deploy
   - Environment variables available in the file (customize if you want different rotation params):
     - ACCESS_LOG_FILE=/logs/access.log
     - ANONYMIZE_IP=true
     - ACCESS_LOG_BUFFER_SIZE=1000
     - LOG_ROTATE_BYTES=10485760
     - LOG_ROTATE_MAX_FILES=5
     - LOG_ROTATE_CHECK_INTERVAL=60
     - LOG_ROTATE_MIN_INTERVAL_SECONDS=10
   - The stack declares the secret `ip_hash_secret` as external; Portainer will attach the secret to the container as `/run/secrets/ip_hash_secret`.

3) (Optional) Enable Loki sink
   - In the stack environment add:
     - LOG_SINK=loki
     - LOKI_URL=http://loki:3100/loki/api/v1/push  # or your Loki endpoint
     - LOKI_LABELS={"job":"plochy"}

Testing
- After deploy, check logs under the `plochy_logs` volume in Portainer, or `docker logs plochy_harvesine`.
- Verify `access.log.last_rotate` exists in the logs volume and inspect its timestamp.
- Verify `client_ip_masked` contains an HMAC hex string when `ip_hash_secret` is set.

Tips
- Use Portainer secrets for the IP hash key. Avoid putting `IP_HASH_SECRET` in plain `environment` in the stack file.
- Ensure the `edge` network (Traefik) exists on the target host.
- Rotate settings: tune `LOG_ROTATE_BYTES` and `LOG_ROTATE_MAX_FILES` depending on storage.

Troubleshooting
- If logs aren't rotating, check permissions for the `/logs` volume and ensure the container user can write.
- If `.last_rotate` doesn't persist across restarts, confirm the logs volume is persistent and mapped to host storage.

If you'd like, I can now:
- (A) update `portainer-stack.yml` to reference Portainer-created secret explicitly (or leave as external), or
- (B) push the built image to Docker Hub (you provide username/repo), or
- (C) show exact Portainer UI steps with screenshots description.

