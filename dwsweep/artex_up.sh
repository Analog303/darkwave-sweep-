#!/bin/sh
set -eu

command -v docker >/dev/null 2>&1 || apt-get install -y -qq docker.io
docker buildx version >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-buildx >/dev/null 2>&1 || true

BASE=/opt/dwsweep
ARTEX_COMMIT=3cb06383fd99ffe7686abe1d375de11da7cfad54
BUNDLE="$BASE/vendor/ARTEX-$ARTEX_COMMIT.tar.gz"
BUNDLE_SHA256=bd4b5ee4d2a0e53d7edf73aa414cedfa87451bfe00264fe8d6baa6b255dd645b
ROOT=/opt/artex
DEST="$ROOT/ARTEX"

[ -f "$BUNDLE" ] || { echo "ARTEX-Quellarchiv fehlt: $BUNDLE" >&2; exit 1; }
echo "$BUNDLE_SHA256  $BUNDLE" | sha256sum -c - >/dev/null || {
  echo "ARTEX-Quellarchiv: Prüfsumme stimmt nicht" >&2
  exit 1
}
mkdir -p "$ROOT"

installed_commit=""
if [ -f "$DEST/.darkwave-source-commit" ]; then
  installed_commit=$(cat "$DEST/.darkwave-source-commit")
fi
if [ "$installed_commit" != "$ARTEX_COMMIT" ]; then
  STAGE=$(mktemp -d "$ROOT/.ARTEX-stage.XXXXXX")
  BACKUP=""
  cleanup() {
    if [ -n "$STAGE" ] && [ -d "$STAGE" ]; then rm -rf "$STAGE"; fi
    if [ -n "$BACKUP" ] && [ -d "$BACKUP" ] && [ ! -d "$DEST" ]; then mv "$BACKUP" "$DEST"; fi
  }
  trap cleanup EXIT HUP INT TERM
  tar -xzf "$BUNDLE" -C "$STAGE"
  [ -f "$STAGE/ARTEX/docker-compose.yml" ] || {
    echo "ARTEX-Archiv ist unvollständig" >&2
    exit 1
  }

  # Keep local configuration, runtime data, signing keys and custom skills on upgrades.
  if [ -d "$DEST" ]; then
    for item in .env data keys; do
      if [ -e "$DEST/$item" ] || [ -L "$DEST/$item" ]; then
        cp -a "$DEST/$item" "$STAGE/ARTEX/"
      fi
    done
    if [ -d "$DEST/skills" ]; then
      mkdir -p "$STAGE/ARTEX/skills"
      cp -a "$DEST/skills/." "$STAGE/ARTEX/skills/"
    fi
    BACKUP="$DEST.previous.$(date +%Y%m%d%H%M%S)"
    mv "$DEST" "$BACKUP"
  fi
  printf '%s\n' "$ARTEX_COMMIT" > "$STAGE/ARTEX/.darkwave-source-commit"
  if ! mv "$STAGE/ARTEX" "$DEST"; then
    echo "Konnte den eingebetteten ARTEX-Stand nicht installieren" >&2
    exit 1
  fi
  rm -rf "$STAGE"
  STAGE=""
  trap - EXIT HUP INT TERM
fi

cd "$DEST"
[ -f .env ] || cp .env.example .env
if ! grep -q '^POSTGRES_PASSWORD=.' .env || grep -q '^POSTGRES_PASSWORD=change-me-please$' .env; then
  POSTGRES_PASSWORD=$(openssl rand -hex 24)
  if grep -q '^POSTGRES_PASSWORD=' .env; then
    sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" .env
  else
    printf '\nPOSTGRES_PASSWORD=%s\n' "$POSTGRES_PASSWORD" >> .env
  fi
fi
if ! grep -q '^ARTEX_SECRET_KEY=.' .env; then
  ARTEX_SECRET_KEY=$(openssl rand -hex 32)
  if grep -q '^ARTEX_SECRET_KEY=' .env; then
    sed -i "s/^ARTEX_SECRET_KEY=.*/ARTEX_SECRET_KEY=$ARTEX_SECRET_KEY/" .env
  else
    printf '\nARTEX_SECRET_KEY=%s\n' "$ARTEX_SECRET_KEY" >> .env
  fi
fi
sed -i 's/^ARTEX_BIND_ADDR=.*/ARTEX_BIND_ADDR=0.0.0.0/' .env
grep -q '^ARTEX_BIND_ADDR=' .env || echo 'ARTEX_BIND_ADDR=0.0.0.0' >> .env
ufw allow 8787/tcp >/dev/null 2>&1 || true
mkdir -p /var/lib/dw
{
  echo "ARTEX source commit: $ARTEX_COMMIT"
  docker compose -p artex up -d --build
} > /var/lib/dw/artex.log 2>&1 || {
  {
    echo "ARTEX source commit: $ARTEX_COMMIT"
    docker-compose -p artex up -d --build
  } >> /var/lib/dw/artex.log 2>&1
}
