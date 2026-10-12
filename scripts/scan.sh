#!/usr/bin/env bash
# Scan the assets listed in policy.yml with Trivy and write slim JSON into data/scans/.
# Works with a local trivy binary (TRIVY=path) or the official image (TRIVY="docker run ...").
# Trivy pulls images straight from the registry: no Docker daemon needed for `trivy image`.
set -euo pipefail
cd "$(dirname "$0")/.."
TRIVY="${TRIVY:-trivy}"
mkdir -p work/scans data/scans

scan_image() {  # <image ref> <output name>
  echo "== $1"
  $TRIVY image --scanners vuln --format json --output "work/scans/$2.json" --quiet "$1"
  $TRIVY image --scanners vuln --format cyclonedx --output "work/scans/$2.cdx.json" --quiet "$1"
  python scripts/slim_scan.py "work/scans/$2.json" "data/scans/$2.json"
}

scan_image "nginx:1.27"                     nginx_1.27
scan_image "wordpress:6.8-php8.2-apache"    wordpress_6.8-php8.2-apache
scan_image "mariadb:11.4"                   mariadb_11.4

echo "== data/manifests/requirements.txt"
$TRIVY fs --scanners vuln --format json --output work/scans/fs_appsec.json --quiet data/manifests
python scripts/slim_scan.py work/scans/fs_appsec.json data/scans/fs_appsec.json
