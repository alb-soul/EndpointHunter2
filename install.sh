#!/usr/bin/env bash
# install.sh — build endpoint-hunter2 dari source repo ini dan pasang SALINAN
# biner (bukan symlink) ke $BINDIR (default /usr/local/bin).
#
#   ./install.sh                  build + pasang ke /usr/local/bin
#   BINDIR=~/.local/bin ./install.sh
#   PREFIX=/opt/tools ./install.sh   -> /opt/tools/bin
#   ./install.sh --uninstall      hapus $BINDIR/endpoint-hunter2 saja
#
# Update: git pull && ./install.sh
#
# Tidak meng-install Go, tidak men-download/clone apa pun (GOTOOLCHAIN=local),
# tidak mengubah PATH / shell rc. sudo hanya dipakai bila $BINDIR tak bisa
# ditulis user saat ini.
set -euo pipefail

NAME="endpoint-hunter2"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install] WARN: %s\n' "$*" >&2; }
die()  { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
	cat <<EOF
Usage: ./install.sh [--uninstall] [-h|--help]

Build ${NAME} dari source di ${SCRIPT_DIR}
dan pasang salinan biner (bukan symlink) ke \$BINDIR.

Environment:
  BINDIR   direktori tujuan (default: /usr/local/bin)
  PREFIX   bila BINDIR kosong: tujuan = \$PREFIX/bin

Opsi:
  --uninstall   hapus \$BINDIR/${NAME} (salinan lain di PATH tidak disentuh)
  -h, --help    tampilkan bantuan ini

Butuh Go >= versi di go.mod. Update: git pull && ./install.sh
EOF
}

# ── argumen ──────────────────────────────────────────────────────────────────
MODE="install"
while [[ $# -gt 0 ]]; do
	case "$1" in
	--uninstall) MODE="uninstall" ;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		usage >&2
		die "opsi tidak dikenal: $1"
		;;
	esac
	shift
done

# ── tujuan ───────────────────────────────────────────────────────────────────
if [[ -z "${BINDIR:-}" ]]; then
	if [[ -n "${PREFIX:-}" ]]; then
		BINDIR="${PREFIX%/}/bin"
	else
		BINDIR="/usr/local/bin"
	fi
fi
case "$BINDIR" in
/*) ;;
*) BINDIR="$PWD/$BINDIR" ;;
esac
while [[ "$BINDIR" == */ && "$BINDIR" != "/" ]]; do
	BINDIR="${BINDIR%/}"
done
DEST="$BINDIR/$NAME"

# ── sudo hanya bila perlu ────────────────────────────────────────────────────
# Direktori yang harus bisa ditulis: $BINDIR, atau induk terdekat yang ada
# (bila $BINDIR belum ada dan perlu dibuat).
writable_target() {
	local d="$BINDIR"
	while [[ ! -e "$d" ]]; do
		d="$(dirname -- "$d")"
	done
	[[ -d "$d" && -w "$d" ]]
}

USE_SUDO=0
if [[ "$(id -u)" -ne 0 ]] && ! writable_target; then
	command -v sudo >/dev/null 2>&1 ||
		die "$BINDIR tidak bisa ditulis user $(id -un) dan sudo tidak tersedia. Jalankan sebagai root, atau pakai BINDIR=\$HOME/.local/bin ./install.sh"
	USE_SUDO=1
	log "$BINDIR butuh hak root -> memakai sudo"
fi

run() {
	if [[ "$USE_SUDO" -eq 1 ]]; then
		sudo -- "$@"
	else
		"$@"
	fi
}

# Semua salinan ${NAME} yang bisa dieksekusi di PATH (urut prioritas, unik).
path_copies() {
	local dir seen=":" p
	local -a dirs
	IFS=":" read -r -a dirs <<<"$PATH"
	for dir in "${dirs[@]}"; do
		[[ -n "$dir" ]] || dir="."
		case "$seen" in *":$dir:"*) continue ;; esac
		seen="$seen$dir:"
		p="$dir/$NAME"
		if [[ -f "$p" && -x "$p" ]]; then
			printf '%s\n' "$p"
		fi
	done
}

describe_copy() {
	local p="$1" kind="file" ver
	if [[ -L "$p" ]]; then
		kind="symlink -> $(readlink -- "$p")"
	fi
	ver="$("$p" -version 2>/dev/null | head -n1 || true)"
	printf '    %s  (%s, versi: %s)\n' "$p" "$kind" "${ver:-?}"
}

# ── uninstall ────────────────────────────────────────────────────────────────
if [[ "$MODE" == "uninstall" ]]; then
	if [[ -L "$DEST" || -e "$DEST" ]]; then
		[[ -d "$DEST" && ! -L "$DEST" ]] && die "$DEST adalah direktori, tidak dihapus"
		run rm -f -- "$DEST"
		log "dihapus: $DEST"
	else
		log "tidak terpasang di $DEST (tidak ada yang dihapus)"
	fi
	mapfile -t others < <(path_copies)
	if [[ ${#others[@]} -gt 0 ]]; then
		warn "masih ada ${NAME} lain di PATH (tidak dihapus otomatis):"
		for p in "${others[@]}"; do describe_copy "$p" >&2; done
	fi
	exit 0
fi

# ── cek Go ───────────────────────────────────────────────────────────────────
need_major=1
need_minor=21
if [[ -f "$SCRIPT_DIR/go.mod" ]]; then
	gomod_ver="$(sed -n 's/^go[[:space:]]\{1,\}\([0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' "$SCRIPT_DIR/go.mod" | head -n1)"
	if [[ "$gomod_ver" =~ ^([0-9]+)\.([0-9]+)$ ]]; then
		need_major="${BASH_REMATCH[1]}"
		need_minor="${BASH_REMATCH[2]}"
	fi
fi
need="${need_major}.${need_minor}"

command -v go >/dev/null 2>&1 ||
	die "Go tidak ditemukan di PATH. Install Go >= $need (https://go.dev/doc/install atau paket distro), lalu jalankan ulang."

# GOTOOLCHAIN=local: Go >= 1.21 tidak boleh men-download toolchain lain.
export GOTOOLCHAIN=local
gover="$(go env GOVERSION 2>/dev/null || true)"
[[ -n "$gover" ]] || gover="$(go version 2>/dev/null | awk '{print $3}')"
if [[ "${gover#go}" =~ ^([0-9]+)\.([0-9]+) ]]; then
	have_major="${BASH_REMATCH[1]}"
	have_minor="${BASH_REMATCH[2]}"
	if ((have_major < need_major || (have_major == need_major && have_minor < need_minor))); then
		die "Go $gover terlalu lama; butuh >= $need (lihat go.mod). Perbarui Go lalu jalankan ulang."
	fi
elif [[ "$gover" == devel* ]]; then
	warn "Go development build ($gover) — versi tidak diperiksa"
else
	die "tidak bisa membaca versi Go ('$gover'); butuh >= $need"
fi
log "Go $gover (butuh >= $need)"

# ── build ke tmpdir (biner terpasang tidak disentuh bila gagal) ──────────────
tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/${NAME}-install.XXXXXX")"
cleanup() { rm -rf -- "$tmpdir"; }
trap cleanup EXIT
trap 'exit 130' INT TERM

log "build dari $SCRIPT_DIR"
# CGO dimatikan (default): biner statis, sama di semua distro (stdlib murni).
if ! (cd -- "$SCRIPT_DIR" && CGO_ENABLED="${CGO_ENABLED:-0}" go build -trimpath -o "$tmpdir/$NAME" .); then
	die "build gagal — biner terpasang ($DEST) tidak diubah"
fi
newver="$("$tmpdir/$NAME" -version 2>/dev/null | head -n1 || true)"
[[ -n "$newver" ]] || die "biner hasil build tidak bisa dijalankan — $DEST tidak diubah"

# ── pasang ───────────────────────────────────────────────────────────────────
if [[ ! -d "$BINDIR" ]]; then
	[[ -e "$BINDIR" ]] && die "$BINDIR ada tetapi bukan direktori"
	run install -d -m 755 "$BINDIR"
fi
if [[ -L "$DEST" ]]; then
	# jangan menulis ke target symlink (mis. build di repo) — ganti dgn file biasa
	log "menghapus symlink lama: $DEST -> $(readlink -- "$DEST")"
	run rm -f -- "$DEST"
elif [[ -e "$DEST" && ! -f "$DEST" ]]; then
	die "$DEST ada tetapi bukan file biasa"
fi
run install -m 755 "$tmpdir/$NAME" "$DEST"
log "terpasang: $DEST"

# ── verifikasi ───────────────────────────────────────────────────────────────
[[ -f "$DEST" && ! -L "$DEST" ]] || die "$DEST bukan file biasa setelah install"
inst_ver="$("$DEST" -version 2>/dev/null | head -n1 || true)"
[[ -n "$inst_ver" ]] || die "$DEST -version gagal"
log "versi: $inst_ver"

hash -r 2>/dev/null || true
resolved="$(command -v "$NAME" 2>/dev/null || true)"
if [[ -z "$resolved" ]]; then
	warn "$BINDIR tidak ada di PATH — '${NAME}' belum bisa dipanggil langsung (PATH tidak diubah oleh installer)."
elif [[ "$resolved" != "$DEST" ]]; then
	warn "'${NAME}' di PATH menunjuk ke $resolved, BUKAN $DEST — versi baru tidak akan terpakai."
	warn "salinan ${NAME} di PATH (urut prioritas); hapus yang tidak dipakai secara manual:"
	while IFS= read -r p; do describe_copy "$p" >&2; done < <(path_copies)
else
	log "OK: '${NAME}' di PATH = $DEST"
	mapfile -t others < <(path_copies)
	if [[ ${#others[@]} -gt 1 ]]; then
		warn "ada salinan lain di PATH dengan prioritas lebih rendah (tidak dihapus):"
		for p in "${others[@]}"; do
			[[ "$p" == "$DEST" ]] || describe_copy "$p" >&2
		done
	fi
fi
