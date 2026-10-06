#!/usr/bin/env bash
# Packages sources into packages/<id>.aix, reusing previously published packages
# for sources whose content hasn't changed.
#
# A source's content hash covers the git trees of its directory and of every local
# path dependency (templates), so it's stable across rebases and catches code changes
# that didn't bump the version. Hashes are written to packages/manifest.json, which
# gets published next to the source list and read back on the next build.
#
# usage: package-sources.sh [previous-gh-pages-dir]
set -euo pipefail

previous="${1:-}"
previous_manifest="$previous/build-manifest.json"
[[ -n "$previous" && -f "$previous_manifest" ]] || previous_manifest=""

mkdir -p packages
manifest="{}"

# prints the source dir plus its local path dependencies, recursively
deps() {
	local dir="$1" dep
	echo "$dir"
	[[ -f "$dir/Cargo.toml" ]] || return 0
	{ grep -oE 'path *= *"[^"]+"' "$dir/Cargo.toml" || true; } | sed -E 's/.*"(.+)"/\1/' |
		while read -r dep; do
			deps "$(python3 -c 'import os, sys; print(os.path.normpath(sys.argv[1]))' "$dir/$dep")"
		done
}

content_hash() {
	deps "$1" | sort -u | while read -r path; do
		echo "$path $(git rev-parse "HEAD:$path")"
	done | sha1sum | cut -d' ' -f1
}

built=0
reused=0

for source in sources/*; do
	[[ -f "$source/Cargo.toml" ]] || continue

	id="$(jq -r .info.id "$source/res/source.json")"
	version="$(jq -r .info.version "$source/res/source.json")"
	hash="$(content_hash "$source")"
	manifest="$(jq --arg id "$id" --arg hash "$hash" '.[$id] = $hash' <<< "$manifest")"

	published="$previous/sources/$id-v$version.aix"
	if [[ -n "$previous" && -f "$published" ]]; then
		if [[ -z "$previous_manifest" ]]; then
			# no manifest from an older build, so trust the version number
			reason=""
		elif [[ "$(jq -r --arg id "$id" '.sources[$id] // ""' "$previous_manifest")" == "$hash" ]]; then
			reason=""
		else
			reason="content changed"
		fi
		if [[ -z "$reason" ]]; then
			cp "$published" "packages/$id.aix"
			reused=$((reused + 1))
			continue
		fi
	elif [[ -n "$previous" ]]; then
		reason="new version"
	else
		reason="full rebuild"
	fi

	echo "::group::Packaging $id v$version ($reason)"
	(
		cd "$source"
		aidoku package
	)
	cp "$source/package.aix" "packages/$id.aix"
	built=$((built + 1))
	echo "::endgroup::"
done

jq --arg commit "$(git rev-parse HEAD)" '{commit: $commit, sources: .}' <<< "$manifest" > packages/manifest.json
echo "Built $built, reused $reused"
