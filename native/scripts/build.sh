#!/bin/bash
set -euo pipefail
script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"
native_dir="$repo_dir/native"
if [[ "$(uname -m)" != arm64 ]]; then
  echo "This build currently supports Apple Silicon and /opt/homebrew/bin/openfortivpn." >&2
  exit 1
fi
export MACOSX_DEPLOYMENT_TARGET=13.0
swift build --package-path "$native_dir" --configuration release --product FortiVPNTray
swift build --package-path "$native_dir" --configuration release --product FortiVPNHelper
binary_dir="$(swift build --package-path "$native_dir" --configuration release --show-bin-path)"
cargo build --manifest-path "$repo_dir/helper/Cargo.toml" --locked --release -p openvpngui-helper
output_dir="${FORTIVPNTRAY_OUTPUT_DIR:-$native_dir/dist}"
app_path="$output_dir/FortiVPNTray.app"
mkdir -p "$app_path/Contents/MacOS" "$app_path/Contents/Resources"
cp "$binary_dir/FortiVPNTray" "$app_path/Contents/MacOS/FortiVPNTray"
cp "$repo_dir/helper/target/release/openvpngui-helper" "$app_path/Contents/Resources/openvpngui-helper"
cp "$binary_dir/FortiVPNHelper" "$app_path/Contents/Resources/FortiVPNHelper"
cp "$native_dir/Resources/Info.plist" "$app_path/Contents/Info.plist"
cp "$native_dir/Resources/icon.icns" "$app_path/Contents/Resources/icon.icns"
cp "$repo_dir/LICENSE" "$app_path/Contents/Resources/LICENSE"
"$script_dir/sign.sh" "$app_path"
ditto -c -k --sequesterRsrc --keepParent "$app_path" "$output_dir/FortiVPNTray-native-arm64.zip"
echo "Built: $app_path"
