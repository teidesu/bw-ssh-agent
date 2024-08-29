#!/usr/bin/env bash
# this file is called by the cargo-make

bundle_name=bw-ssh-agent
bundle_id=$ORGANIZATION_ID.$bundle_name

mkdir -p ./dist/Applications/$bundle_name.app/Contents/MacOS
mkdir -p ./dist/Applications/$bundle_name.app/Contents/Library/LaunchAgents

cp assets/embedded.provisionprofile ./dist/Applications/$bundle_name.app/Contents/
cp target/debug/bw-ssh-agent ./dist/Applications/$bundle_name.app/Contents/MacOS/

sed 's/%TEAM_ID%/'$TEAM_ID'/g; s/%BUNDLE_ID%/'$bundle_id'/g' ./assets/entitlements.plist > ./dist/entitlements.plist
sed 's/%BUNDLE_ID%/'$bundle_id'/g; s/%BUNDLE_NAME%/'$bundle_name'/g' ./assets/Info.plist > ./dist/Applications/$bundle_name.app/Contents/Info.plist
sed 's/%BUNDLE_NAME%/'$bundle_name'/g' ./assets/launchd.plist > ./dist/Applications/$bundle_name.app/Contents/Library/LaunchAgents/launchd.plist

codesign --force --deep --identifier $bundle_id --sign $SIGNING_IDENTITY --entitlements ./dist/entitlements.plist --timestamp=none --verbose=0 -o runtime ./dist/Applications/$bundle_name.app
