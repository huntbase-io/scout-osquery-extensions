#!/bin/bash

OUTPUT_DIR="../bin"
SCOUT_DIR="scout-query"

cd $SCOUT_DIR || { echo "Directory $SCOUT_DIR not found. Aborting."; exit 1; }

platforms=("windows/amd64" "darwin/amd64" "darwin/arm64" "linux/amd64" "linux/arm64")

for platform in "${platforms[@]}"
do
	platform_split=(${platform//\// })
	GOOS=${platform_split[0]}
	GOARCH=${platform_split[1]}
	output_name=$OUTPUT_DIR/scout-query-$GOOS-$GOARCH

	if [ "$GOOS" == "windows" ]; then
		output_name+='.ext.exe'
	else
		output_name+='.ext'
	fi

  	env GOOS=$GOOS GOARCH=$GOARCH go build -ldflags "-w -X main.Version=0.1.0" -o $output_name 2> build_error.log
	if [ $? -ne 0 ]; then
		echo "An error occurred while building for $GOOS/$GOARCH. Aborting..."
		cat build_error.log
		exit 1
	fi
done

rm -f build_error.log
