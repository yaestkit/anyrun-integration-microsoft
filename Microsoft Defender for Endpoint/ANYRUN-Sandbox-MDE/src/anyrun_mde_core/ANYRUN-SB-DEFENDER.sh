#!/bin/bash

set -u

if [[ "${1:-}" != "-payload" || -z "${2:-}" ]]; then
    echo "Invalid Live Response payload."
    exit 1
fi

decode_base64url() {
    local value="$1"
    local remainder=$(( ${#value} % 4 ))

    value="${value//-/+}"
    value="${value//_/\/}"
    case "$remainder" in
        0) ;;
        2) value="${value}==" ;;
        3) value="${value}=" ;;
        *) return 1 ;;
    esac
    printf '%s' "$value" | base64 -d
}

IFS='.' read -r -a payloadParts <<< "$2"
if (( ${#payloadParts[@]} < 6 )) ||
   [[ "${payloadParts[0]}" != "v2" ]] ||
   (( (${#payloadParts[@]} - 3) % 3 != 0 )); then
    echo "Invalid or unsupported Live Response payload."
    exit 1
fi

if ! storageAccountName="$(decode_base64url "${payloadParts[1]}")" ||
   ! containerName="$(decode_base64url "${payloadParts[2]}")"; then
    echo "Failed to decode Live Response payload."
    exit 1
fi

filePaths=()
blobNames=()
sasTokens=()
for ((index = 3; index < ${#payloadParts[@]}; index += 3)); do
    if ! filePath="$(decode_base64url "${payloadParts[$index]}")" ||
       ! blobName="$(decode_base64url "${payloadParts[$((index + 1))]}")" ||
       ! sasToken="$(decode_base64url "${payloadParts[$((index + 2))]}")"; then
        echo "Failed to decode Live Response payload."
        exit 1
    fi
    filePaths+=("$filePath")
    blobNames+=("$blobName")
    sasTokens+=("$sasToken")
done

tempFolder="$(mktemp -d /tmp/ANYRUN.XXXXXXXX)" || exit 1
exclusionAdded=false

cleanup() {
    if $exclusionAdded; then
        sudo mdatp exclusion folder remove --path "$tempFolder" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$tempFolder"
}
trap cleanup EXIT

restore_from_quarantine() {
    local file="$1"
    local restorePath="$2"
    sudo mdatp threat quarantine restore threat-path --path "$file" --destination-path "$restorePath"
    sleep 5
    [[ -f "$restorePath/$(basename "$file")" ]]
}

upload_to_blob() {
    local file="$1"
    local blobName="$2"
    local sas="$3"
    [[ "$sas" == \?* ]] || sas="?$sas"

    curl --fail --silent --show-error --request PUT --upload-file "$file" --config - <<EOF
url = "https://$storageAccountName.blob.core.windows.net/$containerName/$blobName$sas"
header = "x-ms-blob-type: BlockBlob"
header = "x-ms-version: 2021-04-10"
header = "Content-Type: application/octet-stream"
EOF
}

chmod 700 "$tempFolder"
if ! sudo mdatp exclusion folder add --path "$tempFolder"; then
    echo "Failed to add the temporary Microsoft Defender exclusion: $tempFolder"
    exit 1
fi
exclusionAdded=true

uploadedCount=0
for ((index = 0; index < ${#filePaths[@]}; index++)); do
    path="${filePaths[$index]}"
    tempFilePath="$tempFolder/$(basename "$path")"

    if [[ -f "$path" ]]; then
        if ! cp -f -- "$path" "$tempFilePath"; then
            echo "Failed to copy evidence file: $path"
            continue
        fi
    elif ! restore_from_quarantine "$path" "$tempFolder"; then
        echo "File was not found at the source path or in quarantine: $path"
        continue
    fi

    if ! upload_to_blob "$tempFilePath" "${blobNames[$index]}" "${sasTokens[$index]}"; then
        echo "Failed to upload evidence file: $path"
    else
        uploadedCount=$((uploadedCount + 1))
    fi
    rm -f -- "$tempFilePath"
done

if (( uploadedCount == 0 )); then
    echo "No evidence files could be collected or uploaded."
    exit 1
fi

if (( uploadedCount < ${#filePaths[@]} )); then
    echo "Uploaded $uploadedCount of ${#filePaths[@]} evidence files."
fi

echo "Script completed successfully."
