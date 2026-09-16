#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p target/previews
viewer=(foundation-slint-viewer tests/previews.slint
    -L ui=target/foundation/ui/ui
    -L theme=target/foundation/themes/slint)
"${viewer[@]}" --check
for height in 760 800; do
    for dark in false true; do
        for page in 0 1 2 3 4 5 6 7 8 9 10; do
            printf '{"window-height":%s,"dark":%s,"page":%s}' "$height" "$dark" "$page" |
                "${viewer[@]}" --load-data - --screenshot "target/previews/page-${page}-${height}-dark-${dark}.png"
        done
        for scenario in legacy long multiple; do
            case "$scenario" in
                legacy) publishers='[{"name":"","email":"","fingerprint":"D4D0 D320 2FC0 6849 A257\nB38D E946 1833 4C67 4B40","details-available":false,"key-available":false}]' ;;
                long) publishers='[{"name":"A publisher with a very long display name that must wrap inside the card without clipping any text","email":"a-very-long-email-address-for-testing-line-wrapping@example-publisher-with-a-long-domain.com","fingerprint":"AAAA BBBB CCCC DDDD EEEE\nFFFF 0000 1111 2222 3333\n4444 5555 6666 7777 8888\n9999","details-available":true,"key-available":true}]' ;;
                multiple) publishers='[{"name":"Craig Raw","email":"craig@sparrowwallet.com","fingerprint":"D4D0 D320 2FC0 6849 A257\nB38D E946 1833 4C67 4B40","details-available":true,"key-available":true},{"name":"Publisher without an email","email":"","fingerprint":"AAAA BBBB CCCC DDDD EEEE\nFFFF 0000 1111 2222 3333","details-available":true,"key-available":false},{"name":"","email":"email-only@example.com","fingerprint":"BBBB BBBB CCCC DDDD EEEE\nFFFF 0000 1111 2222 3333","details-available":true,"key-available":true}]' ;;
            esac
            printf '{"window-height":%s,"dark":%s,"page":6,"saved-publishers":%s}' "$height" "$dark" "$publishers" |
                "${viewer[@]}" --load-data - --screenshot "target/previews/keys-${scenario}-${height}-dark-${dark}.png"
            printf '{"window-height":%s,"dark":%s,"page":10,"saved-publishers":%s}' "$height" "$dark" "$publishers" |
                "${viewer[@]}" --load-data - --screenshot "target/previews/key-picker-${scenario}-${height}-dark-${dark}.png"
            for confirming in false true; do
                printf '{"window-height":%s,"dark":%s,"page":9,"saved-publishers":%s,"confirming-delete":%s}' "$height" "$dark" "$publishers" "$confirming" |
                    "${viewer[@]}" --load-data - --screenshot "target/previews/publisher-${scenario}-${height}-dark-${dark}-confirm-${confirming}.png"
            done
        done
        printf '{"window-height":%s,"dark":%s,"page":0,"menu-open":true}' "$height" "$dark" |
            "${viewer[@]}" --load-data - --screenshot "target/previews/main-menu-${height}-dark-${dark}.png"
        printf '{"window-height":%s,"dark":%s,"page":9,"confirming-delete":true}' "$height" "$dark" |
            "${viewer[@]}" --load-data - --screenshot "target/previews/publisher-confirm-${height}-dark-${dark}.png"
        printf '{"window-height":%s,"dark":%s,"page":9,"confirming-delete":true,"error":"Could not save the change. The key is still trusted."}' "$height" "$dark" |
            "${viewer[@]}" --load-data - --screenshot "target/previews/publisher-error-${height}-dark-${dark}.png"
        for kind in 0 2; do
            title="Checksum Matches"
            summary="The bytes match. Publisher identity has not been verified."
            if [ "$kind" = 2 ]; then
                title="Checksum Mismatch"
                summary="The file does not match the expected checksum."
            fi
            printf '{"window-height":%s,"dark":%s,"page":3,"result-kind":%s,"result-title":"%s","result-summary":"%s","result-detail":"demo-release.txt","result-fingerprint":"","can-trust":false}' "$height" "$dark" "$kind" "$title" "$summary" |
                "${viewer[@]}" --load-data - --screenshot "target/previews/result-${kind}-${height}-dark-${dark}.png"
        done
        printf '{"window-height":%s,"dark":%s,"page":3,"result-kind":3,"result-title":"SHA-512 Calculated","result-summary":"This identifies the file bytes, not its publisher.","result-detail":"demo-release.txt\\n91 bytes\\n\\n835f067cd089f915\\n85ded4ff30c34d69\\n139cc18f41eea70e\\ncaa47cbd318afdc3\\n29e5a98f2be7ee59\\n378458c3c3deb241\\n64f146bbae4174d5\\n65eb539de40171da","result-fingerprint":"","can-trust":false,"can-compare":true}' "$height" "$dark" |
            "${viewer[@]}" --load-data - --screenshot "target/previews/hash-result-${height}-dark-${dark}.png"
    done
done
