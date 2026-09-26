# Decode-Payload.ps1
# Intercepts obfuscated Base64 payload from Event ID 4698 telemetry
$EncodedString = "dwBoAG8AYQBtAGkAIAAvAGEAbABsACAAPgAgAEMAOgBcAFUAcwBl AHIAcwBcAFAAdQBiAGwAaQBjAFwAcAByAG8AbwBmAC4AdAB4AHQA".Replace(" ", "")
$DecodedBytes = [System.Convert]::FromBase64String($EncodedString)
$DecodedCommand = [System.Text.Encoding]::Unicode.GetString($DecodedBytes)

Write-Output "Decoded Command: $DecodedCommand"
