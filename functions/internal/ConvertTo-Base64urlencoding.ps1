function ConvertTo-Base64urlencoding {
    param ($value)
    if ( $value.GetType().Name -eq "String" ) { $value = [System.Text.Encoding]::UTF8.GetBytes($value) }
    return ( [System.Convert]::ToBase64String($value) -replace '\+','-' -replace '/','_' -replace '=' )
}