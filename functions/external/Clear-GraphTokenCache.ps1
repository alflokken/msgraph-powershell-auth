function Clear-GraphTokenCache {
    <#
        .SYNOPSIS
        Clear windows forms webbrowser session data. (https://itecnote.com/tecnote/c-how-to-clear-system-windows-forms-webbrowser-session-data/)
        .DESCRIPTION
        Clear windows forms webbrowser session data. (https://itecnote.com/tecnote/c-how-to-clear-system-windows-forms-webbrowser-session-data/)
    #>
    $memberDefinition = '[DllImport("wininet.dll", SetLastError = true, CharSet=CharSet.Auto)] public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);'
    $type = Add-Type -MemberDefinition $memberDefinition -Name wininet -Namespace pinvoke -PassThru
    # INTERNET_OPTION_END_BROWSER_SESSION:https://learn.microsoft.com/en-us/windows/win32/wininet/option-flags
    $type::InternetSetOption(0, 42, 0, 0)
}