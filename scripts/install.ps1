<#
.SYNOPSIS
    One-shot installer: bootstrap Python + build + install the driver.

.DESCRIPTION
    Convenience wrapper that runs bootstrap.ps1 with -BuildDriver and
    -InstallDriver.  Use bootstrap.ps1 directly if you only want the
    user-mode pieces.
#>

[CmdletBinding()]
param()

. "$PSScriptRoot\_common.ps1"
Require-Admin

& "$PSScriptRoot\bootstrap.ps1" -BuildDriver -InstallDriver
