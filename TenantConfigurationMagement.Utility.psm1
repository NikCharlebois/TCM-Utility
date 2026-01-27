$APIInformation = @{
    graph = @{
        GUID = "00000003-0000-0000-c000-000000000000"
    }
    "Office 365 Exchange Online" = @{
        GUID = "00000002-0000-0ff1-ce00-000000000000"
    }
}

function Test-TCMConfigurationTemplate
{
    [CmdletBinding()]
    param(
        [Parameter(ParameterSetName = 'Path', Position = 0)]
        [System.String]
        $Path,
        
        [Parameter(ParameterSetName = 'Names', Position = 0)]
        [System.String[]]
        $ResourceNames
    )

    if ($Path)
    {
        $rawContent = Get-Content $Path -Raw
        $jsonTemplate = ConvertFrom-Json $rawContent

        $resourceTypes = $jsonTemplate.Resources | Select-Object ResourceType -Unique
        $allResourceTypes = $resourceTypes.ResourceType
    }
    elseif ($ResourceNames)
    {
        $allResourceTypes = $ResourceNames
    }
    $permissionContent = Get-Content ($PSScriptRoot + "\TCMPermissionsAndRoles.json") -Raw
    $permissionJson = ConvertFrom-Json $permissionContent

    $foundReadPermissions = @{}    
    $foundWritePermissions = @{}
    $foundReadRoles = @()  
    $foundWriteRoles = @()
    foreach ($resourceType in $allResourceTypes)
    {
        $permissionMap = $permissionJson | ?{$_.ResourceName -eq $resourceType} 
        foreach ($role in $permissionMap.Roles.read)
        {
            if (-not $foundReadRoles.Contains($role))
            {
                $foundReadRoles += $role
            }
        }
        foreach ($role in $permissionMap.Roles.update)
        {
            if (-not $foundWriteRoles.Contains($role))
            {
                $foundWriteRoles += $role
            }
        }

        foreach ($permission in $permissionMap.Permissions)
        {
            $currentAPI = $permission.API
            if (-not $foundReadPermissions.ContainsKey($currentAPI))
            {
                $foundReadPermissions.Add($currentAPI, @())
            }
            $foundReadPermissions.$currentAPI += $permission.Read 

            if (-not $foundWritePermissions.ContainsKey($currentAPI))
            {
                $foundWritePermissions.Add($currentAPI, @())
            }
            $foundWritePermissions.$currentAPI += $permission.Write 
        }
    }
    $compiledPermissionsAndRoles = @{
        Read = @{
            Roles = $foundReadRoles
            Permissions = $foundReadPermissions
        }
        Write = @{
            Roles = $foundWriteRoles
            Permissions = $foundWritePermissions
        }
    }
    return $compiledPermissionsAndRoles
}

function Add-TCMServicePrincipalPermissions
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [System.Array]
        $Permissions
    )

    # Retrieve the UTCM Service Principal
    $UTCMSPN = Get-MgServicePrincipal -Filter "AppId eq '03b07b79-c5bc-4b5e-9bfa-13acf4a99998'"
    foreach ($APIName in $Permissions.Keys)
    {
        $apiGUID = $APIInformation.$APIName.GUID
        if (-not [System.String]::IsNullOrEmpty($apiGUID))
        {
            $apiSPN = Get-MgServicePrincipal -Filter "AppId eq '$($apiGUID)'"
            foreach ($perm in $Permissions.$APIName)
            {
                Write-Host "Adding for permission {$perm} for API {$APIName}..." -NoNewline
                try
                {
                    # Retrieve the id of the permission requested 
                    $AppRole = $apiSPN.AppRoles | Where-Object -FilterScript {$_.Value -eq $perm}
                
                    # Assign the permission
                    $body = @{
                        AppRoleId   = $AppRole.Id
                        ResourceId  = $apiSPN.Id
                        PrincipalId = $UTCMSPN.Id
                    }
                    New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $UTCMSPN.Id `
                                                            -BodyParameter $body `
                                                            -ErrorAction Stop | Out-Null
                    Write-Host "Done" -ForegroundColor Green
                }
                catch
                {
                    if ($_.Exception.Message.Contains('assigned already exists'))
                    {
                        Write-Host "Already exists" -ForegroundColor Yellow
                    }
                    else
                    {
                        Write-Host "Failed: $($_.Exception.Message)" -ForegroundColor Red
                    }
                }
            }
        }
    }
}
