
#https://blog.loftinnc.com/convert-enterprise-ca-cert-to-pem-format
#https://www.pkisolutions.com/accessing-and-using-certificate-private-keys-in-net-framework-net-core/
#https://docs.yubico.com/yesdk/users-manual/application-piv/cert-request.html
#https://arvehansen.net/codecave/2021/04/11/generate-a-new-x509certificate2-with-extensions-and-private-key-in-c/
#https://www.sysadmins.lv/blog-en/retrieve-cng-key-container-name-and-unique-name.aspx
#https://stackoverflow.com/questions/48196350/generate-and-sign-certificate-request-using-pure-net-framework
#https://www.powershellgallery.com/packages/ACME-PS/1.0.3/Content/internal%5Cclasses%5Ccrypto%5CCertificate.ps1
#https://github.com/dotnet/runtime/issues/23474
#https://gethttpsforfree.com/
#https://gist.github.com/sevaa/802a01649aa0746c959240146074c2b5
#https://www.ssltrust.com.au/ssl-tools/certificate-key-matcher

#region initialise
#Script folder parent & parent
function Get-ScriptDirectory {      if($hostinvocation -ne $null)  { Split-Path $hostinvocation.MyCommand.path    }     else  { Split-Path $script:MyInvocation.MyCommand.Path   } } 
$SCRIPT_PARENT   = Get-ScriptDirectory
$SCRIPT_PARENTS_PARENT=Split-Path $SCRIPT_PARENT -Parent
#load modules import function
Import-Module $(Join-Path -Path $SCRIPT_PARENT -ChildPath "Modules\unloadall_load_modules_in_folder.psm1") 
#load modules from folder
unloadall_load_modules_in_folder -path $(Join-Path -Path $SCRIPT_PARENT -ChildPath "Modules\")
#endregion


#region Helper



function Generate-RsaKeyPair {
    param(
        [int]$keysize=2048
    )

    $creationParameters=New-Object -TypeName System.Security.Cryptography.CngKeyCreationParameters
    $creationParameters.KeyCreationOptions=[System.Security.Cryptography.CngKeyCreationOptions]::OverwriteExistingKey
    $creationParameters.ExportPolicy=[System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport      #https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.cngexportpolicies?view=net-6.0
    $creationParameters.KeyUsage =[System.Security.Cryptography.CngKeyUsages]::AllUsages
    $creationParameters.Provider =[System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
    $creationParameters.UIPolicy=[System.Security.Cryptography.CngUIProtectionLevels]::None
    $AlgName = [System.Security.Cryptography.CngAlgorithm]::Rsa
    $keylength_bytes_little_endian=[System.BitConverter]::GetBytes($keysize)
    $keylength_property= New-Object System.Security.Cryptography.CngProperty -ArgumentList "Length",$keylength_bytes_little_endian,0
    $null=$creationParameters.Parameters.Add($keylength_property)
    

    $CngKey = [System.Security.Cryptography.CngKey]::Create($AlgName, $KeyName, $creationParameters)
    $RSAKey = New-Object System.Security.Cryptography.RSACng($CngKey)
    return $RSAKey
}




function Generate-CsrPEM {
    param(
        [string]$subjectName,
        [string[]]$subjectAlternativeNames,
        [System.Security.Cryptography.X509Certificates.X500DistinguishedName]$DN,
        [System.Security.Cryptography.RSA]$RSAKey,
        [string[]]$AltHostnames=$null,
        [string[]]$AltIPAddresses=$null,
        [System.Security.Cryptography.HashAlgorithmName] $HashAlg = [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding] $Padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )


    $Request = New-Object System.Security.Cryptography.X509Certificates.CertificateRequest -ArgumentList $DN,$RSAKey,$HashAlg,$Padding


    #region key usage
    
    $X509KeyUsageFlags_KeyEncipherment = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
    $X509KeyUsageFlags_DigitalSignature= [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature
    $X509KeyUsageFlags_DataEncipherment= [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DataEncipherment
    

    #$Ext = New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension -ArgumentList @($X509KeyUsageFlags_KeyEncipherment,$X509KeyUsageFlags_DigitalSignature,$X509KeyUsageFlags_DataEncipherment),$true
    $Ext = New-Object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension -ArgumentList @($X509KeyUsageFlags_KeyEncipherment,$X509KeyUsageFlags_DigitalSignature),$true
    $null=$Request.CertificateExtensions.Add($Ext)
    #endregion


    
    #Region Enhanced Key Usage - Server Auth, Client Auth
    $Oid_server_auth = [System.Security.Cryptography.Oid]::FromFriendlyName("Server Authentication", [System.Security.Cryptography.OidGroup]::EnhancedKeyUsage);
    $Oid_client_auth = [System.Security.Cryptography.Oid]::FromFriendlyName("Client Authentication", [System.Security.Cryptography.OidGroup]::EnhancedKeyUsage);
    $Oid_app_policies= [System.Security.Cryptography.Oid]::FromFriendlyName("Application Policies", [System.Security.Cryptography.OidGroup]::All);

    $Oids = New-Object System.Security.Cryptography.OidCollection
    $null=$Oids.Add($Oid_server_auth)
    #$null=$Oids.Add($Oid_client_auth)
    
    $Ext = New-Object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension -ArgumentList $Oids,$false
    $null=$Request.CertificateExtensions.Add($Ext)
    
    #endregion


    #Region  Subject Alternative Name - assuming only "DNS Name" entries
    $SANBuilder = New-Object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder
    foreach($AltHostname in $AltHostnames)
    {$null=$SANBuilder.AddDnsName($AltHostname);    }
    
    foreach($AltIPAddress  in $AltIPAddresses )
    { $null=$SANBuilder.AddIpAddress($AltIPAddress); }
    
    $null=$Request.CertificateExtensions.Add($SANBuilder.Build())
    #endregion
    
    #Region Subject Key Identifier
    $Ext = New-Object System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension -ArgumentList $($Request.PublicKey),$false
    $null=$Request.CertificateExtensions.Add($Ext)
    #endregion

    #Region Application Policies - HARDCODED to "Server Auth, Client Auth"
    [byte[]]$Policies = @(48, 24, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 1, 48, 10, 6, 8, 43, 6, 1, 5, 5, 7, 3, 2)
    #$Ext = New-Object System.Security.Cryptography.X509Certificates.X509Extension -ArgumentList "1.3.6.1.4.1.311.21.10",$Policies,$false
    #$Ext = New-Object System.Security.Cryptography.X509Certificates.X509Extension -ArgumentList $Oid_app_policies,$false
    $Ext = New-Object System.Security.Cryptography.X509Certificates.X509Extension -ArgumentList $Oid_app_policies,$Policies,$false
    $null=$Request.CertificateExtensions.Add($Ext)
    #endregion

    #region Friendly Name
    if($FriendlyName)
    {
        $Value = [System.Text.Encoding]::Unicode.GetBytes($FriendlyName + "`0")
        $Ext = New-Object System.Security.Cryptography.X509Certificates.X509Extension -ArgumentList "1.3.6.1.4.1.311.10.11.11",$Value,$false
        $null=$Request.CertificateExtensions.Add($Ext)
    }
    #endregion

    $req_pem=$Request.CreateSigningRequestPem()
    return $req_pem
}

#endregion


# Basic parameters. For TLS certs for IIS, this is sufficient
$Hostname = "foo.example.com" # Goes into Subject as the CN
$AltHostnames = @("foo.example.com", "bar.example.com", "baz.example.com") # These go into Subject Alternative Name
$AltIPAddresses = @("10.10.10.100") # These go into Subject Alternative Name

#DN
$DN="CN=$Hostname;OU=IT;O=Acme Ltd;L=Auckland;S=Auckland;C=NZ;DC=local;E=bob@hotmail.com"
$DN = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName -ArgumentList $DN


$rsa_keypair = Generate-RsaKeyPair

$csr_pem=Generate-CsrPEM -RSAKey $rsa_keypair -subjectName $Hostname -AltHostnames $AltHostnames -AltIPAddresses $AltIPAddresses -DN $DN


$CSRPath = Join-Path -Path $SCRIPT_PARENT -ChildPath "MyCert.csr"
$csr_pub_key_path = Join-Path -Path $SCRIPT_PARENT -ChildPath "csr_pub_key.key"
$PublicKeyPath = Join-Path -Path $SCRIPT_PARENT -ChildPath "Public.key"
$PrivateKeyPath = Join-Path -Path $SCRIPT_PARENT -ChildPath "Private.key"
$open_ssl_commands_path = Join-Path -Path $SCRIPT_PARENT -ChildPath "open_ssl_commands.txt"
$plain_message_file_path = Join-Path -Path $SCRIPT_PARENT -ChildPath "message.txt"
$encrypted_message_file_path = Join-Path -Path $SCRIPT_PARENT -ChildPath "message.enc"



<#
$rsa_keypair.ExportPkcs8PrivateKeyPem()
$rsa_keypair.ExportSubjectPublicKeyInfoPem()
$rsa_keypair.ExportRSAPrivateKeyPem()
$rsa_keypair.ExportRSAPublicKeyPem()
#>

Out-File -FilePath $CSRPath -InputObject $csr_pem
#Out-File -FilePath $PublicKeyPath -InputObject $rsa_keypair.ExportRSAPublicKeyPem()
#Out-File -FilePath $PrivateKeyPath -InputObject $rsa_keypair.ExportRSAPrivateKeyPem()

Out-File -FilePath $PublicKeyPath -InputObject $rsa_keypair.ExportSubjectPublicKeyInfoPem()
Out-File -FilePath $PrivateKeyPath -InputObject $rsa_keypair.ExportPkcs8PrivateKeyPem()


Write-Host "vvvvvvvvvvvvvvvvvvvvvvvvvv"
Write-Output $rsa_keypair.ExportSubjectPublicKeyInfoPem()
Write-Host "^^^^^^^^^^^^^^^^^^^^^^^^^^"

Write-Host "vvvvvvvvvvvvvvvvvvvvvvvvvv"
Write-Output $rsa_keypair.ExportPkcs8PrivateKeyPem()
Write-Host "^^^^^^^^^^^^^^^^^^^^^^^^^^"


#https://certlogik.com/decoder/

