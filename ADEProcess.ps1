#http://www.derekmartin.org/easily-encrypt-your-azure-vms-with-keyvault/

#1. One Time Run - Create Key Vault
$KeyVaultName = "kv-neu-b"
$rgName = "rg-neu-b-kv"
$location = "North Europe"
New-AzureRmResourceGroup -Name $rgName -Location $location
New-AzureRmKeyVault -VaultName $KeyVaultName -ResourceGroupName $rgName -Location $location -SKU 'Premium'

Get-AzureRmKeyVault -VaultName $KeyVaultName
#Remove-AzureRmKeyVault -VaultName $KeyVaultName -ResourceGroupName $rgName


#2. One Time Run - Create KEK
$KEKname = "kek-neu-b"
$kek = add-azurekeyvaultkey -vaultname $keyvaultname -name $kekname -destination 'software'
$KeyEncryptionKeyUrl = $kek.key.kid

$kek = get-AzureKeyVaultKey -VaultName $KeyVaultName -Name $kekname



#3. One Time Run - Enable KV for DE
Set-AzureRmKeyVaultAccessPolicy -VaultName $KeyVaultName -ResourceGroupName $rgName -EnabledForDiskEncryption
Set-AzureRmKeyVaultAccessPolicy -VaultName $KeyVaultName -ResourceGroupName $rgName -EnabledForDeployment

Get-AzureRmKeyVault -VaultName $KeyVaultName

#4. One Time Run - Create an Azure AD Application and a service principle - Allows VMs to manage keys in KV
$appDispName = "kv-b-app"
$azureADApplication = New-AzureRMADApplication -DisplayName $appDispName -homepage "http://kv-b-app" -IdentifierUris "http://kv-b-app"
$aadClientID = $azureadapplication.applicationid
$serviceprincipal = new-azurermadserviceprincipal -ApplicationId $aadClientID
Get-AzureRMADApplication -DisplayName $appDispName

##here
#Remove-AzureRmADApplication -ApplicationObjectId $aadClientID

##Create a self-signed cert using IIS and export it (with private key) to pfx file (https://technet.microsoft.com/en-gb/library/cc753127(v=ws.10).aspx)

#5. Create JSON Object to import into KV
$fileName = "C:\azure\certs\kv-b-auth.pfx" 
$fileContentBytes = get-content $fileName -Encoding Byte
$fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)
$plaintextPassword = 'password'
$jsonObject = @"
{
"data": "$filecontentencoded",
"dataType" :"pfx",
"password": "$plaintextPassword"
}
"@
#Next we byte out the object, then covert it to base 64, that's what actually goes into the KeyVault: 
$jsonObjectBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonObject)
$jsonEncoded = [System.Convert]::ToBase64String($jsonObjectBytes)

#6. Add the certificate to the service principle - allows the VM to auth via a cert
#Need now to use AAD Powershell and connect to MSFT AAD - using 2FA (http://connect.microsoft.com/site1164/Downloads/DownloadDetails.aspx?DownloadID=59185)
Connect-MsolService
$cert = Get-PfxCertificate -FilePath C:\azure\certs\kv-b-auth.pfx 
$bincert = $cert.getrawcertdata()
$credvalue = [system.convert]::ToBase64String($bincert)
$thumbprint = $cert.thumbprint
$serviceprincipal = get-azurermadserviceprincipal -SearchString "kv-b-app"
New-MsolServicePrincipalCredential -Objectid "de4522b0-7967-4b50-86e2-84b15e9875ff" -Type asymmetric -Value $credValue


#Get-MsolServicePrincipalCredential -ObjectId <>  #-AppPrincipalID 
#Remove-MsolServicePrincipal -ObjectId "de4522b0-7967-4b50-86e2-84b15e9875ff"

#7. Set the access permissions for the AAD app in KV
$appDispName = "kv-b-app"
$azureADApplication = Get-AzureRMADApplication -DisplayName $appDispName 
$aadClientID = $azureadapplication.applicationid
set-azurermkeyvaultaccesspolicy -vaultname $keyvaultname -serviceprincipalname $aadclientid `
-permissionstokeys all -permissionstosecrets all -resourcegroupname $rgname

#Access Policy Maintenance
$keyvault = get-azurermkeyvault -vaultname $keyvaultname
#Remove-AzureRmKeyVaultAccessPolicy -VaultName <> -ObjectID <>


#8. Uploade the certificate also into KeyVault
$secret = ConvertTo-SecureString -String $jsonEncoded -AsPlainText –Force
$KeyVaultName = "kv-neu-b"
$Name = "ADAppAuthSecret"
Set-AzureKeyVaultSecret -VaultName $keyVaultName -Name $Name -SecretValue $secret 

#Secret Maintenance (Get and delete - if required)
Get-AzureKeyVaultSecret -VaultName $keyVaultName -Name $Name 
Remove-AzureKeyVaultSecret -VaultName $keyVaultName -Name $Name

#9. Deploy the DE cert to the VM 
$encryptionCertURI = (get-azurekeyvaultsecret -vaultname $keyVaultName -Name $name).Id
$keyvault = get-azurermkeyvault -vaultname $keyvaultname
$rgvmname = "rg-neu-b-mdmig"
$vm = get-azurermvm -ResourceGroupName $rgvmname -Name "vm1-neu-b-mdmig"
$vmName = $vm.Name

$vm.OSProfile
Add-Azurermvmsecret -VM $vm -sourcevaultid $keyvault.resourceid -certificatestore 'My' -CertificateURL $encryptionCertURI
Update-Azurermvm -resourcegroupname $rgvmname -vm $vm

#Look at what certificates (secrets) are installed on the VM
$vm.OSProfile.Secrets | format-list

#10. Encrypt the VM
$KeyVaultName = "kv-neu-b"
$rgvmName = "rg-neu-b-mdmig"
$kekname = "kek-neu-b"
$appDispName = "kv-b-app"
$diskencryptionvaulturl = "https://kv-neu-b.vault.azure.net/"
$azureADApplication = Get-AzureRMADApplication -DisplayName $appDispName 
$vmName = "vm1-neu-b-mdmig"
$aadClientID = $azureadapplication.applicationid
$kek = get-AzureKeyVaultKey -VaultName $KeyVaultName -Name $kekname 
$keyEncryptionKeyUrl = $kek.key.Kid
Set-AzureRmVMDiskEncryptionExtension -ResourceGroupName $rgvmname -VMName $vmname -AadClientID $aadClientID -AadClientCertThumbprint $Thumbprint -DiskEncryptionKeyVaultUrl $diskencryptionvaulturl -DiskEncryptionKeyVaultId $keyvault.resourceid -KeyEncryptionKeyUrl $keyEncryptionKeyUrl -KeyEncryptionKeyVaultId $keyvault.resourceid

#Check Encryption Status on VM
#Get-azurermvmdiskencryptionstatus -resourcegroup $rgname -vmname $vmname

##############################################################
#Operations
##############################################################

#Export a key
######Get KV#######
$KeyVaultName = "kv-neu-b"
$rgName = "rg-neu-b-kv"
$location = "North Europe"
Get-AzureRmKeyVault -VaultName $KeyVaultName -ResourceGroupName $rgName

######Get All Secrets#######
Get-AzureKeyVaultSecret -vaultname $KeyVaultName

######Get a specific Secrets#######
$secret = Get-AzureKeyVaultSecret -vaultname $KeyVaultName -Name 'E3854410-BF11-45A4-ADAA-83157996D5C5'
$secret.Attributes

