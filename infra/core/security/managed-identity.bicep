param name string
param location string = resourceGroup().location

resource apiIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: name
  location: location
}

output resourceId string = apiIdentity.id
output tenantId string = apiIdentity.properties.tenantId
output principalId string = apiIdentity.properties.principalId
output clientId string = apiIdentity.properties.clientId
