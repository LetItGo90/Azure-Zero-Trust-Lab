output "resource_group_name" {
  description = "Name of the main resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_id" {
  description = "ID of the main resource group"
  value       = azurerm_resource_group.main.id
}

output "log_analytics_workspace_id" {
  description = "ID of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.main.id
}

output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace"
  value       = azurerm_log_analytics_workspace.main.name
}
output "hub_vnet_id" {
  description = "ID of the hub virtual network"
  value       = azurerm_virtual_network.hub.id
}

output "hub_vnet_name" {
  description = "Name of the hub virtual network"
  value       = azurerm_virtual_network.hub.name
}

output "firewall_subnet_id" {
  description = "ID of the Azure Firewall subnet"
  value       = azurerm_subnet.firewall.id
}

output "bastion_subnet_id" {
  description = "ID of the Azure Bastion subnet"
  value       = azurerm_subnet.bastion.id
}

output "firewall_id" {
  description = "ID of the Azure Firewall"
  value       = azurerm_firewall.main.id
}

output "firewall_private_ip" {
  description = "Private IP of the Azure Firewall"
  value       = azurerm_firewall.main.ip_configuration[0].private_ip_address
}

output "firewall_public_ip" {
  description = "Public IP of the Azure Firewall"
  value       = azurerm_public_ip.firewall.ip_address
}

output "bastion_id" {
  description = "ID of the Azure Bastion host"
  value       = azurerm_bastion_host.main.id
}

output "bastion_public_ip" {
  description = "Public IP of the Azure Bastion host"
  value       = azurerm_public_ip.bastion.ip_address
}

output "spoke_vnet_id" {
  description = "ID of the spoke VNet"
  value       = azurerm_virtual_network.spoke.id
}

output "workload_subnet_id" {
  description = "ID of the workload subnet"
  value       = azurerm_subnet.workload.id
}

output "key_vault_id" {
  description = "ID of the Key Vault"
  value       = azurerm_key_vault.main.id
}

output "key_vault_name" {
  description = "Name of the Key Vault"
  value       = azurerm_key_vault.main.name
}

output "test_vm_name" {
  description = "Name of the test VM"
  value       = azurerm_linux_virtual_machine.testvm.name
}

output "test_vm_private_ip" {
  description = "Private IP of the test VM"
  value       = azurerm_network_interface.testvm.private_ip_address
}
