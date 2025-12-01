terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.1"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.45"
    }
  }

  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "stterraformstate83160"
    container_name       = "tfstate"
    key                  = "securelandingzone.tfstate"
  }
}

provider "azurerm" {
  features {}
  subscription_id = "fd0adf6a-200d-4cd8-99eb-c9be0c10f5ac"
}

provider "azuread" {}
