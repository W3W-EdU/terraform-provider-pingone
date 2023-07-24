data "pingone_digital_wallet_application" "example_by_id" {
  environment_id    = var.environment_id
  digital_wallet_id = var.application_id
}

data "pingone_digital_wallet_application" "example_by_digital_wallet_name" {
  environment_id = var.environment_id
  name           = "foo"
}

data "pingone_digital_wallet_application" "example_by_application_id" {
  environment_id = var.environment_id
  application_id = var.application_id
}

