variable "region" {
  type    = string
  default = "eu-west-2"
}

variable "project_name" {
  type    = string
  default = "change-relationship-cards"
}

variable "table_name" {
  type    = string
  default = "change-relationship-cards"
}

variable "cognito_domain_prefix" {
  type    = string
  default = "change-relationship-cards"
}

variable "callback_urls" {
  type    = list(string)
  default = ["http://localhost:5173"]
}

variable "logout_urls" {
  type    = list(string)
  default = ["http://localhost:5173"]
}

variable "frontend_bucket_prefix" {
  type    = string
  default = "change-relationship-frontend"
}
