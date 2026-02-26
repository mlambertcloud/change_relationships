output "api_base_url" {
  value = aws_apigatewayv2_api.http_api.api_endpoint
}

output "dynamodb_table" {
  value = aws_dynamodb_table.cards.name
}

output "frontend_bucket" {
  value = aws_s3_bucket.frontend.bucket
}

output "cloudfront_domain" {
  value = aws_cloudfront_distribution.frontend.domain_name
}

output "cloudfront_distribution_id" {
  value = aws_cloudfront_distribution.frontend.id
}

output "cognito_user_pool_id" {
  value = aws_cognito_user_pool.users.id
}

output "cognito_user_pool_client_id" {
  value = aws_cognito_user_pool_client.client.id
}

output "cognito_domain" {
  value = aws_cognito_user_pool_domain.domain.domain
}

output "cognito_hosted_ui" {
  value = "https://${aws_cognito_user_pool_domain.domain.domain}.auth.${var.region}.amazoncognito.com"
}
