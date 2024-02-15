# Cloud Native Web Application - Infrastructure Code

### Description
Configuration for creating a VPC, two subnets and a route to access internet

### Requirements
1. Terraform
2. GCP

### Build and Deploy Instructions
1. Clone the respository in your local machine using the `git clone` command.
2. Open a terminal and navigate to the location where the repository is cloned.
3. Run `terraform init`.
4. Run `terraform validate` to check for any syntax errors.
5. Run `terraform plan`. This command will show what resources are changed.
6. Run `terraform apply` to create GCP resources. You can view the created resources on GCP console.
