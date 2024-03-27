#Provider - GCP

provider "google" {
  #credentials = file(var.gcp_credentials_file)
  project = var.gcp_project
  region  = var.gcp_region
}