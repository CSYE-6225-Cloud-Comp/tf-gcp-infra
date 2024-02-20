terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
      version = "5.15.0"
    }
  }
}

# Create a VPC network - Disable auto subnet creation and delete default routes on creation
resource "google_compute_network" "vpc_network" {
    name = var.vpc_name
    description = var.vpc_description
    auto_create_subnetworks = var.auto_create_subnetworks
    routing_mode = var.routing_mode
    delete_default_routes_on_create = var.delete_default_routes_on_create
    enable_ula_internal_ipv6 = var.enable_ula_internal_ipv6
    mtu = var.maximum_transmission_unit
}

# Create two subnets in the VPC network
#Subnet 1 - For webapp. This subnet will have access to internet
resource "google_compute_subnetwork" "vpc_subnet_webapp" {
    name = var.subnet-1-name
    description = var.webapp_subnet_description
    region = var.region_subnet_1
    network = google_compute_network.vpc_network.id
    ip_cidr_range = var.ip_cidr_range_webapp 
    private_ip_google_access = var.private_ip_google_access
}

#Subnet 2 - For DB. This subnet will not have access to internet
resource "google_compute_subnetwork" "vpc_subnet_db" {
    name = var.subnet-2-name 
    description = var.db_subnet_description
    region = var.region_subnet_2
    network = google_compute_network.vpc_network.id
    ip_cidr_range = var.ip_cidr_range_db
    private_ip_google_access = var.private_ip_google_access
}

# Add a route to VPC netwrok to route traffic to internet
resource "google_compute_route" "internet-route" {
    name = var.route_name
    network = google_compute_network.vpc_network.id
    dest_range = var.internet_gateway_dest_range
    priority = var.priority
    next_hop_gateway = var.default_internet_gateway
}