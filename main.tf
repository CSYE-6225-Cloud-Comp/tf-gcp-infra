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

# Add a firewall rule to deny traffic from internet to ssh port
resource "google_compute_firewall" "deny-ssh-traffic" {
    name = var.ssh_firewall_rule_name_deny
    network = google_compute_network.vpc_network.id
    direction = var.direction
    deny {
        protocol = var.ssh_protocol # TCP
        ports = var.ssh_ports # 22
    }
    source_ranges = var.source_ranges # 0.0.0.0/0
    target_tags = var.target_tags
}

# Add a firewall rule to allow traffic from internet to webapp subnet
resource "google_compute_firewall" "allow-webapp-traffic" {
    name = var.webapp_firewall_rule_name
    network = google_compute_network.vpc_network.id
    direction = var.direction
    priority = var.firewall_priority
    allow {
        protocol = var.webapp_protocol # TCP
        ports = var.webapp_ports # 3000
    }
    source_ranges = var.source_ranges # 0.0.0.0/0
    target_tags = var.target_tags
}

# Configure a VM instance
resource "google_compute_instance" "webapp" {
  boot_disk {
    auto_delete = var.auto_delete
    device_name = var.device_name

    initialize_params {
      image = var.image
      size  = var.size
      type  = var.type
    }

    mode = var.mode
  }

  can_ip_forward      = var.can_ip_forward
  deletion_protection = var.deletion_protection
  enable_display      = var.enable_display

  labels = {
    goog-ec-src = var.goog-ec-src
  }

  machine_type = var.machine_type
  name         = var.vm_name

  network_interface {
    network = google_compute_network.vpc_network.name
    access_config {
      network_tier = var.network_tier
    }

    queue_count = var.queue_count
    stack_type  = var.stack_type
    subnetwork  = google_compute_subnetwork.vpc_subnet_webapp.name
  }

  scheduling {
    automatic_restart   = var.automatic_restart
    on_host_maintenance = var.on_host_maintenance
    preemptible         = var.preemptible
    provisioning_model  = var.provisioning_model
  }

  service_account {
    email  = var.email
    scopes = var.scopes
  }

  shielded_instance_config {
    enable_integrity_monitoring = var.enable_integrity_monitoring
    enable_secure_boot          = var.enable_secure_boot
    enable_vtpm                 = var.enable_vtpm
  }

  zone = var.vm_zone
  tags = var.tags

  metadata_startup_script = <<-EOT
      #!/bin/bash
      cd /opt/webapp
      touch .env
      echo DB_HOST=${google_sql_database_instance.webapp-db-instance.private_ip_address} >> .env
      echo DB_PORT=3306 >> .env
      echo DB_USER=${google_sql_user.webapp-db-user.name} >> .env
      echo DB_PASSWORD=${random_password.password.result} >> .env
      echo DB_SCHEMA=${google_sql_database.webapp-db.name} >> .env
      echo DB_TIMEZONE=-05:00 >> .env
      echo PORT=3000 >> .env
      cat .env

      EOT
}

# Create a database instance
resource "google_sql_database_instance" "webapp-db-instance" {
  name             = "${var.db_instance_name}-${random_string.db_instance_suffix.result}"
  database_version = var.database_version
  region           = var.db_region
  deletion_protection = var.db_deletion_protection

  depends_on = [google_service_networking_connection.default]

  settings {
    # Second-generation instance tiers are based on the machine
    # type. See argument reference below.
    tier = var.db_tier
    availability_type = var.availability_type
    disk_type = var.disk_type
    disk_size = var.disk_size

    ip_configuration {
      ipv4_enabled    = var.ipv4_enabled
      private_network = google_compute_network.vpc_network.id
    }

    backup_configuration {
      enabled = var.backup_enabled
      binary_log_enabled = var.binary_log_enabled
    }

  }
}

# Create a database
resource "google_sql_database" "webapp-db" {
  name     = "${var.db_name}-${random_string.db_suffix.result}"
  instance = google_sql_database_instance.webapp-db-instance.name
}

# Create a database user
resource "google_sql_user" "webapp-db-user" {
  name     = "${var.db_user_name}-${random_string.db_user_suffix.result}"
  instance = google_sql_database_instance.webapp-db-instance.name
  password = random_password.password.result
}

resource "google_compute_global_address" "private_ip_address" {
  name          = "private-ip-address"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.vpc_network.id
}

resource "google_service_networking_connection" "default" {
  network                 = google_compute_network.vpc_network.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_address.name]
}


# Create a random password for the database user
resource "random_password" "password" {
  length           = var.password_length
  special          = var.password_special
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# Create a random suffix for the database instance
resource "random_string" "db_instance_suffix" {
  length  = 4
  special = false
  upper = false
}

# Create a random suffix for the database user
resource "random_string" "db_user_suffix" {
  length  = 4
  special = false
  upper = false
}

# Create a random suffix for the database
resource "random_string" "db_suffix" {
  length  = 4
  special = false
  upper = false
}




