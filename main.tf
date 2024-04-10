terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "5.15.0"
    }
  }
}

# Create a service account which is used by the compute instance
resource "google_service_account" "service_account" {
  account_id   = var.service_account_id
  display_name = var.service_account_display_name
  description  = var.service_account_description
  project      = var.gcp_project
}

# Bind IAM Role to the service account - Logging Admin role
resource "google_project_iam_binding" "logging_admin" {
  project = var.gcp_project
  role    = "roles/logging.admin"

  members = [
    "serviceAccount:${google_service_account.service_account.email}",
  ]
}

# Bind IAM Role to the service account - Monitoring Metric Writer Role
resource "google_project_iam_binding" "metric_writer" {
  project = var.gcp_project
  role    = "roles/monitoring.metricWriter"

  members = [
    "serviceAccount:${google_service_account.service_account.email}",
  ]
}

# Add an A record to the public zone created in GCP through GCP Console
resource "google_dns_record_set" "default" {
  managed_zone = var.dns_public_zone_name
  name         = var.dns_record_name
  type         = var.dns_record_type
  # rrdatas      = [google_compute_instance.webapp.network_interface[0].access_config[0].nat_ip]
  rrdatas = [google_compute_global_address.compute_global_address.address]
  ttl     = var.dns_record_ttl
  # depends_on   = [google_compute_instance.webapp]
  # depends_on = [google_compute_instance_template.instance_template]
}

# Create a VPC network - Disable auto subnet creation and delete default routes on creation
resource "google_compute_network" "vpc_network" {
  name                            = var.vpc_name
  description                     = var.vpc_description
  auto_create_subnetworks         = var.auto_create_subnetworks
  routing_mode                    = var.routing_mode
  delete_default_routes_on_create = var.delete_default_routes_on_create
  enable_ula_internal_ipv6        = var.enable_ula_internal_ipv6
  mtu                             = var.maximum_transmission_unit
}

# Create two subnets in the VPC network
#Subnet 1 - For webapp. This subnet will have access to internet
resource "google_compute_subnetwork" "vpc_subnet_webapp" {
  name                     = var.subnet-1-name
  description              = var.webapp_subnet_description
  region                   = var.region_subnet_1
  network                  = google_compute_network.vpc_network.id
  ip_cidr_range            = var.ip_cidr_range_webapp
  private_ip_google_access = var.private_ip_google_access
}

#Subnet 2 - For DB. This subnet will not have access to internet
resource "google_compute_subnetwork" "vpc_subnet_db" {
  name                     = var.subnet-2-name
  description              = var.db_subnet_description
  region                   = var.region_subnet_2
  network                  = google_compute_network.vpc_network.id
  ip_cidr_range            = var.ip_cidr_range_db
  private_ip_google_access = var.private_ip_google_access_db
}

# Add a route to VPC netwrok to route traffic to internet
resource "google_compute_route" "internet-route" {
  name             = var.route_name
  network          = google_compute_network.vpc_network.id
  dest_range       = var.internet_gateway_dest_range
  priority         = var.priority
  next_hop_gateway = var.default_internet_gateway
}

# Add a firewall rule to deny traffic from internet to ssh port
resource "google_compute_firewall" "deny-ssh-traffic" {
  name      = var.ssh_firewall_rule_name_deny
  network   = google_compute_network.vpc_network.id
  direction = var.direction
  deny {
    protocol = var.ssh_protocol # TCP
    ports    = var.ssh_ports    # 22
  }
  source_ranges = var.source_ranges # 0.0.0.0/0
  target_tags   = var.target_tags
}

# Add a firewall rule to allow traffic from internet to ssh port
resource "google_compute_firewall" "allow-ssh-traffic" {
  name      = "allow-ssh-traffic"
  network   = google_compute_network.vpc_network.id
  direction = var.direction
  allow {
    protocol = var.ssh_protocol # TCP
    ports    = ["22"]   # 22
  }
  source_ranges = var.source_ranges #
  target_tags = ["allow-ssh-traffic"]
  
}


# Add a firewall rule to allow traffic from internet to webapp subnet
resource "google_compute_firewall" "allow-webapp-traffic" {
  name      = var.webapp_firewall_rule_name
  network   = google_compute_network.vpc_network.id
  direction = var.direction
  priority  = var.firewall_priority
  allow {
    protocol = var.webapp_protocol # TCP
    ports    = var.webapp_ports    # 3000
  }
  # source_ranges = var.source_ranges # 0.0.0.0/0
  source_ranges = var.ingress_source_ranges
  target_tags   = var.target_tags
}

# Configure a VM instance
# resource "google_compute_instance" "webapp" {
#   depends_on = [google_service_account.service_account, google_project_iam_binding.logging_admin, google_project_iam_binding.metric_writer]
#   boot_disk {
#     auto_delete = var.auto_delete
#     device_name = var.device_name

#     initialize_params {
#       image = var.image
#       size  = var.size
#       type  = var.type
#     }

#     mode = var.mode
#   }

#   can_ip_forward      = var.can_ip_forward
#   deletion_protection = var.deletion_protection
#   enable_display      = var.enable_display

#   labels = {
#     goog-ec-src = var.goog-ec-src
#   }

#   machine_type = var.machine_type
#   name         = var.vm_name

#   network_interface {
#     network = google_compute_network.vpc_network.name
#     access_config {
#       network_tier = var.network_tier
#     }

#     queue_count = var.queue_count
#     stack_type  = var.stack_type
#     subnetwork  = google_compute_subnetwork.vpc_subnet_webapp.name
#   }

#   scheduling {
#     automatic_restart   = var.automatic_restart
#     on_host_maintenance = var.on_host_maintenance
#     preemptible         = var.preemptible
#     provisioning_model  = var.provisioning_model
#   }

#   service_account {
#     email  = google_service_account.service_account.email
#     scopes = var.scopes
#   }

#   shielded_instance_config {
#     enable_integrity_monitoring = var.enable_integrity_monitoring
#     enable_secure_boot          = var.enable_secure_boot
#     enable_vtpm                 = var.enable_vtpm
#   }

#   zone = var.vm_zone
#   tags = var.tags

#   metadata = {
#     startup-script = <<-EOT
#       #!/bin/bash
#       cd /opt/webapp

#       if [ ! -f /opt/webapp/.env ]; then
#           touch /opt/webapp/.env
#           echo DB_HOST=${google_sql_database_instance.webapp-db-instance.private_ip_address} >> .env
#           echo DB_PORT=3306 >> .env
#           echo DB_USER=${google_sql_user.webapp-db-user.name} >> .env
#           echo DB_PASSWORD=${random_password.password.result} >> .env
#           echo DB_SCHEMA=${google_sql_database.webapp-db.name} >> .env
#           echo DB_TIMEZONE=-05:00 >> .env
#           echo PORT=3000 >> .env
#           echo TOPIC_NAME=${google_pubsub_topic.topic.name} >> .env
#           cat .env
#       else 
#         if [ ! -s /opt/webapp/.env ]; then
#           echo DB_HOST=${google_sql_database_instance.webapp-db-instance.private_ip_address} >> .env
#           echo DB_PORT=3306 >> .env
#           echo DB_USER=${google_sql_user.webapp-db-user.name} >> .env
#           echo DB_PASSWORD=${random_password.password.result} >> .env
#           echo DB_SCHEMA=${google_sql_database.webapp-db.name} >> .env
#           echo DB_TIMEZONE=-05:00 >> .env
#           echo PORT=3000 >> .env
#           echo TOPIC_NAME=${google_pubsub_topic.topic.name} >> .env
#           cat .env
#         fi
#       fi

#       EOT
#   }

#   # metadata_startup_script = 
# }

# Create a database instance
resource "google_sql_database_instance" "webapp-db-instance" {
  name                = "${var.db_instance_name}-${random_string.db_instance_suffix.result}"
  database_version    = var.database_version
  region              = var.db_region
  deletion_protection = var.db_deletion_protection

  depends_on = [google_service_networking_connection.default]

  settings {
    # Second-generation instance tiers are based on the machine
    # type. See argument reference below.
    tier              = var.db_tier
    availability_type = var.availability_type
    disk_type         = var.disk_type
    disk_size         = var.disk_size

    ip_configuration {
      ipv4_enabled    = var.ipv4_enabled
      private_network = google_compute_network.vpc_network.id
    }

    backup_configuration {
      enabled            = var.backup_enabled
      binary_log_enabled = var.binary_log_enabled
    }
  }

  # encryption_key_name = google_kms_crypto_key.sql-instance-key.id
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

# Create a private connection
resource "google_compute_global_address" "private_ip_address" {
  name          = var.private_ip_address
  purpose       = var.purpose
  address_type  = var.address_type
  prefix_length = var.prefix_length
  network       = google_compute_network.vpc_network.id
  address       = var.global_address
}

resource "google_service_networking_connection" "default" {
  network                 = google_compute_network.vpc_network.id
  service                 = var.service
  reserved_peering_ranges = [google_compute_global_address.private_ip_address.name]
}

# Create a random password for the database user
resource "random_password" "password" {
  length           = var.password_length
  special          = var.password_special
  override_special = var.password_override_special
}

# Create a random suffix for the database instance
resource "random_string" "db_instance_suffix" {
  length  = var.suffix_length
  special = var.suffix_special
  upper   = var.suffix_isUpperCase
}

# Create a random suffix for the database user
resource "random_string" "db_user_suffix" {
  length  = var.suffix_length
  special = var.suffix_special
  upper   = var.suffix_isUpperCase
}

# Create a random suffix for the database
resource "random_string" "db_suffix" {
  length  = var.suffix_length
  special = var.suffix_special
  upper   = var.suffix_isUpperCase
}

# Create a Pub/Sub topic
resource "google_pubsub_topic" "topic" {
  name                       = var.topic_name
  message_retention_duration = var.message_retention_duration
}

# Create a Pub/Sub subscription
resource "google_pubsub_subscription" "subscription" {
  name                       = var.subscription_name
  topic                      = google_pubsub_topic.topic.id
  message_retention_duration = var.message_retention_duration
}

# Create a Cloud Function
resource "google_cloudfunctions2_function" "cloud_function" {
  name     = var.cloud_function_name
  location = var.cloud_function_location

  build_config {
    runtime     = var.cloud_function_runtime
    entry_point = var.cloud_function_entry_point # Set the entry point 
    source {
      storage_source {
        bucket = var.bucket_name
        object = var.bucket_object
      }
    }
  }

  service_config {
    environment_variables = {
      DB_HOST     = google_sql_database_instance.webapp-db-instance.private_ip_address
      DB_USER     = google_sql_user.webapp-db-user.name
      DB_PASSWORD = random_password.password.result
      DB_DIALECT  = "mysql"
      DB_PORT     = "3306"
      DB_SCHEMA   = google_sql_database.webapp-db.name
      DB_TIMEZONE = "-05:00"
      # PORT = "3000"
      TOPIC_NAME = google_pubsub_topic.topic.name
    }

    max_instance_count = var.max_instance_count

    vpc_connector = google_vpc_access_connector.vpc_connector.name
  }

  event_trigger {
    event_type   = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic = google_pubsub_topic.topic.id
    retry_policy = var.retry_policy
  }
}


# IAM binding for the Pub/Sub topics
resource "google_pubsub_topic_iam_binding" "topic_binding" {
  project = var.gcp_project
  topic   = google_pubsub_topic.topic.name
  role    = var.pubsub_publisher_role
  members = [
    "serviceAccount:${google_service_account.service_account.email}",
  ]
}

# # IAM binding for the Cloud Function    
# resource "google_cloudfunctions2_function_iam_binding" "binding" {
#   project = "tf-gcp-infra"
#   location = google_cloudfunctions2_function.cloud_function.location
#   cloud_function = google_cloudfunctions2_function.cloud_function.name
#   role = "roles/viewer"
#   members = [
#     "serviceAccount:${google_service_account.service_account.email}",
#   ]
# }

# IAM binding for the subscription
# resource "google_pubsub_subscription_iam_binding" "subscription_binding" {
#   project = "tf-gcp-infra"
#   subscription = google_pubsub_subscription.subscription.name
#   role = "roles/pubsub.subscriber"
#   members = [
#     "serviceAccount:${google_service_account.service_account.email}",
#   ]
# }

# Create a VPC Access Connector
resource "google_vpc_access_connector" "vpc_connector" {
  name          = var.vpc_connector_name
  ip_cidr_range = var.vpc_connector_ip_cidr_range
  network       = google_compute_network.vpc_network.name
  region        = var.vpc_connector_region
}

# # Create a google compute engine instance template
# resource "google_compute_region_instance_template" "template" {
#   depends_on = [google_service_account.service_account, google_project_iam_binding.logging_admin, google_project_iam_binding.metric_writer]
#   disk {
#     source_image = var.image
#     auto_delete = var.auto_delete
#     device_name = var.device_name
#     disk_size_gb = var.size
#     disk_type = var.type

#     # initialize_params {
#     #   image = var.image
#     #   size  = var.size
#     #   type  = var.type
#     # }

#     mode = var.mode
#   }

#   can_ip_forward      = var.can_ip_forward

#   labels = {
#     goog-ec-src = var.goog-ec-src
#   }

#   machine_type = var.machine_type
#   name         = var.vm_name

#   network_interface {
#     network = google_compute_network.vpc_network.name
#     access_config {
#       network_tier = var.network_tier
#     }

#     queue_count = var.queue_count
#     stack_type  = var.stack_type
#     subnetwork  = google_compute_subnetwork.vpc_subnet_webapp.name
#   }

#   scheduling {
#     automatic_restart   = var.automatic_restart
#     on_host_maintenance = var.on_host_maintenance
#     preemptible         = var.preemptible
#     provisioning_model  = var.provisioning_model
#   }

#   service_account {
#     email  = google_service_account.service_account.email
#     scopes = var.scopes
#   }

#   shielded_instance_config {
#     enable_integrity_monitoring = var.enable_integrity_monitoring
#     enable_secure_boot          = var.enable_secure_boot
#     enable_vtpm                 = var.enable_vtpm
#   }

#   tags = var.tags

#   metadata = {
#     startup-script = <<-EOT
#       #!/bin/bash
#       cd /opt/webapp

#       if [ ! -f /opt/webapp/.env ]; then
#           touch /opt/webapp/.env
#           echo DB_HOST=${google_sql_database_instance.webapp-db-instance.private_ip_address} >> .env
#           echo DB_PORT=3306 >> .env
#           echo DB_USER=${google_sql_user.webapp-db-user.name} >> .env
#           echo DB_PASSWORD=${random_password.password.result} >> .env
#           echo DB_SCHEMA=${google_sql_database.webapp-db.name} >> .env
#           echo DB_TIMEZONE=-05:00 >> .env
#           echo PORT=3000 >> .env
#           echo TOPIC_NAME=${google_pubsub_topic.topic.name} >> .env
#           cat .env
#       else 
#         if [ ! -s /opt/webapp/.env ]; then
#           echo DB_HOST=${google_sql_database_instance.webapp-db-instance.private_ip_address} >> .env
#           echo DB_PORT=3306 >> .env
#           echo DB_USER=${google_sql_user.webapp-db-user.name} >> .env
#           echo DB_PASSWORD=${random_password.password.result} >> .env
#           echo DB_SCHEMA=${google_sql_database.webapp-db.name} >> .env
#           echo DB_TIMEZONE=-05:00 >> .env
#           echo PORT=3000 >> .env
#           echo TOPIC_NAME=${google_pubsub_topic.topic.name} >> .env
#           cat .env
#         fi
#       fi

#       EOT
#   }
# }

# # Create a health check
# resource "google_compute_health_check" "db_health_check" {
#   name = "db-health-check"

#   https_health_check {
#     request_path = "/healthz"
#     port = "3000"
#   }
# }

# # Create a compute region autoscaler
# resource "google_compute_region_autoscaler" "autoscaler" {
#   name   = "my-autoscaler"
#   region = "us-central1"
#   target = google_compute_region_instance_group_manager.instance_group_manager.id

#   autoscaling_policy {
#     max_replicas    = 5
#     min_replicas    = 1
#     cooldown_period = 60

#     cpu_utilization {
#       target = 0.5
#     }
#   }
# }

# # Create a compute instance group manager
# resource "google_compute_region_instance_group_manager" "instance_group_manager" {
#   name = "webapp-instance-group-manager"
#   base_instance_name = "webapp-instance"
#   region = "us-central1"
#   distribution_policy_zones = []

#   version {
#     instance_template = google_compute_region_instance_template.template.self_link_unique
#   }

#   all_instances_config {

#   }

#   named_port {
#     name = "http"
#     port = 80
#   }
# }

# # Create a proxy-only subnet
# resource "google_compute_subnetwork" "proxy_only" {
#   name                     = "proxy-only-subnet"
#   region                   = "us-central1"
#   network                  = google_compute_network.vpc_network.id
#   ip_cidr_range            = "10.129.0.0/23"
#   purpose = "REGIONAL_MANAGED_PROXY"
# }

# # Create a subnet for backend instances
# resource "google_compute_subnetwork" "backend" {
#   name                     = "backend-subnet"
#   region                   = "us-central1"
#   network                  = google_compute_network.vpc_network.id
#   ip_cidr_range            = "192.168.3.0"
# }

# # Create a firewall rule to allow health check traffic
# resource "google_compute_firewall" "default" {
#   name = "fw-allow-health-check"
#   allow {
#     protocol = "tcp"
#   }
#   direction     = "INGRESS"
#   network       = google_compute_network.vpc_network.id
#   priority      = 1000
#   source_ranges = ["130.211.0.0/22", "35.191.0.0/16"]
#   target_tags   = ["load-balanced-backend"]
# }

# # Create a firewall rule to allow traffic to the proxy-only subnet
# resource "google_compute_firewall" "allow_proxy" {
#   name = "fw-allow-proxies"
#   allow {
#     ports    = ["443"]
#     protocol = "tcp"
#   }
#   allow {
#     ports    = ["80"]
#     protocol = "tcp"
#   }
#   allow {
#     ports    = ["8080"]
#     protocol = "tcp"
#   }
#   direction     = "INGRESS"
#   network       = google_compute_network.vpc_network.id
#   priority      = 1000
#   source_ranges = ["10.129.0.0/23"]
#   target_tags   = ["load-balanced-backend"]
# }

# resource "google_compute_address" "load_balancer_ip" {
#   name         = "address-name"
#   address_type = "EXTERNAL"
#   network_tier = "STANDARD"
#   region       = "us-west1"
# }

# resource "google_compute_region_backend_service" "backend_service" {
#   name = "backend-service"
#   region = "us-west1"
#   protocol = "HTTP"
#   timeout_sec = 10
#   port_name = "http"
#   health_checks = [google_compute_health_check.db_health_check.id]
#   backend {
#     group = google_compute_region_instance_group_manager.instance_group_manager.instance_group
#   }
# }

# resource "google_compute_region_url_map" "url_map" {
#   name = "url-map"
#   region = "us-west1"
#   default_service = google_compute_region_backend_service.backend_service.id
# }

# resource "google_compute_forwarding_rule" "forwarding_rule" {
#   name = "forwarding-rule"
#   region = "us-west1"
#   load_balancing_scheme = "EXTERNAL"
#   ip_address = google_compute_address.load_balancer_ip.address
#   port_range = "80"
#   target = google_compute_region_url_map.url_map.id
# }

# Create a managed SSL certificate
resource "google_compute_managed_ssl_certificate" "lb_default" {
  project  = var.gcp_project
  provider = google-beta
  name     = var.ssl_certificate_name

  managed {
    domains = var.domains
  }
}

# Create a compute instance template
resource "google_compute_region_instance_template" "instance_template" {
  name = var.instance_template_name
  disk {
    auto_delete = true
    boot        = true
    # device_name  = "persistent-disk-0"
    mode         = var.instance_template_mode
    source_image = var.image
    type         = var.type
    disk_size_gb = var.size

    # disk_encryption_key {
    #   kms_key_self_link = google_kms_crypto_key.vm-key.id
    # }
  }
  labels = {
    managed-by-cnrm = var.instance_template_labels
  }
  machine_type = var.instance_template_machine
  metadata = {
    DB_HOST     = google_sql_database_instance.webapp-db-instance.private_ip_address,
    DB_PORT     = "3306",
    DB_USER     = google_sql_user.webapp-db-user.name,
    DB_PASSWORD = random_password.password.result,
    DB_SCHEMA   = google_sql_database.webapp-db.name,
    DB_TIMEZONE = "-05:00",
    PORT        = "3000",
    startup-script = <<-EOT
      #!/bin/bash
      cd /opt/webapp

      if [ ! -f /opt/webapp/.env ]; then
          touch /opt/webapp/.env
          echo DB_HOST=${google_sql_database_instance.webapp-db-instance.private_ip_address} >> .env
          echo DB_PORT=3306 >> .env
          echo DB_USER=${google_sql_user.webapp-db-user.name} >> .env
          echo DB_PASSWORD=${random_password.password.result} >> .env
          echo DB_SCHEMA=${google_sql_database.webapp-db.name} >> .env
          echo DB_TIMEZONE=-05:00 >> .env
          echo PORT=3000 >> .env
          echo TOPIC_NAME=${google_pubsub_topic.topic.name} >> .env
          cat .env
      else 
        if [ ! -s /opt/webapp/.env ]; then
          echo DB_HOST=${google_sql_database_instance.webapp-db-instance.private_ip_address} >> .env
          echo DB_PORT=3306 >> .env
          echo DB_USER=${google_sql_user.webapp-db-user.name} >> .env
          echo DB_PASSWORD=${random_password.password.result} >> .env
          echo DB_SCHEMA=${google_sql_database.webapp-db.name} >> .env
          echo DB_TIMEZONE=-05:00 >> .env
          echo PORT=3000 >> .env
          echo TOPIC_NAME=${google_pubsub_topic.topic.name} >> .env
          cat .env
        fi
      fi

      EOT
  }

  network_interface {
    access_config {
      network_tier = var.network_tier
    }
    network    = google_compute_network.vpc_network.name
    subnetwork = google_compute_subnetwork.vpc_subnet_webapp.name
  }
  region = var.load_balancing_region
  scheduling {
    automatic_restart   = var.instance_template_automatic_template
    on_host_maintenance = var.instance_template_automatic_template_on_host_maintenance
    provisioning_model  = var.instance_template_automatic_template_provisioning_model
  }
  service_account {
    email  = google_service_account.service_account.email
    scopes = var.full_scope
  }
  tags = var.tags
}

# Create a managed instance group
resource "google_compute_region_instance_group_manager" "managed_instance_group" {
  name   = var.managed_instance_group_name
  region = var.load_balancing_region
  # zone = "us-east1-b"
  named_port {
    name = var.managed_instance_named_port_name
    port = var.managed_instance_named_port_number
  }
  version {
    instance_template = google_compute_region_instance_template.instance_template.id
    name              = var.managed_instance_group_version_name
  }
  base_instance_name = var.base_instance_name
  # target_size        = 2

  auto_healing_policies {
    initial_delay_sec = var.auto_healing_policies_initial_delay_sec
    health_check      = google_compute_health_check.db_health_check.id
  }

}

# Create a firewall rule to allow traffic to the instances
resource "google_compute_firewall" "default" {
  name          = var.health_check_firewall_name
  direction     = var.health_check_firewall_direction
  network       = google_compute_network.vpc_network.name
  priority      = var.health_check_firewall_priority
  source_ranges = var.ingress_source_ranges
  target_tags   = var.health_check_firewall_target_tags
  allow {
    ports    = var.health_check_firewall_allow_port
    protocol = var.health_check_firewall_protocol
  }
}

resource "google_compute_global_address" "compute_global_address" {
  name       = var.compute_global_address_name
  ip_version = var.compute_global_address_name_ip_version
  project    = var.gcp_project
}

# Health Check
resource "google_compute_health_check" "db_health_check" {
  name               = var.health_check_name
  check_interval_sec = var.health_check_check_interval_sec
  healthy_threshold  = var.health_check_healthy_threshold

  http_health_check {
    port         = var.health_check_port
    request_path = var.health_check_request_path
  }

  timeout_sec         = var.health_check_timeout_sec
  unhealthy_threshold = var.health_check_unhealthy_threshold
}

# Backend Service
resource "google_compute_backend_service" "backend_service" {
  name                            = var.backend_service_name
  connection_draining_timeout_sec = var.backend_service_connection_draining_timeout_sec
  health_checks                   = [google_compute_health_check.db_health_check.id]
  load_balancing_scheme           = var.backend_load_balancing_scheme
  port_name                       = var.backend_port_name
  protocol                        = var.backend_protocol
  session_affinity                = var.backend_session_affinity
  timeout_sec                     = var.backend_timeout_sec
  backend {
    group           = google_compute_region_instance_group_manager.managed_instance_group.instance_group
    balancing_mode  = var.backend_balancing_mode
    capacity_scaler = var.backend_capacity_scaler
  }
}

# URL Map
resource "google_compute_url_map" "url_map" {
  name            = var.url_map_name
  default_service = google_compute_backend_service.backend_service.id
}

# resource "google_compute_target_http_proxy" "http_proxy" {
#   name    = "http-lb-proxy"
#   url_map = google_compute_url_map.url_map.id
# }

resource "google_compute_target_https_proxy" "https_proxy" {
  name             = var.https_proxy_name
  url_map          = google_compute_url_map.url_map.id
  ssl_certificates = [google_compute_managed_ssl_certificate.lb_default.id]
}

resource "google_compute_global_forwarding_rule" "forwarding_rule" {
  name                  = var.forwarding_rule_name
  ip_protocol           = var.forwarding_rule_ip_protocol
  load_balancing_scheme = var.forwarding_load_balancing_scheme
  port_range            = var.forwarding_rule_port_range
  target                = google_compute_target_https_proxy.https_proxy.id
  ip_address            = google_compute_global_address.compute_global_address.id
}

# Autoscaler
resource "google_compute_region_autoscaler" "auto_scaler" {
  project  = var.gcp_project
  provider = google-beta

  name = var.autoscaler_name
  # zone   = "us-central1-f"
  region = var.load_balancing_region
  target = google_compute_region_instance_group_manager.managed_instance_group.id

  autoscaling_policy {
    max_replicas    = var.autoscaler_max_replicas
    min_replicas    = var.autoscaler_min_replicas
    cooldown_period = var.autoscaler_cooldown_period

    cpu_utilization {
      target = var.autoscaler_cpu_utilization
    }
  }
}

# Create a secret for db private ip address
resource "google_secret_manager_secret" "db_ip" {
  secret_id = "db_ip"

  replication {
    auto {
      
    }
  }
}

# Store the value of the secret in the secret version
resource "google_secret_manager_secret_version" "db_ip_secret_version" {
  secret = google_secret_manager_secret.db_ip.name
  secret_data = google_sql_database_instance.webapp-db-instance.private_ip_address
}

# db user secret
resource "google_secret_manager_secret" "db_user" {
  secret_id = "db_user"

  replication {
    auto {
      
    }
  }
}

# db user secret version
resource "google_secret_manager_secret_version" "db_user_secret_version" {
  secret = google_secret_manager_secret.db_user.name
  secret_data = google_sql_user.webapp-db-user.name
}

# db password secret
resource "google_secret_manager_secret" "db_password" {
  secret_id = "db_password"

  replication {
    auto {
      
    }
  }
}

# db password secret version
resource "google_secret_manager_secret_version" "db_password_secret_version" {
  secret = google_secret_manager_secret.db_password.name
  secret_data = random_password.password.result
}

# db schema secret
resource "google_secret_manager_secret" "db_schema" {
  secret_id = "db_schema"

  replication {
    auto {
      
    }
  }
}

# db schema secret version
resource "google_secret_manager_secret_version" "db_schema_secret_version" {
  secret = google_secret_manager_secret.db_schema.name
  secret_data = google_sql_database.webapp-db.name
}

# # Create a key ring
# resource "google_kms_key_ring" "keyring" {
#   name     = "${var.key_ring_name}-${random_string.keys.result}"
#   location = var.key_ring_location
# }

# # Create a random suffix for the key ring and keys
# resource "random_string" "keys" {
#   length  = var.suffix_length
#   special = var.suffix_special
#   upper   = var.suffix_isUpperCase
# }

# # Create a key for VM
# resource "google_kms_crypto_key" "vm-key" {
#   name            = "${var.vm_key_name}-${random_string.keys.result}"
#   key_ring        = google_kms_key_ring.keyring.id
#   rotation_period = var.key_rotation_period

#   lifecycle {
#     prevent_destroy = false
#   }
# }

# # Create a key for SQL instance
# resource "google_kms_crypto_key" "sql-instance-key" {
#   name            = "${var.sql_instance_key_name}-${random_string.keys.result}"
#   key_ring        = google_kms_key_ring.keyring.id
#   rotation_period = var.key_rotation_period

#   lifecycle {
#     prevent_destroy = false
#   }
# }

# # Create a key for Storage Bucket
# resource "google_kms_crypto_key" "storage-bucket-key" {
#   name            = "${var.storage_bucket_key_name}-${random_string.keys.result}"
#   key_ring        = google_kms_key_ring.keyring.id
#   rotation_period = var.key_rotation_period

#   lifecycle {
#     prevent_destroy = false
#   }
# }

# # Storage Bucket resource
# resource "google_storage_bucket" "bucket" {
#   name          = "cloud-serverless-bucket"
#   location = "us-east1"
#   encryption {
#     default_kms_key_name = google_kms_crypto_key.storage-bucket-key.id
#   }
# }

# data "google_storage_project_service_account" "gcs_account" {
# }

# # Storage bucket key binding
# resource "google_kms_crypto_key_iam_binding" "bucket_crypto_key_binding" {
#   crypto_key_id = google_kms_crypto_key.storage-bucket-key.id
#   role          = "roles/cloudkms.cryptoKeyEncrypter"
  
#   members = [
#     "serviceAccount:${data.google_storage_project_service_account.gcs_account.email_address}"
#   ]
# }

# # VM key binding
# resource "google_kms_crypto_key_iam_binding" "vm_crypto_key_binding" {
#   crypto_key_id = google_kms_crypto_key.vm-key.id
#   role          = "roles/cloudkms.cryptoKeyEncrypter"

#   members = [
#     "serviceAccount:1007110371311-compute@developer.gserviceaccount.com",
#   ]
# }

# resource "google_project_service_identity" "gcp_sa_cloud_sql" {
#   project = var.gcp_project
#   provider = google-beta
#   service  = "sqladmin.googleapis.com"
# }

# # SQL instance key binding
# resource "google_kms_crypto_key_iam_binding" "sql_crypto_key_binding" {
#   crypto_key_id = google_kms_crypto_key.sql-instance-key.id
#   role          = "roles/cloudkms.cryptoKeyEncrypter"

#   members = [
#     "serviceAccount:${google_project_service_identity.gcp_sa_cloud_sql.email}",
#   ]
# }



