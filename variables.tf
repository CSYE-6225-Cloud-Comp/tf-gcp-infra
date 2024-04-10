variable "gcp_credentials_file" {
  type = string
}

variable "gcp_project" {
  type = string
}

variable "auto_create_subnetworks" {
  type = bool
}

variable "routing_mode" {
  type = string
}

variable "delete_default_routes_on_create" {
  type = bool
}

variable "subnet-1-name" {
  type = string
}

variable "subnet-2-name" {
  type = string
}

variable "vpc_name" {
  type = string
}

variable "ip_cidr_range_webapp" {
  type = string
}

variable "ip_cidr_range_db" {
  type = string
}

variable "zone" {
  type = string
}

variable "webapp_subnet_description" {
  type = string
}

variable "db_subnet_description" {
  type = string
}

variable "private_ip_google_access" {
  type = bool
}

variable "maximum_transmission_unit" {
  type = number
}

variable "vpc_description" {
  type = string
}

variable "internet_gateway_dest_range" {
  type = string
}

variable "route_name" {
  type = string
}

variable "enable_ula_internal_ipv6" {
  type = bool
}

variable "priority" {
  type = number
}

variable "region_subnet_1" {
  type = string
}

variable "region_subnet_2" {
  type = string
}

variable "gcp_region" {
  type = string
}

variable "default_internet_gateway" {
  type = string
}

variable "webapp_firewall_rule_name" {
  type = string
}

variable "ssh_firewall_rule_name_deny" {
  type = string
}

variable "webapp_protocol" {
  type = string
}

variable "webapp_ports" {
  type = list(string)
}

variable "source_ranges" {
  type = list(string)
}

variable "target_tags" {
  type = list(string)
}

variable "ssh_protocol" {
  type = string
}

variable "ssh_ports" {
  type = list(string)
}

variable "direction" {
  type = string
}

variable "tags" {
  type = list(string)
}

variable "auto_delete" {
  type = bool
}

variable "device_name" {
  type = string
}

variable "image" {
  type = string
}

variable "size" {
  type = number
}

variable "type" {
  type = string
}

variable "mode" {
  type = string
}

variable "vm_zone" {
  type = string
}

variable "machine_type" {
  type = string
}

variable "vm_name" {
  type = string
}

variable "can_ip_forward" {
  type = bool
}

variable "deletion_protection" {
  type = bool
}

variable "enable_display" {
  type = bool
}

variable "goog-ec-src" {
  type = string
}

variable "network_tier" {
  type = string
}

variable "queue_count" {
  type = number
}

variable "stack_type" {
  type = string
}

variable "automatic_restart" {
  type = bool
}

variable "on_host_maintenance" {
  type = string
}

variable "preemptible" {
  type = bool
}

variable "provisioning_model" {
  type = string
}

variable "email" {
  type = string
}

variable "scopes" {
  type = list(string)
}

variable "enable_integrity_monitoring" {
  type = bool
}

variable "enable_secure_boot" {
  type = bool
}

variable "enable_vtpm" {
  type = bool
}

variable "db_deletion_protection" {
  type = bool
}

variable "availability_type" {
  type = string
}

variable "disk_type" {
  type = string
}

variable "disk_size" {
  type = number
}

variable "ipv4_enabled" {
  type = bool
}

variable "db_instance_name" {
  type = string
}

variable "database_version" {
  type = string
}

variable "db_region" {
  type = string
}

variable "db_tier" {
  type = string
}

variable "db_name" {
  type = string
}

variable "db_user_name" {
  type = string
}

variable "password_length" {
  type = number
}

variable "password_special" {
  type = bool
}

variable "backup_enabled" {
  type = bool
}

variable "binary_log_enabled" {
  type = bool
}

variable "firewall_priority" {
  type = number
}

variable "private_ip_address" {
  type = string
}

variable "purpose" {
  type = string
}

variable "address_type" {
  type = string
}

variable "prefix_length" {
  type = number
}

variable "suffix_length" {
  type = number
}

variable "suffix_special" {
  type = bool
}

variable "suffix_isUpperCase" {
  type = bool
}

variable "password_override_special" {
  type = string
}

variable "service" {
  type = string
}

variable "global_address" {
  type = string
}

variable "service_account_id" {
  type = string
}

variable "service_account_display_name" {
  type = string
}

variable "service_account_description" {
  type = string
}

variable "dns_public_zone_name" {
  type = string
}

variable "dns_record_name" {
  type = string
}

variable "dns_record_type" {
  type = string
}

variable "dns_record_ttl" {
  type = number
}

variable "topic_name" {
  type = string
}

variable "message_retention_duration" {
  type = string
}

variable "subscription_name" {
  type = string
}

variable "cloud_function_name" {
  type = string
}

# variable cloud_function_description {
#   type = string
# }

variable "cloud_function_runtime" {
  type = string
}

variable "cloud_function_location" {
  type = string
}

variable "cloud_function_entry_point" {
  type = string
}

variable "bucket_name" {
  type = string
}

variable "bucket_object" {
  type = string
}

variable "retry_policy" {
  type = string
}

variable "vpc_connector_name" {
  type = string
}

variable "vpc_connector_ip_cidr_range" {
  type = string
}

variable "vpc_connector_region" {
  type = string
}

variable "max_instance_count" {
  type = number
}

variable "private_ip_google_access_db" {
  type = bool
}

variable "autoscaler_cooldown_period" {
  type = number
}

variable "autoscaler_cpu_utilization" {
  type = number
}

variable "autoscaler_min_replicas" {
  type = number
}

variable "autoscaler_max_replicas" {
  type = number
}

variable "instance_template_machine" {
  type = string
}

variable "ingress_source_ranges" {
  type = list(string)
}

variable "load_balancing_region" {
  type = string
}

variable "domains" {
  type = list(string)
}

variable "ssl_certificate_name" {
  type = string
}

variable "instance_template_name" {
  type = string
}

variable "instance_template_mode" {
  type = string
}

variable "instance_template_labels" {
  type = string
}

variable "full_scope" {
  type = list(string)
}

variable "autoscaler_name" {
  type = string
}

variable "health_check_name" {
  type = string
}

variable "forwarding_rule_name" {
  type = string
}

variable "forwarding_rule_ip_protocol" {
  type = string
}

variable "forwarding_rule_port_range" {
  type = string
}

variable "forwarding_load_balancing_scheme" {
  type = string
}

variable "https_proxy_name" {
  type = string
}

variable "url_map_name" {
  type = string
}

variable "backend_service_name" {
  type = string
}

variable "backend_service_connection_draining_timeout_sec" {
  type = number
}

variable "backend_load_balancing_scheme" {
  type = string
}

variable "backend_port_name" {
  type = string
}

variable "backend_protocol" {
  type = string
}

variable "backend_session_affinity" {
  type = string
}

variable "backend_timeout_sec" {
  type = number
}

variable "backend_balancing_mode" {
  type = string
}

variable "backend_capacity_scaler" {
  type = number
}

variable "health_check_check_interval_sec" {
  type = number
}

variable "health_check_healthy_threshold" {
  type = number
}

variable "health_check_port" {
  type = number
}

variable "health_check_request_path" {
  type = string
}

variable "health_check_timeout_sec" {
  type = number
}

variable "health_check_unhealthy_threshold" {
  type = number
}

variable "compute_global_address_name" {
  type = string
}

variable "compute_global_address_name_ip_version" {
  type = string
}

variable "pubsub_publisher_role" {
  type = string
}

variable "instance_template_automatic_template" {
  type = bool
}

variable "instance_template_automatic_template_on_host_maintenance" {
  type = string
}

variable "instance_template_automatic_template_provisioning_model" {
  type = string
}

variable "managed_instance_group_name" {
  type = string
}

variable "managed_instance_named_port_name" {
  type = string
}

variable "managed_instance_named_port_number" {
  type = string
}

variable "managed_instance_group_version_name" {
  type = string
}

variable "base_instance_name" {
  type = string
}

variable "auto_healing_policies_initial_delay_sec" {
  type = number
}

variable "health_check_firewall_name" {
  type = string
}

variable "health_check_firewall_direction" {
  type = string
}

variable "health_check_firewall_priority" {
  type = number
}

variable "health_check_firewall_target_tags" {
  type = list(string)
}

variable "health_check_firewall_allow_port" {
  type = list(string)
}

variable "health_check_firewall_protocol" {
  type = string
}

variable key_ring_name {
  type = string
}

variable "key_ring_location" {
  type = string
}

variable "vm_key_name" {
  type = string
}

variable key_rotation_period {
  type = string
}

variable key_prevent_destroy {
  type = bool
}

variable "sql_instance_key_name" {
  type = string
}

variable "storage_bucket_key_name" {
  type = string
}