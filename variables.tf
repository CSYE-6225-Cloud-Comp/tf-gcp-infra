variable gcp_credentials_file {
  type = string
}

variable gcp_project {
  type = string
}

variable auto_create_subnetworks {
    type = bool
}

variable routing_mode {
    type = string
}

variable delete_default_routes_on_create {
    type = bool
}

variable subnet-1-name {
    type = string
}

variable subnet-2-name {
    type = string
}

variable vpc_name {
    type = string
}

variable ip_cidr_range_webapp {
    type = string
}

variable ip_cidr_range_db {
    type = string
}

variable zone {
    type = string
}

variable webapp_subnet_description {
    type = string
}

variable db_subnet_description {
    type = string
}

variable private_ip_google_access {
    type = bool
}

variable maximum_transmission_unit {
    type = number
}

variable vpc_description {
    type = string
}

variable internet_gateway_dest_range {
    type = string
}

variable route_name {
    type = string
}

variable enable_ula_internal_ipv6 {
    type = bool
}

variable priority {
    type = number
}

variable region_subnet_1 {
    type = string
}

variable region_subnet_2 {
    type = string
}

variable gcp_region {
    type = string
}

variable default_internet_gateway {
    type = string
}

variable webapp_firewall_rule_name {
    type = string
}

variable ssh_firewall_rule_name_deny {
    type = string
}

variable webapp_protocol {
    type = string
}

variable webapp_ports {
    type = list(string)
}

variable source_ranges {
    type = list(string)
}

variable target_tags {
    type = list(string)
}

variable ssh_protocol {
    type = string
}

variable ssh_ports {
    type = list(string)
}

variable direction {
    type = string
}

variable tags {
    type = list(string)
}

variable auto_delete {
    type = bool
}

variable device_name {
    type = string
}

variable image {
    type = string
}

variable size {
    type = number
}

variable type {
    type = string
}

variable mode {
    type = string
}

variable vm_zone {
    type = string
}

variable machine_type {
    type = string
}

variable vm_name {
    type = string
}

variable can_ip_forward {
    type = bool
}

variable deletion_protection {
    type = bool
}

variable enable_display {
    type = bool
}

variable goog-ec-src {
    type = string
}

variable network_tier {
    type = string
}

variable queue_count {
    type = number
}

variable stack_type {
    type = string
}

variable automatic_restart {
    type = bool
}

variable on_host_maintenance {
    type = string
}

variable preemptible {
    type = bool
}

variable provisioning_model {
    type = string
}

variable email {
    type = string
}

variable scopes {
    type = list(string)
}

variable enable_integrity_monitoring {
    type = bool
}

variable enable_secure_boot {
    type = bool
}

variable enable_vtpm {
    type = bool
}

variable db_deletion_protection {
    type = bool
}

variable availability_type {
    type = string
}

variable disk_type {
    type = string
}

variable disk_size {
    type = number
}

variable ipv4_enabled {
    type = bool
}

variable db_instance_name {
    type = string
}

variable database_version {
    type = string
}

variable db_region {
    type = string
}

variable db_tier {
    type = string
}

variable db_name {
    type = string
}

variable db_user_name {
    type = string
}

variable password_length {
    type = number
}

variable password_special {
    type = bool
}

variable backup_enabled {
    type = bool
}

variable binary_log_enabled {
    type = bool
}

variable firewall_priority {
    type = number
}

variable private_ip_address {
    type = string
}

variable purpose {
    type = string
}

variable address_type {
    type = string
}

variable prefix_length {
    type = number
}

variable suffix_length {
    type = number
}

variable suffix_special {
    type = bool
}

variable suffix_isUpperCase {
    type = bool
}

variable password_override_special {
    type = string
}

variable service {
    type = string
}