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

variable region {
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