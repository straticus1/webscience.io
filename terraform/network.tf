# VCN for WebScience
resource "oci_core_vcn" "webscience_vcn" {
  compartment_id = var.compartment_id
  cidr_blocks    = ["10.20.0.0/16"]
  display_name   = "webscience-vcn"
  dns_label      = "webscience"
}

# Internet Gateway
resource "oci_core_internet_gateway" "webscience_igw" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.webscience_vcn.id
  display_name   = "webscience-igw"
  enabled        = true
}

# Route Table
resource "oci_core_route_table" "webscience_rt" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.webscience_vcn.id
  display_name   = "webscience-rt"

  route_rules {
    network_entity_id = oci_core_internet_gateway.webscience_igw.id
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
  }
}

# Security List
resource "oci_core_security_list" "webscience_sl" {
  compartment_id = var.compartment_id
  vcn_id         = oci_core_vcn.webscience_vcn.id
  display_name   = "webscience-sl"

  # Egress - Allow all outbound
  egress_security_rules {
    protocol    = "all"
    destination = "0.0.0.0/0"
  }

  # Ingress - SSH
  ingress_security_rules {
    protocol = "6"  # TCP
    source   = "0.0.0.0/0"
    tcp_options {
      min = 22
      max = 22
    }
  }

  # Ingress - HTTP
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 80
      max = 80
    }
  }

  # Ingress - HTTPS
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 443
      max = 443
    }
  }

  # Ingress - Flask dev port
  ingress_security_rules {
    protocol = "6"
    source   = "0.0.0.0/0"
    tcp_options {
      min = 5003
      max = 5003
    }
  }
}

# Public Subnet
resource "oci_core_subnet" "webscience_subnet" {
  compartment_id             = var.compartment_id
  vcn_id                     = oci_core_vcn.webscience_vcn.id
  cidr_block                 = "10.20.1.0/24"
  display_name               = "webscience-public-subnet"
  dns_label                  = "public"
  route_table_id             = oci_core_route_table.webscience_rt.id
  security_list_ids          = [oci_core_security_list.webscience_sl.id]
  prohibit_public_ip_on_vnic = false
}
