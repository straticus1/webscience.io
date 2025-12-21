# WebScience Compute Instance
resource "oci_core_instance" "webscience" {
  compartment_id      = var.compartment_id
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  shape               = var.instance_shape
  display_name        = "webscience-web"

  shape_config {
    ocpus         = var.instance_ocpus
    memory_in_gbs = var.instance_memory_gb
  }

  source_details {
    source_type             = "image"
    source_id               = data.oci_core_images.oracle_linux.images[0].id
    boot_volume_size_in_gbs = 50
  }

  create_vnic_details {
    subnet_id        = oci_core_subnet.webscience_subnet.id
    assign_public_ip = true
    display_name     = "webscience-vnic"
    hostname_label   = "webscience"
  }

  metadata = {
    ssh_authorized_keys = var.ssh_public_key
    user_data = base64encode(templatefile("${path.module}/cloud-init.yaml", {
      domain = var.domain
    }))
  }

  freeform_tags = {
    "Project"     = "WebScience"
    "ManagedBy"   = "Terraform"
    "Environment" = "production"
  }

  lifecycle {
    ignore_changes = [source_details[0].source_id]
  }
}

# Reserve public IP
resource "oci_core_public_ip" "webscience_ip" {
  compartment_id = var.compartment_id
  lifetime       = "RESERVED"
  display_name   = "webscience-public-ip"

  lifecycle {
    prevent_destroy = true
  }
}
