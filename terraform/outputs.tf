# Outputs

output "instance_public_ip" {
  description = "Public IP of the WebScience instance"
  value       = oci_core_instance.webscience.public_ip
}

output "instance_id" {
  description = "OCID of the compute instance"
  value       = oci_core_instance.webscience.id
}

output "vcn_id" {
  description = "OCID of the VCN"
  value       = oci_core_vcn.webscience_vcn.id
}

output "cloudflare_dns_records" {
  description = "Cloudflare DNS records created"
  value = {
    root = cloudflare_record.root.hostname
    www  = cloudflare_record.www.hostname
    api  = cloudflare_record.api.hostname
  }
}

output "app_url" {
  description = "Application URL"
  value       = "https://${var.domain}"
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = "ssh opc@${oci_core_instance.webscience.public_ip}"
}
