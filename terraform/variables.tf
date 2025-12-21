# OCI Variables
variable "compartment_id" {
  description = "OCI Compartment OCID"
  type        = string
}

variable "oci_region" {
  description = "OCI Region"
  type        = string
  default     = "us-ashburn-1"
}

variable "instance_shape" {
  description = "Compute instance shape"
  type        = string
  default     = "VM.Standard.A1.Flex"  # ARM-based, cost effective
}

variable "instance_ocpus" {
  description = "Number of OCPUs"
  type        = number
  default     = 1
}

variable "instance_memory_gb" {
  description = "Memory in GB"
  type        = number
  default     = 6
}

variable "ssh_public_key" {
  description = "SSH public key for instance access"
  type        = string
}

variable "domain" {
  description = "Domain name"
  type        = string
  default     = "webscience.io"
}
