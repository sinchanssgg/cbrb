terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

variable "project" { type = string }
variable "region"  { type = string  default = "us-east1" }
variable "zone"    { type = string  default = "us-east1-b" }
variable "n"       { type = number  default = 10 }
variable "t"       { type = number  default = 3 }
variable "c"       { type = number  default = 1 }
variable "payload_bytes" { type = number default = 1024 }

variable "controller_addr" { type = string }
variable "tls_ca_b64"      { type = string }
variable "tls_cert_b64"    { type = map(string) }
variable "tls_key_b64"     { type = map(string) }

provider "google" {
  project = var.project
  region  = var.region
  zone    = var.zone
}

resource "google_compute_network" "vpc" {
  name                    = "crbb-vpc"
  auto_create_subnetworks = true
}

resource "google_compute_firewall" "allow_internal" {
  name    = "crbb-allow-internal"
  network = google_compute_network.vpc.name
  allow {
    protocol = "tcp"
    ports    = ["0-65535"]
  }
  source_ranges = ["10.0.0.0/8"]
}

resource "google_compute_instance" "node" {
  count        = var.n
  name         = "crbb-node-${count.index}"
  machine_type = "c2-standard-4"
  zone         = var.zone

  boot_disk {
    initialize_params { image = "ubuntu-os-cloud/ubuntu-2204-lts" }
  }

  network_interface {
    network = google_compute_network.vpc.name
    access_config {}
  }

  metadata_startup_script = templatefile("${path.module}/startup.sh", {
    node_id          = count.index
    n                = var.n
    t                = var.t
    c                = var.c
    payload_bytes    = var.payload_bytes
    controller_addr  = var.controller_addr
    tls_ca_b64       = var.tls_ca_b64
    tls_cert_b64     = var.tls_cert_b64[count.index]
    tls_key_b64      = var.tls_key_b64[count.index]
    self_ip          = google_compute_instance.node[count.index].network_interface[0].network_ip
  })
}

output "node_ips" {
  value = google_compute_instance.node[*].network_interface[0].network_ip
}