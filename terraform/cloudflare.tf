# Cloudflare DNS and CDN Configuration

# Get zone info
data "cloudflare_zone" "webscience" {
  zone_id = var.cloudflare_zone_id
}

# Root domain A record - proxied through Cloudflare
resource "cloudflare_record" "root" {
  zone_id = var.cloudflare_zone_id
  name    = "@"
  content = oci_core_instance.webscience.public_ip
  type    = "A"
  proxied = true
  ttl     = 1  # Auto when proxied

  lifecycle {
    create_before_destroy = true
  }
}

# WWW CNAME - proxied
resource "cloudflare_record" "www" {
  zone_id = var.cloudflare_zone_id
  name    = "www"
  content = var.domain
  type    = "CNAME"
  proxied = true
  ttl     = 1
}

# API subdomain - proxied
resource "cloudflare_record" "api" {
  zone_id = var.cloudflare_zone_id
  name    = "api"
  content = oci_core_instance.webscience.public_ip
  type    = "A"
  proxied = true
  ttl     = 1
}

# Page Rules for caching
resource "cloudflare_page_rule" "cache_static" {
  zone_id  = var.cloudflare_zone_id
  target   = "${var.domain}/static/*"
  priority = 1

  actions {
    cache_level = "cache_everything"
    edge_cache_ttl = 86400  # 1 day
  }
}

resource "cloudflare_page_rule" "bypass_api" {
  zone_id  = var.cloudflare_zone_id
  target   = "${var.domain}/api/*"
  priority = 2

  actions {
    cache_level       = "bypass"
    disable_apps      = true
    disable_performance = true
  }
}

# SSL/TLS settings
resource "cloudflare_zone_settings_override" "webscience" {
  zone_id = var.cloudflare_zone_id

  settings {
    ssl                      = "full_strict"
    always_use_https         = "on"
    min_tls_version          = "1.2"
    automatic_https_rewrites = "on"

    # Security
    security_level           = "medium"
    browser_check            = "on"

    # Performance
    minify {
      css  = "on"
      html = "on"
      js   = "on"
    }
    brotli                   = "on"

    # Caching
    browser_cache_ttl        = 14400

    # HTTP/2 & HTTP/3
    http2                    = "on"
    http3                    = "on"
  }
}

# Rate limiting for API
resource "cloudflare_rate_limit" "api_rate_limit" {
  zone_id   = var.cloudflare_zone_id
  threshold = 100
  period    = 60

  match {
    request {
      url_pattern = "${var.domain}/api/*"
      schemes     = ["HTTP", "HTTPS"]
      methods     = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    }
  }

  action {
    mode    = "simulate"  # Change to "ban" in production
    timeout = 60
  }

  disabled = false
}
