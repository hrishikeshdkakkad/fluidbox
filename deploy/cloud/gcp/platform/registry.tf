# ── Artifact Registry ────────────────────────────────────────────────────────
#
# The deployment pulls from GHCR today (that is where release.yml publishes).
# This repository exists so images can be MIRRORED in-region, which buys three
# things: pulls that do not leave Google's network, a registry that survives
# GHCR being unavailable, and immutable tags.

resource "google_artifact_registry_repository" "fluidbox" {
  project       = var.project_id
  location      = var.region
  repository_id = "fluidbox"
  format        = "DOCKER"
  description   = "Fluidbox server, web, runner and collector images (mirrored from GHCR)."
  labels        = var.labels

  docker_config {
    # A tag, once pushed, cannot be moved to a different digest. This is what
    # makes "deployed image = this tag" a durable claim instead of a
    # point-in-time observation.
    immutable_tags = true
  }

  cleanup_policies {
    id     = "keep-recent-releases"
    action = "KEEP"
    most_recent_versions {
      keep_count = 20
    }
  }

  cleanup_policies {
    id     = "delete-untagged"
    action = "DELETE"
    condition {
      tag_state  = "UNTAGGED"
      older_than = "604800s" # 7 days
    }
  }
}
