##
# Gitea Mirror fingerprint for the asset inventory and vulnerable-component
# matching.
#
# Gitea Mirror is a self-hosted dashboard that mirrors repositories between
# GitHub, GitLab, Gitea and Forgejo. Its server-rendered shell sets a
# product-specific `__GITEA_MIRROR_BASE_PATH__` window constant and names the
# product in the document title (`Login - Gitea Mirror`, `Setup Admin Account -
# Gitea Mirror`, `Dashboard - Gitea Mirror`). The sign-in and setup pages also
# carry the `Gitea Mirror Logo` alt text. The shell carries no release, so
# version extraction is a gap; the Asteroid rule reads /api/github and
# /api/health itself.
#
# Requiring the title and one of the shell markers keeps a blog post or an
# unrelated page that merely mentions the product out of the match.
##
Plugin.define do
  name "Gitea Mirror"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Gitea Mirror, a self-hosted repository mirroring dashboard."
  website "https://github.com/RayLabsHQ/gitea-mirror"

  matches [
    {
      :regexp => /<title[^>]*>[^<]{0,160}Gitea Mirror<\/title>[\s\S]{0,20000}?(?:__GITEA_MIRROR_BASE_PATH__|alt="Gitea Mirror Logo")/i,
      :name => "Gitea Mirror shell",
    },
  ]
end
