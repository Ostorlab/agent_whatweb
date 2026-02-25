Plugin.define do
  name "Saltcorn"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Saltcorn is an open-source, no-code web application builder. It provides an admin UI for page/code editing, user management, backups, and system operations backed by PostgreSQL."
  website "https://saltcorn.com/"

  matches [
    {
      :search => "body",
      :regexp => /_sc_version_tag\s*=\s*"([a-f0-9]+)"/,
      :name => "Saltcorn version tag JS variable",
    },
    {
      :search => "body",
      :regexp => /\/static_assets\/[a-f0-9]+\/saltcorn\.css/,
      :name => "Saltcorn static asset path",
    },
    {
      :search => "body",
      :regexp => /\/static_assets\/[a-f0-9]+\/saltcorn(?:-common)?\.js/,
      :name => "Saltcorn JavaScript bundle",
    },
    {
      :search => "body",
      :regexp => /any-bootstrap-theme@([0-9][0-9.]*)/,
      :name => "Saltcorn Bootstrap theme",
    },
    {
      :search => "body",
      :regexp => /_sc_loglevel\s*=/,
      :name => "Saltcorn runtime config (_sc_loglevel)",
    },
    {
      :search => "body",
      :regexp => /_sc_globalCsrf\s*=/,
      :name => "Saltcorn CSRF token variable",
    },
  ]
end
