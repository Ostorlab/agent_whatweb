Plugin.define do
  name "nginxWebUI"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "nginxWebUI is a web-based tool for managing nginx configuration, certificates, upstreams and remote servers."
  website "https://github.com/cym1102/nginxWebUI"

  matches [
    {
      :search => "body",
      :regexp => /<title>\s*nginxWebUI\s*<\/title>/i,
      :name => "nginxWebUI landing title"
    },
    {
      :search => "body",
      :regexp => /location\.href\s*=\s*['"]\/adminPage\/login['"]/i,
      :name => "nginxWebUI admin login redirect"
    },
  ]
end
