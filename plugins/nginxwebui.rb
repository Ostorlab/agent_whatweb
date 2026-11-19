Plugin.define do
  name "nginxWebUI"
  authors [
    "Ostorlab",
  ]
  version "0.2"
  description "nginxWebUI is a web-based tool for managing nginx configuration, certificates, upstreams and remote servers."
  website "https://github.com/cym1102/nginxWebUI"

  matches [
    {
      :search => "body",
      :regexp => /<title>\s*nginxWebUI\s*<\/title>/i,
      :name => "nginxWebUI landing title"
    },
  ]
end
