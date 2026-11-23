Plugin.define do
  name "Kerberos Agent"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Identifies Kerberos Agent, an open-source video-surveillance agent with an HTTP API and web dashboard, by the title of its public landing page. The running release is served by the /health document, which WhatWeb does not fetch at default aggression, so version extraction is a gap."
  website "https://github.com/kerberos-io/agent"

  matches [
    {
      :search => "body",
      :regexp => /<title[^>]*>\s*Kerberos Agent\s*\|\s*Video surveillance for everyone\s*<\/title>/mi,
      :name => "Kerberos Agent landing title",
    },
  ]
end
