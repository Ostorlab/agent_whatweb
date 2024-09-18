Plugin.define do
  name "WhatsUp Gold"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "WhatsUp Gold is a network monitoring software that provides complete visibility into the status and performance of applications, network devices, and services."
  website "https://www.whatsupgold.com/"

  matches [
    {
      :search => "headers[server]",
      :regexp => /WhatsUp_Gold/i,
      :name => "WhatsUp_Gold Server Header"
    },
  ]
end
