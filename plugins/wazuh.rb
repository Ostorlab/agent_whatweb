Plugin.define do
  name "Wazuh"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Wazuh is a free and open source platform used for threat prevention, detection, and response."
  website "https://wazuh.com/"

  matches [
    {
      :search => "body",
      :regexp => /<title>Wazuh<\/title>/i,
      :name => "Wazuh Title Tag"
    },
  ]
end
