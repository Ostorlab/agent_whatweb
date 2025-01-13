Plugin.define do
  name "Aviatrix Controller"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Aviatrix Controller is a critical network security and cloud networking platform used for managing multi-cloud environments across major providers like AWS, Azure, and GCP"
  website "https://aviatrix.com/"

  matches [
    {
      :search => "body",
      :regexp => /<title>Aviatrix Controller<\/title>/i,
    },
  ]
end
