Plugin.define do
  name "Expedition Project"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Expedition is the fourth evolution of the Palo Alto Networks Migration Tool. The purpose of this tool is to help reduce the time and efforts of migrating a configuration from a supported vendor to Palo Alto Networks."
  website "https://live.paloaltonetworks.com/t5/expedition/ct-p/migration_tool"

  matches [
    {
      :search => "title",
      :regexp => /<title>Expedition Project<\/title>/,
      :name => "Expedition Project Title Tag"
    },
  ]
end