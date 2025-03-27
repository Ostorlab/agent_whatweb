Plugin.define do
  name "NAKIVO Backup & Replication"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "NAKIVO Backup & Replication is a data protection solution."
  website "https://www.nakivo.com/"

  matches [
    {
      :search => "head",
      :regexp => /<title>NAKIVO\sBackup\s(?:&|\&amp;)\sReplication(?:\sv?\d+(\.\d+)*)?<\/title>/i,
      :name => "NAKIVO Title Tag"
    },
  ]
end