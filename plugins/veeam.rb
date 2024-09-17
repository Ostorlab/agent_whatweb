Plugin.define do
  name "Veeam"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Veeam Backup & Replication is a proprietary backup app developed by Veeam for virtual environments built on VMware vSphere, Nutanix AHV, and Microsoft Hyper-V hypervisors."
  website "https://www.veeam.com/"

  matches [
    {
      :search => "title",
      :regexp => /<title>Veeam Backup/,
      :name => "Veeam Backup Enterprise Manager Title Tag"
    },
  ]
end