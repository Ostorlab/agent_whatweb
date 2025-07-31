Plugin.define do
  name "Cisco BroadWorks"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Cisco BroadWorks is a cloud-based communications software platform that provides unified communications, collaboration, and contact center solutions for service providers."
  website "https://www.cisco.com/c/en/us/products/unified-communications/broadworks/index.html"

  matches [
    {
      :search => "headers[server]",
      :regexp => /BroadWorks/i,
      :name => "Server Header"
    },
  ]

  # Version detection for Cisco BroadWorks
  version [
    {
      :search => "headers[server]",
      :regexp => /BroadWorks[\/\s]+([0-9\.]+)/i,
      :offset => 0
    }
  ]
end
