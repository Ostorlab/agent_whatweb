Plugin.define do
  name "Fortinet FortiManager"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "FortiManager, now powered by FortiAI, revolutionizes network management and security operations by automating routine tasks and providing intelligent insights."
  website "https://www.fortinet.com/products/management/fortimanager"

  matches [
    {
      :regexp => /<title>FortiManager-/,
      :name => "FortiManager Title Pattern"
    }
  ]
end
