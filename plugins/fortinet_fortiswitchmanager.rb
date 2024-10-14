Plugin.define do
  name "fortinet fortiswitchmanager"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "FortiSwitch Manager enables network administrators to cut through the complexities of non-FortiGate-managed FortiSwitch deployments."
  website "https://docs.fortinet.com/product/fortiswitch-manager"

  matches [
    {
      :search => "body",
      :regexp => /FortiSwitchManager/,
      :name => "FortiSwitchManager Body Content"
    }
  ]
end
