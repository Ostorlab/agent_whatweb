Plugin.define do
  name "Citrix-NetScaler"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Citrix NetScaler is an application delivery controller (ADC) that provides load balancing, application firewall, and other networking services for web applications and services."
  website "https://www.citrix.com/products/citrix-adc/"

  matches [
    {
      :search => "headers[server]",
      :regexp => /Citrix NetScaler/i,
      :name => "Citrix NetScaler Direct Server Header"
    },
    {
      :search => "headers[set-cookie]",
      :regexp => /ELS-NETSCALER/i,
      :name => "ELS NetScaler Cookie"
    },
    {
      :search => "body",
      :regexp => /NETSCALER-([\d\.]+)/i,
      :name => "NetScaler Version in Body"
    },
    {
      :search => "body",
      :regexp => /system: FreeBSD\/([\d\.]+-NETSCALER-[\d\.]+)/i,
      :name => "FreeBSD NetScaler System Version"
    },
  ]

  # Version detection for Citrix NetScaler
  version [
    {
      :search => "body",
      :regexp => /NETSCALER-([\d\.]+)/i,
      :offset => 0
    },
    {
      :search => "body",
      :regexp => /system: FreeBSD\/([\d\.]+-NETSCALER-[\d\.]+)/i,
      :offset => 0
    },
  ]
end
