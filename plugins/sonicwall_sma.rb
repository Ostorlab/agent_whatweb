Plugin.define do
  name "SonicWall SMA"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Secure Mobile Access (SMA) Secure your infrastructure while empowering your workforce. The Secure Mobile Access (SMA) series offers complete security for remote access to corporate resources hosted on-prem, in cloud and in hybrid datacenters."
  website "https://www.sonicwall.com/products/remote-access"

  matches [
    {
      :search => "headers[server]",
      :regexp => /SMA/i,
      :name => "SMA Server Header"
    },
  ]
end
