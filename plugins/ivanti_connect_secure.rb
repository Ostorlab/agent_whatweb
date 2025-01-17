Plugin.define do
  name "Ivanti Connect Secure"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Ivanti Connect Secure provides a seamless, cost-effective SSL VPN solution for remote and mobile users from any web-enabled device to corporate resources— anytime, anywhere."
  website "https://www.ivanti.com/products/connect-secure-vpn"

  matches [
    {
      :search => "body",
      :regexp => /<title>Ivanti Connect Secure<\/title>/i,
    },
  ]
end
