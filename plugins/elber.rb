Plugin.define do
  name "Elber"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Elber is an Italian quality trademark, with European roots and worldwide dimension. The Company supplies television transmitters with satellite equipments, microwave links for Telco and IP applications, monitoring equipments for TV and Radio signals, HD and UHD video compression contribution solutions, audio devices..."
  website "https://www.elber.it"

  matches [
    {
      :search => "body",
      :regexp => /Elber\ss\.r\.l\./i,
      :name => "Elber s.r.l."
    },
  ]
end
