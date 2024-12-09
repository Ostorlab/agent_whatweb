Plugin.define do
  name "Solana"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Solana is a blockchain platform designed to host decentralized, scalable applications."
  website "https://solana.com/"

  matches [
    {
      :text => '<script src="https://unpkg.com/@solana/web3.js@'
    }
  ]
end
