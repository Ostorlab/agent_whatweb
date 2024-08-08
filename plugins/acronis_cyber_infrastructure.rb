Plugin.define do
	name "Acronis cyber infrastructure"
	authors [
	  "Ostorlab",
	]
    version "0.1"
	description "Acronis cyber infrastructure is a multi-tenant, hyper-converged infrastructure solution for cyber protection"
	website "https://www.acronis.com/en-eu/products/cyber-infrastructure/"

	matches [
        {
            :text => "<title>Acronis Cyber Infrastructure</title>"
        }
	]
  end

