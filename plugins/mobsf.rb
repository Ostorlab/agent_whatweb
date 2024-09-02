Plugin.define do
	name "MobSF"
	authors [
	  "Ostorlab",
	]
    version "0.1"
	description "MobSF is a Mobile Security Framework"
	website "https://github.com/MobSF/Mobile-Security-Framework-MobSF"

	matches [
        {
            :text => "Mob<strong>SF</strong>"
		},
		{
            :text => "<strong> Mob</strong>SF</span>"
        }
	]
  end

