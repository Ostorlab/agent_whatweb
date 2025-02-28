Plugin.define do
  name "Microsoft Power Pages"
  authors [
    "Ostorlab",
  ]
  version "0.1"
  description "Microsoft Power Pages is a low-code platform for creating, hosting, and managing secure business websites."
  website "https://powerpages.microsoft.com/"

  matches [
    {
      :search => "body",
      :regexp => /https:\/\/content\.powerapps\.com\/resource\/powerappsportal\//i,
      :name => "PowerApps Portal Resource Reference"
    },
    {
      :search => "body",
      :regexp => /window\[\"Microsoft\"\]\.Dynamic365\.Portal/i,
      :name => "Microsoft Dynamic 365 Portal JavaScript Object"
    },
    {
      :search => "body",
      :regexp => /data-ckeditor-basepath="\/js\/BaseHtmlContentDesigner\/Libs\/msdyncrm_\//i,
      :name => "Power Pages CKEditor Base Path"
    }
  ]
end
