##
# Joomla! CMS fingerprint for the asset inventory and vulnerable-component
# matching.
#
# The upstream WhatWeb joomla plugin recognises old Joomla 1.x/2.x/3.x pages and
# expects a numeric generator version. Modern Joomla 4/5/6 front pages emit the
# unversioned `Joomla! - Open Source Content Management` generator meta, so the
# upstream plugin does not fire on them. This plugin matches that meta, the
# administrator login page and the web-installer page (whose header carries the
# exact release). A site that still serves its installation folder redirects the
# landing to the installer, so the installer match also fingerprints exactly the
# vulnerable configuration.
##
Plugin.define do
name "Joomla CMS"
authors [
  "Ostorlab",
]
version "1.0"
description "Joomla! content management system (Joomla 4, 5 and 6)."
website "https://www.joomla.org/"

matches [
  { :regexp=>/<meta name="generator" content="Joomla! - Open Source Content Management"/i, :name=>"generator meta" },
  { :text=>"Joomla Administrator Login", :name=>"administrator login" },
  { :version=>/<title>Joomla Installer<\/title>[\s\S]{0,8000}?Joomla! ([0-9]+\.[0-9]+\.[0-9]+)/, :name=>"web installer" },
  { :url=>'/administrator/manifests/files/joomla.xml', :version=>/<version>(.*?)<\/version>/ },
]
end
