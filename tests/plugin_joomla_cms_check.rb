# Behavioral check for the Joomla CMS plugin's product-specific markers.
#
# Usage: ruby plugin_joomla_cms_check.rb <plugins directory>
# Exits 1 if a genuine Joomla page does not match, a lookalike matches, or the
# installer version is not extracted.

class Plugin
  @plugins = []
  ALLOWED = %i[name authors version description website dorks matches passive aggressive].freeze

  class << self
    attr_reader :plugins

    def define(&block)
      plugin = new
      plugin.instance_eval(&block)
      @plugins << plugin
    end
  end

  ALLOWED.each do |attribute|
    define_method(attribute) do |value = nil|
      instance_variable_set("@#{attribute}", value) unless value.nil?
      instance_variable_get("@#{attribute}")
    end
  end

  def matches(value = nil)
    @matches = value unless value.nil?
    @matches || []
  end

  def method_missing(name, *_args, &_block)
    raise NoMethodError, "unknown WhatWeb Plugin DSL attribute: #{name}"
  end

  def respond_to_missing?(name, _include_private = false)
    ALLOWED.include?(name)
  end
end

FRONT_PAGE = <<~HTML
  <!doctype html>
  <html lang="en-GB"><head>
  <meta charset="utf-8">
  <meta name="generator" content="Joomla! - Open Source Content Management">
  <title>Home</title>
  </head><body><p>Welcome.</p></body></html>
HTML

INSTALLER_VULNERABLE = <<~HTML
  <!doctype html>
  <html lang="en-GB"><head><title>Joomla Installer</title></head>
  <body><div id="container-installation">
  <h1><span class="small">Joomla! 5.4.10</span></h1>
  <div data-page-name="remove">Congratulations! Your Joomla site is ready.</div>
  </div></body></html>
HTML

INSTALLER_FIXED = <<~HTML
  <!doctype html>
  <html lang="en-GB"><head><title>Joomla Installer</title></head>
  <body><h1><span class="small">Joomla! 5.4.11</span></h1>
  <p>The installation has already been completed.</p></body></html>
HTML

ADMIN_PAGE = <<~HTML
  <!doctype html>
  <html lang="en-GB"><head><title>Example - Administration</title></head>
  <body><h1>Joomla Administrator Login</h1></body></html>
HTML

TITLE_ONLY_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>Joomla Installer</title></head>
  <body>Documentation for a different installer.</body></html>
HTML

MENTION_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head><title>CMS comparison</title></head>
  <body>Joomla! is one of several content management systems.</body></html>
HTML

OTHER_GENERATOR_LOOKALIKE = <<~HTML
  <!doctype html>
  <html><head>
  <meta name="generator" content="Joomla! - Documentation">
  </head><body>Not the Joomla CMS.</body></html>
HTML

plugins_directory = ARGV[0]
load File.join(plugins_directory, "joomla_cms.rb")
plugin = Plugin.plugins.last

def page_matched?(plugin, page)
  plugin.matches.any? do |match|
    next false if match[:url]

    hit = false
    hit ||= page.match?(match[:regexp]) if match[:regexp].is_a?(Regexp)
    hit ||= page.include?(match[:text]) if match[:text].is_a?(String)
    hit ||= page.match?(match[:version]) if match[:version].is_a?(Regexp)
    hit
  end
end

def version_of(plugin, page)
  plugin.matches.each do |match|
    next unless match[:version].is_a?(Regexp)

    matched = match[:version].match(page)
    return matched[1] if matched
  end
  nil
end

failures = []
failures << "front page did not match" unless page_matched?(plugin, FRONT_PAGE)
failures << "vulnerable installer page did not match" unless page_matched?(plugin, INSTALLER_VULNERABLE)
failures << "fixed installer page did not match" unless page_matched?(plugin, INSTALLER_FIXED)
failures << "administrator login did not match" unless page_matched?(plugin, ADMIN_PAGE)
failures << "title-only lookalike matched" if page_matched?(plugin, TITLE_ONLY_LOOKALIKE)
failures << "mention lookalike matched" if page_matched?(plugin, MENTION_LOOKALIKE)
failures << "other generator lookalike matched" if page_matched?(plugin, OTHER_GENERATOR_LOOKALIKE)

vulnerable_version = version_of(plugin, INSTALLER_VULNERABLE)
fixed_version = version_of(plugin, INSTALLER_FIXED)
failures << "vulnerable installer version was #{vulnerable_version.inspect}" unless vulnerable_version == "5.4.10"
failures << "fixed installer version was #{fixed_version.inspect}" unless fixed_version == "5.4.11"

begin
  Plugin.new.instance_eval { websit "https://example.test" }
  failures << "misspelled DSL attribute was accepted"
rescue NoMethodError
  # expected: the stand-in rejects an unknown DSL attribute
end

puts failures
exit(failures.empty? ? 0 : 1)
