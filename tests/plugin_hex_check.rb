# Behavioral check for the Hex (hexpm) landing markers.
#
# Usage: ruby plugin_hex_check.rb <plugins directory>
# Exits 1 if a genuine Hex landing does not match or a lookalike matches.

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

  def respond_to_missing?(_name, _include_private)
    ALLOWED.include?(_name)
  end
end

# Captured from the real hex.pm landing document.
PRODUCT_LANDING = <<~HTML
  <!doctype html>
  <html lang="en">
    <head>
      <title data-default="Hex">Hex</title>
      <meta name="description" content="A package manager for the Erlang ecosystem">
      <meta content="A package manager for the Erlang ecosystem" property="og:description">
      <meta content="Hex" property="og:site_name">
      <link rel="alternate" type="application/atom+xml" href="/feeds/blog.xml">
    </head>
    <body>
      <a href="/packages">Packages</a>
      <a href="/docs">Docs</a>
      <a href="/blog">Blog</a>
    </body>
  </html>
HTML

# The CVE-2026-129514 fix is server-side; the landing document is unchanged.
PRODUCT_FIXED_LANDING = <<~HTML
  <!doctype html><html><head>
  <title data-default="Hex">Hex</title>
  <meta name="description" content="A package manager for the Erlang ecosystem">
  </head><body><a href="/packages">Packages</a></body></html>
HTML

TITLE_ONLY = <<~HTML
  <!doctype html><html><head><title>Hex</title></head>
  <body><h1>Hex</h1><p>A color conversion tool.</p></body></html>
HTML

DESCRIPTION_ONLY = <<~HTML
  <!doctype html><html><head><title>HexDocs</title>
  <meta name="description" content="A package manager for the Erlang ecosystem">
  </head><body><p>Documentation for Hex packages.</p></body></html>
HTML

OTHER_PRODUCT = <<~HTML
  <!doctype html><html><head><title>Acme Registry</title>
  <meta name="description" content="A package manager for the Acme ecosystem">
  </head><body><a href="/packages">Packages</a></body></html>
HTML

DOCS_TITLE = <<~HTML
  <!doctype html><html><head><title>Hex</title>
  <meta name="description" content="Hex documentation and guides">
  </head><body><p>Install Hex with mix local.hex.</p></body></html>
HTML

plugins_directory = ARGV[0] or abort "usage: ruby plugin_hex_check.rb <plugins directory>"
load File.join(plugins_directory, "hex.rb")

plugin = Plugin.plugins.fetch(0)
match = plugin.matches.fetch(0)
abort "expected :search => body" unless match[:search] == "body"
regexp = Regexp.new(match[:regexp])

cases = {
  "Hex landing" => [PRODUCT_LANDING, true],
  "fixed Hex landing" => [PRODUCT_FIXED_LANDING, true],
  "title-only page" => [TITLE_ONLY, false],
  "description-only page" => [DESCRIPTION_ONLY, false],
  "other product" => [OTHER_PRODUCT, false],
  "docs title page" => [DOCS_TITLE, false],
}

failures = cases.filter_map do |name, (body, expected)|
  actual = !body.scan(regexp).empty?
  "#{name}: expected #{expected}, got #{actual}" if actual != expected
end

if failures.empty?
  puts "plugin_hex_check: all #{cases.length} cases passed"
else
  warn failures.join("\n")
  exit 1
end
