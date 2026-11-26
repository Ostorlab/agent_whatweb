# Behavioral check for the Budibase builder-landing markers.
#
# Usage: ruby plugin_budibase_check.rb <plugins directory>
# Exits 1 if a genuine Budibase landing does not match or a lookalike matches.

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

  def respond_to_missing?(_name, _include_private = false)
    ALLOWED.include?(_name)
  end
end

# Captured from the real Budibase builder index template at the affected commit.
PRODUCT_LANDING = <<~HTML
  <!doctype html>
  <html class="spectrum spectrum--medium spectrum--darkest" lang="en" dir="ltr">
    <head>
      <meta charset="utf8" />
      <title>Budibase</title>
      <link href="/builder/fonts/inter/inter.css" rel="stylesheet" />
      <script>const theme = localStorage.getItem("bb-theme")</script>
    </head>
    <body id="app">
      <script type="module" src="/builder/assets/index-abc123.js"></script>
    </body>
  </html>
HTML

# The 4.0.0 fix is server-side; the landing document is unchanged.
PRODUCT_FIXED_LANDING = <<~HTML
  <!doctype html><html><head><title>Budibase</title>
  <link href="/builder/assets/index-def456.css" rel="stylesheet"></head>
  <body id="app"><script type="module" src="/builder/assets/index-def456.js"></script></body></html>
HTML

TITLE_ONLY = <<~HTML
  <!doctype html><html><head><title>Budibase</title></head>
  <body><h1>Budibase documentation</h1><p>Learn about our low-code platform.</p></body></html>
HTML

DOCS_TITLE = <<~HTML
  <!doctype html><html><head><title>Budibase Docs</title></head>
  <body><p>Budibase documentation and guides.</p></body></html>
HTML

OTHER_PRODUCT = <<~HTML
  <!doctype html><html><head><title>Acme Admin</title></head>
  <body><a href="/builder/">Builder</a></body></html>
HTML

DOCS_WITH_BUILDER_PATH = <<~HTML
  <!doctype html><html><head><title>Budibase</title></head>
  <body><h1>Budibase documentation</h1><p>Open <code>/builder/</code> to start.</p></body></html>
HTML

plugins_directory = ARGV[0] or abort "usage: ruby plugin_budibase_check.rb <plugins directory>"
load File.join(plugins_directory, "budibase.rb")

plugin = Plugin.plugins.fetch(0)
match = plugin.matches.fetch(0)
abort "expected :search => body" unless match[:search] == "body"
regexp = Regexp.new(match[:regexp])

cases = {
  "Budibase landing" => [PRODUCT_LANDING, true],
  "Budibase 4.0.0 landing" => [PRODUCT_FIXED_LANDING, true],
  "title-only page" => [TITLE_ONLY, false],
  "docs title page" => [DOCS_TITLE, false],
  "other product" => [OTHER_PRODUCT, false],
  "docs with /builder/ path" => [DOCS_WITH_BUILDER_PATH, false],
}

failures = cases.filter_map do |name, (body, expected)|
  actual = !body.scan(regexp).empty?
  "#{name}: expected #{expected}, got #{actual}" if actual != expected
end

if failures.empty?
  puts "plugin_budibase_check: all #{cases.length} cases passed"
else
  warn failures.join("\n")
  exit 1
end
