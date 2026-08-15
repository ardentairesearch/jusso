#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "yaml"

ROOT = File.expand_path(__dir__)
OUT = File.expand_path("../openapi.yaml", ROOT)

def load_yaml(relative_path)
  path = File.join(ROOT, relative_path)
  YAML.load_file(path) || {}
rescue Errno::ENOENT
  warn "missing OpenAPI source file: #{relative_path}"
  exit 1
end

def deep_merge!(target, source, context = [])
  source.each do |key, value|
    if target[key].is_a?(Hash) && value.is_a?(Hash)
      deep_merge!(target[key], value, context + [key])
    elsif target.key?(key)
      dotted = (context + [key]).join(".")
      warn "duplicate OpenAPI key while bundling: #{dotted}"
      exit 1
    else
      target[key] = value
    end
  end
  target
end

root = load_yaml("root.yaml")
bundle = root.delete("x-ardent-bundle") || {}

spec = root
spec["paths"] ||= {}
Array(bundle["paths"]).each do |relative_path|
  deep_merge!(spec["paths"], load_yaml(relative_path), ["paths"])
end

spec["components"] ||= {}
Array(bundle["components"]).each do |relative_path|
  deep_merge!(spec["components"], load_yaml(relative_path), ["components"])
end

FileUtils.mkdir_p(File.dirname(OUT))
File.write(
  OUT,
  "# This file is generated from docs/agent-integration/openapi/.\n" \
  "# Edit the split source files, then run: ruby docs/agent-integration/openapi/bundle.rb\n" \
  "#{YAML.dump(spec)}"
)

puts "wrote #{OUT}"
