require_relative "lib/chacha20/version"

Gem::Specification.new do |spec|
  spec.name = "chacha20"
  spec.version = ChaCha20::VERSION
  spec.authors = ["Alexander Gitter"]
  spec.email = ["contact@agitter.de"]

  spec.summary = "ChaCha20 stream cipher algorithm in pure Ruby."
  spec.homepage = "https://github.com/alexandergitter/chacha20"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.0.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.require_paths = ["lib"]

  spec.add_development_dependency "minitest", "~> 5.0"
  spec.add_development_dependency "rake", "~> 13.0"
end